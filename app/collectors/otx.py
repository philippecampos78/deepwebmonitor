"""AlienVault OTX: o domínio do cliente aparece em relatórios de ameaças (pulses)?

Aparecer num pulse pode indicar que o domínio foi comprometido, usado em
campanhas ou imitado. Domínios na lista de permissões do OTX (ex.: grandes
provedores) são marcados como informativos.
"""

from urllib.parse import quote

from ..config import settings
from .base import Collector, FindingData

API = "https://otx.alienvault.com/api/v1"
MAX_PULSES = 25


class OTXCollector(Collector):
    name = "otx"
    label = "AlienVault OTX"
    description = "Domínio citado em relatórios de ameaças da comunidade."

    def __init__(self, http, api_key: str | None = None):
        super().__init__(http)
        self.api_key = settings.otx_api_key if api_key is None else api_key

    def status_note(self) -> str:
        return "" if self.api_key else "sem chave (funciona, mas com limite menor de consultas)"

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else None
        data = self.get_json(f"{API}/indicators/domain/{quote(domain)}/general", headers=headers,
                             not_found_value={}, timeout=60) or {}
        whitelisted = bool(data.get("validation"))
        pulses = (data.get("pulse_info") or {}).get("pulses") or []
        pulses = sorted((p for p in pulses if isinstance(p, dict)),
                        key=lambda p: p.get("modified") or p.get("created") or "", reverse=True)

        findings = []
        for p in pulses[:MAX_PULSES]:
            families = ", ".join(
                f.get("display_name", "") if isinstance(f, dict) else str(f)
                for f in p.get("malware_families") or [])
            detail = f"Relatório: {p.get('name', '?')}."
            if p.get("adversary"):
                detail += f" Adversário: {p['adversary']}."
            if families:
                detail += f" Malware: {families}."
            if p.get("tags"):
                detail += f" Tags: {', '.join(map(str, p['tags'][:10]))}."
            if whitelisted:
                detail += " O OTX marca este domínio como confiável; provavelmente citado como referência."
            findings.append(FindingData(
                source=self.name,
                category="ioc",
                severity="info" if whitelisted else "media",
                asset=domain,
                title=f"{domain} citado no relatório de ameaça \"{p.get('name', '?')}\"",
                detail=detail,
                reference_url=f"https://otx.alienvault.com/pulse/{p.get('id')}" if p.get("id") else "",
                event_date=str(p.get("created") or "")[:10],
                fingerprint=f"otx:{p.get('id') or p.get('name')}",
            ))
        return findings
