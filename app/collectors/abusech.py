"""abuse.ch: URLhaus (URLs que distribuem malware) e ThreatFox (indicadores de ameaça).

Se o domínio do cliente aparece no URLhaus, o site provavelmente foi invadido e
está sendo usado para distribuir malware. No ThreatFox, o domínio foi visto
como infraestrutura de ataque (C2, phishing etc.). Exige chave gratuita.
"""

from ..config import settings
from .base import Collector, CollectorError, FindingData

URLHAUS = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
MAX_URLS = 50


class AbuseChCollector(Collector):
    name = "abusech"
    label = "abuse.ch (URLhaus e ThreatFox)"
    description = "Site do cliente distribuindo malware ou usado como infraestrutura de ataque."

    def __init__(self, http, auth_key: str | None = None):
        super().__init__(http)
        self.auth_key = settings.abusech_auth_key if auth_key is None else auth_key

    def enabled(self) -> bool:
        return bool(self.auth_key)

    def disabled_reason(self) -> str:
        return "defina ABUSECH_AUTH_KEY no .env (chave gratuita em auth.abuse.ch)"

    def _urlhaus(self, domain: str) -> list[FindingData]:
        data = self.get_json(URLHAUS, method="POST", headers={"Auth-Key": self.auth_key},
                             data={"host": domain}, not_found_value={}) or {}
        findings = []
        for u in (data.get("urls") or [])[:MAX_URLS]:
            if not isinstance(u, dict) or not u.get("url"):
                continue
            online = u.get("url_status") == "online"
            tags = ", ".join(u.get("tags") or [])
            findings.append(FindingData(
                source=self.name,
                category="ioc",
                severity="critica" if online else "alta",
                asset=domain,
                title=f"URL do domínio listada no URLhaus distribuindo malware ({'ONLINE' if online else 'offline'})",
                detail=(f"URL: {u['url']}. Ameaça: {u.get('threat', '?')}."
                        + (f" Tags: {tags}." if tags else "")
                        + " Indica site comprometido: investigar o servidor."),
                reference_url=u.get("urlhaus_reference", ""),
                event_date=str(u.get("date_added") or "")[:10],
                fingerprint=f"urlhaus:{u['url']}",
            ))
        return findings

    def _threatfox(self, domain: str) -> list[FindingData]:
        data = self.get_json(THREATFOX, method="POST", headers={"Auth-Key": self.auth_key},
                             json={"query": "search_ioc", "search_term": domain}, not_found_value={}) or {}
        if data.get("query_status") != "ok" or not isinstance(data.get("data"), list):
            return []
        findings = []
        for ioc in data["data"]:
            if not isinstance(ioc, dict) or domain not in str(ioc.get("ioc", "")).lower():
                continue
            findings.append(FindingData(
                source=self.name,
                category="ioc",
                severity="alta",
                asset=domain,
                title=f"Indicador de ameaça no ThreatFox: {ioc.get('ioc')}",
                detail=(f"Tipo: {ioc.get('threat_type_desc') or ioc.get('threat_type', '?')}. "
                        f"Malware: {ioc.get('malware_printable', '?')}. "
                        f"Confiança: {ioc.get('confidence_level', '?')}%."),
                reference_url=f"https://threatfox.abuse.ch/ioc/{ioc['id']}/" if ioc.get("id") else "",
                event_date=str(ioc.get("first_seen") or "")[:10],
                fingerprint=f"threatfox:{ioc.get('id') or ioc.get('ioc')}",
            ))
        return findings

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        findings, errors = [], []
        for fn in (self._urlhaus, self._threatfox):  # uma falha não esconde o resultado da outra
            try:
                findings += fn(domain)
            except CollectorError as exc:
                errors.append(str(exc))
        if errors:
            raise CollectorError("; ".join(errors), findings=findings)
        return findings
