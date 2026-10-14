"""VirusTotal: o domínio do cliente é considerado malicioso por antivírus e listas de reputação?

Chave gratuita: 4 consultas por minuto e 500 por dia; o coletor espera entre
as consultas para respeitar esse limite.
"""

import time
from datetime import datetime, timezone
from urllib.parse import quote

from ..config import settings
from .base import Collector, FindingData

API = "https://www.virustotal.com/api/v3"
MIN_INTERVAL = 15.5  # segundos entre consultas (4/min no plano gratuito)


class VirusTotalCollector(Collector):
    name = "virustotal"
    label = "VirusTotal"
    description = "Reputação do domínio em cerca de 90 antivírus e listas de bloqueio."

    _last_call = 0.0  # compartilhado entre instâncias: o limite é por chave

    def __init__(self, http, api_key: str | None = None, min_interval: float = MIN_INTERVAL):
        super().__init__(http)
        self.api_key = settings.virustotal_api_key if api_key is None else api_key
        self.min_interval = min_interval

    def enabled(self) -> bool:
        return bool(self.api_key)

    def disabled_reason(self) -> str:
        return "defina VIRUSTOTAL_API_KEY no .env (chave gratuita em virustotal.com)"

    def _throttle(self):
        wait = VirusTotalCollector._last_call + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        VirusTotalCollector._last_call = time.monotonic()

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        self._throttle()
        data = self.get_json(f"{API}/domains/{quote(domain)}", headers={"x-apikey": self.api_key},
                             not_found_value={}) or {}
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious, suspicious = int(stats.get("malicious") or 0), int(stats.get("suspicious") or 0)
        if not malicious and not suspicious:
            return []
        engines = [f"{name} ({r.get('result')})" for name, r in (attrs.get("last_analysis_results") or {}).items()
                   if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious")]
        when = attrs.get("last_analysis_date")
        date = datetime.fromtimestamp(when, tz=timezone.utc).strftime("%Y-%m-%d") if isinstance(when, int) else ""
        severity = "critica" if malicious >= 5 else "alta" if malicious else "media"
        detail = (f"{malicious} antivírus/listas marcam o domínio como malicioso e {suspicious} como suspeito"
                  f" (de {sum(int(v or 0) for v in stats.values())} analisadores).")
        if engines:
            detail += f" Quem marcou: {', '.join(engines[:12])}."
        if attrs.get("reputation") is not None:
            detail += f" Reputação na comunidade: {attrs['reputation']}."
        detail += (" Consequência: e-mails e acessos ao site podem ser bloqueados por clientes e parceiros. "
                   "Verifique se o site foi comprometido e peça a revisão a cada fornecedor.")
        return [FindingData(
            source=self.name, category="ioc", severity=severity, asset=domain,
            title=f"{domain} marcado como malicioso/suspeito por {malicious + suspicious} analisador(es) no VirusTotal",
            detail=detail,
            reference_url=f"https://www.virustotal.com/gui/domain/{quote(domain)}",
            event_date=date,
            fingerprint=f"vt:{domain}:{malicious}:{suspicious}",
        )]
