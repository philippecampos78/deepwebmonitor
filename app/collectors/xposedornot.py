"""XposedOrNot (https://xposedornot.com): em quais vazamentos públicos um e-mail aparece.

Gratuito e sem chave para consulta por e-mail. Catálogo próprio, parecido com o
do HIBP; o mesmo vazamento encontrado nas duas fontes vira um achado só.
"""

import time
from urllib.parse import quote

from .base import Collector, FindingData
from .hibp import describe_classes
from .matching import STEALER_NOTE, breach_key, is_stealer_source

API = "https://api.xposedornot.com/v1"
MIN_INTERVAL = 1.0  # segundos entre consultas, para não ser bloqueado em varreduras grandes
MAX_BREACHES = 200

RISK = {
    "plaintext": ("alta", "senhas em texto puro"),
    "easytocrack": ("alta", "senhas com proteção fraca, fáceis de descobrir"),
    "hardtocrack": ("media", "senhas com proteção forte"),
    "unknown": ("media", ""),
}


class XposedOrNotCollector(Collector):
    name = "xposedornot"
    label = "XposedOrNot"
    description = "Vazamentos públicos em que cada e-mail prioritário aparece (catálogo próprio)."

    checks_discovered_emails = True  # também verifica e-mails do cliente encontrados por outras fontes
    _last_call = 0.0

    def __init__(self, http, min_interval: float = MIN_INTERVAL):
        super().__init__(http)
        self.min_interval = min_interval

    def _throttle(self):
        wait = XposedOrNotCollector._last_call + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        XposedOrNotCollector._last_call = time.monotonic()

    def collect_email(self, email: str) -> list[FindingData]:
        email = email.lower()
        self._throttle()
        data = self.get_json(f"{API}/breach-analytics", params={"email": email}, not_found_value={}) or {}
        details = ((data.get("ExposedBreaches") or {}).get("breaches_details")) or []
        findings = []
        details = [b for b in details if isinstance(b, dict)]
        # Logs de infostealer primeiro: nunca podem ficar de fora pelo limite de MAX_BREACHES
        details.sort(key=lambda b: not is_stealer_source(str(b.get("breach") or ""), str(b.get("details") or "")))
        for b in details[:MAX_BREACHES]:
            if not isinstance(b, dict) or not b.get("breach"):
                continue
            name = str(b["breach"])
            severity, risk_text = RISK.get(str(b.get("password_risk", "unknown")).lower(), RISK["unknown"])
            exposed = [x.strip() for x in str(b.get("xposed_data") or "").split(";") if x.strip()]
            detail = f"Incidente: {name}"
            if b.get("domain"):
                detail += f" ({b['domain']})"
            if b.get("xposed_date"):
                detail += f", ocorrido em {b['xposed_date']}"
            detail += "."
            if exposed:
                detail += f" Dados expostos: {describe_classes(exposed[:12])}."
            if risk_text:
                detail += f" O vazamento tinha {risk_text}."
            stealer = is_stealer_source(name, str(b.get("details") or ""))
            if stealer:
                detail += STEALER_NOTE
            findings.append(FindingData(
                source=self.name,
                category="infostealer" if stealer else "vazamento",
                severity="critica" if stealer else severity,
                asset=email,
                title=(f"{email} aparece em logs de infostealer ({name})" if stealer
                       else f"{email} aparece no vazamento {name}"),
                detail=detail,
                reference_url=f"https://xposedornot.com/xposed#{quote(name)}",
                event_date=str(b.get("xposed_date") or ""),
                fingerprint=f"xon:{email}:{name.lower()}",
                merge_key=breach_key(email, name),
            ))
        return findings
