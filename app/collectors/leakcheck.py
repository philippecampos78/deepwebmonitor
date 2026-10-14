"""LeakCheck (API pública gratuita): em quais vazamentos um e-mail aparece.

Devolve o nome e a data de cada vazamento e quais tipos de dado existem nas bases
(senha, telefone, documento...). Os dados em si não são devolvidos pela API pública.
"""

import time

from .base import Collector, FindingData
from .matching import breach_key

API = "https://leakcheck.io/api/public"
MIN_INTERVAL = 1.0
MAX_SOURCES = 200

FIELDS_PT = {
    "password": "senha", "username": "nome de usuário", "phone": "telefone", "dob": "data de nascimento",
    "address": "endereço", "ip": "endereço IP", "ssn": "documento de identidade", "name": "nome",
    "first_name": "nome", "last_name": "sobrenome", "city": "cidade", "zip": "CEP", "country": "país",
    "company_name": "empresa", "gender": "gênero",
}


class LeakCheckCollector(Collector):
    name = "leakcheck"
    label = "LeakCheck"
    description = "Vazamentos em que cada e-mail prioritário aparece (inclui bases menores e combolists)."

    _last_call = 0.0

    def __init__(self, http, min_interval: float = MIN_INTERVAL):
        super().__init__(http)
        self.min_interval = min_interval

    def _throttle(self):
        wait = LeakCheckCollector._last_call + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        LeakCheckCollector._last_call = time.monotonic()

    def collect_email(self, email: str) -> list[FindingData]:
        email = email.lower()
        self._throttle()
        data = self.get_json(API, params={"check": email}, not_found_value={}) or {}
        if not data.get("success"):
            return []
        raw_fields = [f for f in data.get("fields") or [] if isinstance(f, str)]
        has_password = "password" in raw_fields
        # Só os campos relevantes, traduzidos e sem repetir ("ip1", "ip2", "region"... ficam de fora)
        types = ", ".join(dict.fromkeys(FIELDS_PT[f] for f in raw_fields if f in FIELDS_PT))
        findings = []
        for src in (data.get("sources") or [])[:MAX_SOURCES]:
            if not isinstance(src, dict) or not src.get("name"):
                continue
            name, date = str(src["name"]), str(src.get("date") or "")
            detail = f"Vazamento: {name}" + (f" ({date})" if date else "") + "."
            if types:
                detail += (f" Dados encontrados para este e-mail no conjunto das bases: {types}."
                           " A API gratuita não informa quais vazaram em cada base.")
            if has_password:
                detail += " Há senha associada ao e-mail em pelo menos uma base: confira com \"Verificar senha\"."
            findings.append(FindingData(
                source=self.name,
                category="vazamento",
                severity="media",  # a API gratuita não diz se ESTA base tinha senha
                asset=email,
                title=f"{email} aparece no vazamento {name}",
                detail=detail,
                reference_url="https://leakcheck.io",
                event_date=date,
                fingerprint=f"leakcheck:{email}:{name.lower()}:{date}",
                merge_key=breach_key(email, name),
            ))
        return findings
