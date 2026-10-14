"""crt.sh: certificados TLS emitidos para nomes que contêm a marca do cliente.

Golpistas costumam emitir certificado para o site falso (ex.:
empresa-login.com) dias antes do ataque. Os certificados ficam públicos nos
logs de Certificate Transparency, então isso funciona como alerta antecipado.
Nomes dentro do próprio domínio do cliente são ignorados.
"""

import re
from datetime import datetime, timedelta

from ..config import settings
from ..models import utcnow
from .base import Collector, CollectorError, FindingData
from .matching import search_term

API = "https://crt.sh/"
MAX_FINDINGS = 100
PHISHING_WORDS = ("login", "logon", "signin", "secure", "seguro", "conta", "acesso", "portal",
                  "webmail", "mail", "sso", "auth", "verify", "verifica", "pagamento", "boleto",
                  "pix", "suporte", "support", "rh", "vpn", "office", "microsoft", "update")


_HOSTNAME = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def looks_suspicious(name: str, domain: str) -> bool:
    """Nome contém o domínio do cliente ou uma palavra típica de phishing.

    Compara palavra a palavra (separadas por "." e "-") para evitar falsos
    positivos como "sso" dentro de "ericsson". Palavras longas também valem
    como parte de uma palavra (ex.: "empresalogin").
    """
    if re.search(rf"(^|[.-]){re.escape(domain)}($|[.-])", name):
        return True
    tokens = re.split(r"[.-]", name)
    return any(t == w or (len(w) >= 5 and w in t) for t in tokens for w in PHISHING_WORDS)


def _parse_date(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value)[:19])
    except ValueError:
        return None


class CrtShCollector(Collector):
    name = "crtsh"
    label = "crt.sh (certificados)"
    description = "Certificados recém-emitidos para domínios com o nome do cliente (sites falsos)."

    def __init__(self, http, days: int | None = None):
        super().__init__(http)
        self.days = settings.crtsh_days if days is None else days

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        term = search_term(domain)
        params = {"q": f"%{term}%", "output": "json", "exclude": "expired", "deduplicate": "Y"}
        for attempt in range(2):  # o crt.sh falha com frequência; uma segunda tentativa costuma resolver
            try:
                data = self.get_json(API, params=params, not_found_value=[], timeout=150)
                break
            except CollectorError as exc:
                if attempt:
                    raise CollectorError(f"{exc} — o crt.sh costuma ficar sobrecarregado; tente mais tarde.") from exc

        own = self.client_domains | {domain}
        cutoff = utcnow() - timedelta(days=self.days)
        seen: dict[str, dict] = {}
        for cert in data or []:
            if not isinstance(cert, dict):
                continue
            issued = _parse_date(cert.get("not_before") or cert.get("entry_timestamp") or "")
            if not issued or issued < cutoff:
                continue
            for raw in str(cert.get("name_value", "")).splitlines():
                name = raw.strip().lower().removeprefix("*.")
                if (not _HOSTNAME.match(name) or term not in name
                        or any(name == d or name.endswith("." + d) for d in own)):
                    continue
                prev = seen.get(name)
                if not prev or issued > prev["issued"]:
                    seen[name] = {"issued": issued, "issuer": cert.get("issuer_name", ""), "id": cert.get("id")}

        findings = []
        for name, info in sorted(seen.items(), key=lambda kv: kv[1]["issued"], reverse=True)[:MAX_FINDINGS]:
            suspicious = looks_suspicious(name, domain)
            detail = f"Certificado emitido em {info['issued']:%d/%m/%Y}"
            if info["issuer"]:
                detail += f" por {info['issuer']}"
            detail += "."
            if suspicious:
                detail += " O nome imita o domínio do cliente ou usa termos comuns em phishing."
            findings.append(FindingData(
                source=self.name,
                category="dominio_similar",
                severity="alta" if suspicious else "media",
                asset=domain,
                title=f"Certificado TLS para domínio com o nome do cliente: {name}",
                detail=detail,
                reference_url=f"https://crt.sh/?id={info['id']}" if info["id"] else f"https://crt.sh/?q={name}",
                event_date=f"{info['issued']:%Y-%m-%d}",
                fingerprint=f"crt:{name}",
            ))
        return findings
