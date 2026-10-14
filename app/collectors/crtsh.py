"""crt.sh: certificados TLS emitidos para nomes que contêm a marca do cliente.

Golpistas costumam emitir certificado para o site falso (ex.:
empresa-login.com) dias antes do ataque. Os certificados ficam públicos nos
logs de Certificate Transparency, então isso funciona como alerta antecipado.
Nomes dentro do próprio domínio do cliente são ignorados.
"""

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
        try:
            data = self.get_json(API, params={"q": f"%{term}%", "output": "json", "exclude": "expired",
                                              "deduplicate": "Y"}, not_found_value=[], timeout=120)
        except CollectorError as exc:
            raise CollectorError(f"{exc} — o crt.sh costuma ficar sobrecarregado; tente mais tarde.") from exc

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
                if (not name or term not in name or name == domain or name.endswith("." + domain)
                        or "@" in name):
                    continue
                prev = seen.get(name)
                if not prev or issued > prev["issued"]:
                    seen[name] = {"issued": issued, "issuer": cert.get("issuer_name", ""), "id": cert.get("id")}

        findings = []
        for name, info in sorted(seen.items(), key=lambda kv: kv[1]["issued"], reverse=True)[:MAX_FINDINGS]:
            suspicious = domain in name or any(w in name for w in PHISHING_WORDS)
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
