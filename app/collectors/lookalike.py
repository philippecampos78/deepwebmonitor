"""Domínios parecidos com o do cliente (typosquatting), via dnstwist.

Gera variações do domínio (troca de letras, hífens, outros TLDs...) e consulta
o DNS para ver quais estão registradas. Roda localmente, sem API externa.
"""

from ..config import settings
from .base import Collector, CollectorError, FindingData


def _join(value) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v and not str(v).startswith("!"))
    return str(value or "")


class LookalikeCollector(Collector):
    name = "lookalike"
    label = "Domínios parecidos (dnstwist)"
    description = "Domínios registrados parecidos com o do cliente, usados em phishing."

    def __init__(self, http, run=None, enabled: bool | None = None):
        super().__init__(http)
        self._run = run
        self._enabled = settings.dnstwist_enabled if enabled is None else enabled

    def enabled(self) -> bool:
        return self._enabled

    def disabled_reason(self) -> str:
        return "desativado no .env (DNSTWIST_ENABLED=false)"

    def _dnstwist(self, domain: str) -> list[dict]:
        if self._run:
            return self._run(domain)
        try:
            import dnstwist
        except ImportError as exc:
            raise CollectorError("dnstwist não está instalado (pip install dnstwist dnspython)") from exc
        return dnstwist.run(domain=domain, registered=True, format="null", threads=16)

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        findings = []
        for r in self._dnstwist(domain) or []:
            name = str(r.get("domain", "")).lower()
            if not name or name == domain or r.get("fuzzer") == "*original":
                continue
            a = _join(r.get("dns_a")) or _join(r.get("dns_aaaa"))
            mx = _join(r.get("dns_mx"))
            ns = _join(r.get("dns_ns"))
            if not (a or mx or ns):
                continue
            severity = "alta" if mx else "media"
            detail = f"Técnica de variação: {r.get('fuzzer', '?')}."
            if a:
                detail += f" IP: {a}."
            if mx:
                detail += f" Servidor de e-mail (MX): {mx} — o domínio pode enviar e-mails de phishing."
            if ns:
                detail += f" DNS: {ns}."
            findings.append(FindingData(
                source=self.name,
                category="dominio_similar",
                severity=severity,
                asset=domain,
                title=f"Domínio parecido registrado: {name}",
                detail=detail,
                reference_url=f"https://lookup.icann.org/lookup?name={name}",
                fingerprint=f"lookalike:{name}:{'mx' if mx else 'nomx'}",
            ))
        return findings
