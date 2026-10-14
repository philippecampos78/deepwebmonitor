"""Consultas DNS usadas pelas fontes (SPF, DKIM, DMARC, IPs dos servidores).

Padrão: DNS via HTTPS (DoH), que funciona atrás de proxy corporativo e não
depende da porta 53. Com DNS_MODE=local, usa o DNS do computador (dnspython).
"""

import re

import httpx

from ..config import settings

TYPES = {"A": 1, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
_TXT_CHUNK = re.compile(r'"((?:[^"\\]|\\.)*)"')


class DNSError(Exception):
    pass


def _txt(data: str) -> str:
    """Registros TXT longos vêm divididos em pedaços entre aspas; junta tudo."""
    chunks = _TXT_CHUNK.findall(data)
    return "".join(chunks) if chunks else data.strip('"')


def resolve(http: httpx.Client | None, name: str, rtype: str) -> list[str]:
    """Devolve os valores do registro (vazio se não existir)."""
    rtype = rtype.upper()
    if settings.dns_mode == "local":
        return _resolve_local(name, rtype)
    try:
        resp = http.get(settings.dns_doh_url, params={"name": name, "type": rtype},
                        headers={"accept": "application/dns-json"}, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise DNSError(f"falha na consulta DNS de {name} ({exc.__class__.__name__})") from exc
    if data.get("Status") not in (0, 3):  # 3 = domínio inexistente
        raise DNSError(f"consulta DNS de {name} devolveu status {data.get('Status')}")
    out = []
    for ans in data.get("Answer") or []:
        if ans.get("type") != TYPES[rtype]:
            continue
        value = str(ans.get("data", ""))
        if rtype == "TXT":
            value = _txt(value)
        elif rtype == "MX":
            value = value.split()[-1]
        out.append(value.rstrip(".") if rtype in ("MX", "CNAME") else value)
    return out


def _resolve_local(name: str, rtype: str) -> list[str]:
    import dns.exception
    import dns.resolver

    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=10)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise DNSError(f"falha na consulta DNS de {name} ({exc.__class__.__name__})") from exc
    out = []
    for r in answers:
        if rtype == "TXT":
            out.append(b"".join(r.strings).decode("utf-8", errors="replace"))
        elif rtype == "MX":
            out.append(str(r.exchange).rstrip("."))
        else:
            out.append(str(r).rstrip("."))
    return out
