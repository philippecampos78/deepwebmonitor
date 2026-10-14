"""ransomware.live: vítimas publicadas em sites de vazamento de grupos de ransomware.

API pública e gratuita (https://www.ransomware.live/apidocs). A busca é por
palavra-chave, então usamos o "nome" do domínio (empresa.com.br -> empresa) e
classificamos a correspondência:
  - forte: o domínio completo aparece no nome ou site da vítima;
  - possível: só o nome aparece (pode ser outra empresa com nome parecido).
"""

from urllib.parse import quote

from .base import Collector, FindingData

API = "https://api.ransomware.live/v2"
SITE = "https://www.ransomware.live"

# Segundo nível comum em TLDs de país (empresa.com.br, empresa.co.uk ...)
_SECOND_LEVEL = {"com", "net", "org", "gov", "edu", "co", "ind", "adv", "eng", "med", "art", "ac"}
MIN_KEYWORD_LEN = 4


def brand_keyword(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in _SECOND_LEVEL:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


def _first(v: dict, *keys) -> str:
    for k in keys:
        val = v.get(k)
        if val:
            return str(val)
    return ""


class RansomwareLiveCollector(Collector):
    name = "ransomware_live"
    label = "ransomware.live"
    description = "Vítimas publicadas por grupos de ransomware."

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        keyword = brand_keyword(domain)
        if len(keyword) < MIN_KEYWORD_LEN:
            keyword = domain
        data = self.get_json(f"{API}/searchvictims/{quote(keyword)}", not_found_value=[])
        if isinstance(data, dict):
            data = data.get("victims") or data.get("data") or []

        findings = []
        for v in data or []:
            if not isinstance(v, dict):
                continue
            victim = _first(v, "victim", "post_title", "name")
            group = _first(v, "group", "group_name")
            date = _first(v, "attackdate", "discovered", "published")[:10]
            website = _first(v, "domain", "website")
            haystack = f"{victim} {website}".lower()

            if domain in haystack:
                severity, match = "critica", "Correspondência forte (domínio completo)"
            elif keyword in haystack:
                severity, match = "media", "Possível correspondência (somente o nome) — validar manualmente"
            else:
                continue

            detail = f"{match}. Grupo: {group or 'desconhecido'}."
            if website:
                detail += f" Site informado: {website}."
            if v.get("country"):
                detail += f" País: {v['country']}."
            desc = _first(v, "description")
            if desc:
                detail += f" Descrição publicada: {desc[:400]}"
            post = _first(v, "url", "post_url")
            if post:
                detail += f" Endereço da publicação (rede Tor, não acessar da rede corporativa): {post}"

            findings.append(FindingData(
                source=self.name,
                category="ransomware",
                severity=severity,
                asset=domain,
                title=f"{victim or website} listado pelo grupo {group or 'desconhecido'}",
                detail=detail,
                reference_url=_first(v, "permalink") or SITE,
                event_date=date,
                fingerprint=f"rl:{group.lower()}:{victim.lower()}:{date}",
            ))
        return findings
