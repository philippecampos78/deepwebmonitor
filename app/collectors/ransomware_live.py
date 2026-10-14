"""ransomware.live: vítimas publicadas em sites de vazamento de grupos de ransomware.

API pública e gratuita (https://www.ransomware.live/apidocs). A busca é por
palavra-chave, então usamos o "nome" do domínio (empresa.com.br -> empresa) e
classificamos a correspondência:
  - forte: o domínio completo aparece no nome ou site da vítima;
  - possível: só o nome aparece (pode ser outra empresa com nome parecido).
"""

from urllib.parse import quote

from .base import Collector, FindingData
from .matching import brand_keyword, first_value, search_term, victim_match  # noqa: F401

API = "https://api.ransomware.live/v2"
SITE = "https://www.ransomware.live"


class RansomwareLiveCollector(Collector):
    name = "ransomware_live"
    label = "ransomware.live"
    description = "Vítimas publicadas por grupos de ransomware."

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        keyword = search_term(domain)
        data = self.get_json(f"{API}/searchvictims/{quote(keyword)}", not_found_value=[])
        if isinstance(data, dict):
            data = data.get("victims") or data.get("data") or []

        findings = []
        for v in data or []:
            if not isinstance(v, dict):
                continue
            victim = first_value(v, "victim", "post_title", "name")
            group = first_value(v, "group", "group_name")
            date = first_value(v, "attackdate", "discovered", "published")[:10]
            website = first_value(v, "domain", "website")
            matched = victim_match(domain, victim, website)
            if not matched:
                continue
            severity, match = matched

            detail = f"{match}. Grupo: {group or 'desconhecido'}."
            if website:
                detail += f" Site informado: {website}."
            if v.get("country"):
                detail += f" País: {v['country']}."
            desc = first_value(v, "description")
            if desc:
                detail += f" Descrição publicada: {desc[:400]}"
            claim = first_value(v, "claim_url", "post_url")
            if ".onion" in claim:
                detail += f" Endereço da publicação (rede Tor, não acessar da rede corporativa): {claim}"
            permalink = first_value(v, "url", "permalink")

            findings.append(FindingData(
                source=self.name,
                category="ransomware",
                severity=severity,
                asset=domain,
                title=f"{victim or website} listado pelo grupo {group or 'desconhecido'}",
                detail=detail,
                reference_url=permalink if permalink.startswith(SITE) else SITE,
                event_date=date,
                fingerprint=f"rl:{group.lower()}:{victim.lower()}:{date}",
            ))
        return findings
