"""RansomLook (https://www.ransomlook.io): outro agregador de sites de vazamento
de ransomware, com cobertura de grupos diferente da do ransomware.live.

A API pública não tem busca por palavra, então baixamos as publicações dos
últimos N dias uma vez por varredura e comparamos localmente.
"""

from ..config import settings
from .base import Collector, FindingData
from .matching import first_value, victim_match

API = "https://www.ransomlook.io/api"
SITE = "https://www.ransomlook.io"


class RansomLookCollector(Collector):
    name = "ransomlook"
    label = "RansomLook"
    description = "Vítimas publicadas por grupos de ransomware (segunda base, outros grupos)."

    def __init__(self, http, days: int | None = None):
        super().__init__(http)
        self.days = settings.ransomlook_days if days is None else days
        self._posts: list[dict] | None = None

    def posts(self) -> list[dict]:
        if self._posts is None:
            data = self.get_json(f"{API}/last/{self.days}", not_found_value=[], timeout=120)
            if isinstance(data, dict):  # algumas versões agrupam por grupo
                flat = []
                for group, items in data.items():
                    for p in items if isinstance(items, list) else []:
                        if isinstance(p, dict):
                            flat.append({"group_name": group, **p})
                data = flat
            self._posts = [p for p in data or [] if isinstance(p, dict)]
        return self._posts

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        findings = []
        for p in self.posts():
            title = first_value(p, "post_title", "victim", "title")
            website = first_value(p, "website", "domain")
            matched = victim_match(domain, title, website)
            if not matched:
                continue
            severity, match = matched
            group = first_value(p, "group_name", "group")
            date = first_value(p, "discovered", "published", "date")[:10]
            detail = f"{match}. Grupo: {group or 'desconhecido'}."
            desc = first_value(p, "description")
            if desc:
                detail += f" Descrição publicada: {desc[:400]}"
            link = first_value(p, "link", "url")
            if link and ".onion" in link:
                detail += f" Endereço da publicação (rede Tor, não acessar da rede corporativa): {link}"
            findings.append(FindingData(
                source=self.name,
                category="ransomware",
                severity=severity,
                asset=domain,
                title=f"{title or website} listado pelo grupo {group or 'desconhecido'}",
                detail=detail,
                reference_url=f"{SITE}/group/{group}" if group else SITE,
                event_date=date,
                fingerprint=f"rlook:{group.lower()}:{title.lower()}:{date}",
            ))
        return findings
