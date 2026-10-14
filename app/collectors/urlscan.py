"""urlscan.io: páginas falsas que usam a marca do cliente.

Duas buscas nos sites analisados recentemente (públicos):
  1. páginas em outros domínios que carregam imagens/scripts do site do cliente,
     um sinal clássico de kit de phishing copiando o visual original;
  2. páginas cujo domínio contém o nome da marca (ex.: empresa-login.com).
Sem chave, só é possível buscar domínios que COMEÇAM com o nome da marca;
com a chave gratuita a busca cobre o nome em qualquer posição.
"""

from ..config import settings
from .base import Collector, FindingData
from .matching import search_term

API = "https://urlscan.io/api/v1/search/"
MAX_RESULTS = 100
SCAM_TAGS = {"phishing", "scam", "cryptoscam", "fakeshop", "malicious", "suspicious"}


class UrlscanCollector(Collector):
    name = "urlscan"
    label = "urlscan.io"
    description = "Páginas falsas usando a marca ou o visual do site do cliente."

    def __init__(self, http, api_key: str | None = None, days: int | None = None):
        super().__init__(http)
        self.api_key = settings.urlscan_api_key if api_key is None else api_key
        self.days = settings.urlscan_days if days is None else days

    def status_note(self) -> str:
        return "" if self.api_key else "sem chave: busca da marca só no início do domínio e limites menores"

    def _search(self, query: str) -> list[dict]:
        headers = {"API-Key": self.api_key} if self.api_key else None
        data = self.get_json(API, headers=headers, params={"q": f"({query}) AND date:>now-{self.days}d",
                                                           "size": MAX_RESULTS}, not_found_value={}) or {}
        return [r for r in data.get("results") or [] if isinstance(r, dict)]

    def _own(self, page_domain: str) -> bool:
        own = self.client_domains | {self._domain}
        return any(page_domain == d or page_domain.endswith("." + d) for d in own)

    def collect_domain(self, domain: str) -> list[FindingData]:
        self._domain = domain = domain.lower()
        brand = search_term(domain)
        brand_query = f"page.domain:*{brand}*" if self.api_key else f"page.domain:{brand}*"
        seen: dict[str, tuple[dict, str]] = {}
        for result in self._search(f"domain:{domain} AND NOT page.domain:{domain}"):
            seen.setdefault((result.get("page") or {}).get("domain", ""), (result, "resources"))
        for result in self._search(f"{brand_query} AND NOT page.domain:{domain}"):
            seen[(result.get("page") or {}).get("domain", "")] = (result, "brand")

        findings = []
        for page_domain, (r, why) in seen.items():
            page_domain = page_domain.lower()
            if not page_domain or self._own(page_domain):
                continue
            page, task = r.get("page") or {}, r.get("task") or {}
            tags = {t.lower() for t in (task.get("tags") or []) + (r.get("labels") or []) if isinstance(t, str)}
            scam = bool(tags & SCAM_TAGS)
            if scam:
                severity = "critica"
            elif why == "brand":
                severity = "alta"
            else:
                severity = "media"
            reason = ("O domínio contém o nome da marca" if why == "brand"
                      else f"A página carrega imagens ou scripts de {domain} (comum em cópias de sites para phishing)")
            detail = f"{reason}. URL: {page.get('url') or task.get('url', '?')}."
            if page.get("title"):
                detail += f" Título: \"{page['title'][:150]}\"."
            if tags:
                detail += f" Classificação do urlscan: {', '.join(sorted(tags))}."
            if page.get("domainAgeDays") is not None:
                detail += f" Domínio com {page['domainAgeDays']} dia(s) de existência."
            if page.get("ip"):
                detail += f" IP: {page['ip']} ({page.get('asnname', '')})."
            findings.append(FindingData(
                source=self.name, category="phishing", severity=severity, asset=domain,
                title=f"Página suspeita usando a marca: {page_domain}",
                detail=detail,
                reference_url=f"https://urlscan.io/result/{r['_id']}/" if r.get("_id") else "https://urlscan.io",
                event_date=str(task.get("time") or "")[:10],
                fingerprint=f"urlscan:{page_domain}",
            ))
        return findings
