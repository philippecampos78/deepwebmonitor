"""Catálogo de Vazamentos BR: incidentes públicos envolvendo o cliente e seus
fornecedores/parceiros (risco de terceiros).

O catálogo é outro sistema da UXGUARD (repositório catalogo-vazamentos-br),
rodando localmente; esta fonte só consulta a API de busca dele.
"""

from datetime import date, timedelta

from ..config import settings
from .base import ClientInfo, Collector, CollectorError, FindingData

STALE_DAYS = 365  # incidentes com mais de 1 ano baixam um nível de gravidade
_LOWER = {"critica": "alta", "alta": "media", "media": "baixa", "baixa": "info", "info": "info"}
CONFIDENCE_PT = {"confirmado": "Informação confirmada", "alegado": "Informação alegada pelo grupo criminoso",
                 "reportado": "Informação reportada pela imprensa"}

# (tipo do incidente, correspondência) -> gravidade, para o cliente e para terceiros
SEVERITY_CLIENT = {("ransomware", "forte"): "critica", ("vazamento", "forte"): "alta",
                   ("acesso_indevido", "forte"): "alta"}
SEVERITY_SUPPLIER = {("ransomware", "forte"): "alta", ("vazamento", "forte"): "media",
                     ("acesso_indevido", "forte"): "media"}


class CatalogoBRCollector(Collector):
    name = "catalogo_br"
    label = "Catálogo de Vazamentos BR"
    description = "Incidentes públicos no Brasil envolvendo o cliente e seus fornecedores e parceiros."

    def __init__(self, http, url: str | None = None, api_key: str | None = None):
        super().__init__(http)
        self.url = settings.catalogo_url if url is None else url.rstrip("/")
        self.api_key = settings.catalogo_api_key if api_key is None else api_key

    def enabled(self) -> bool:
        return bool(self.url)

    def disabled_reason(self) -> str:
        return "defina CATALOGO_URL no .env (catálogo rodando, ex.: http://127.0.0.1:8001)"

    def _search(self, name: str = "", domain: str = "") -> list[dict]:
        headers = {"X-API-Key": self.api_key} if self.api_key else None
        try:
            data = self.get_json(f"{self.url}/api/v1/busca", headers=headers,
                                 params={k: v for k, v in {"nome": name, "dominio": domain}.items() if v},
                                 not_found_value={}, timeout=30)
        except CollectorError as exc:
            raise CollectorError(f"{exc} — o Catálogo de Vazamentos BR está aberto ({self.url})?") from exc
        return [r for r in (data or {}).get("resultados") or [] if isinstance(r, dict)]

    @staticmethod
    def _severity(table: dict, inc: dict) -> str:
        sev = table.get((inc.get("tipo"), inc.get("correspondencia")))
        if not sev:  # notícias genéricas e correspondências só pelo nome
            sev = "media" if inc.get("correspondencia") == "forte" else "baixa"
        when = inc.get("data_divulgacao") or inc.get("data_incidente") or ""
        if when and when < (date.today() - timedelta(days=STALE_DAYS)).isoformat():
            sev = _LOWER[sev]
        return sev

    def _finding(self, inc: dict, target: str, asset: str, supplier: bool) -> FindingData:
        possible = inc.get("correspondencia") != "forte"
        org = inc.get("organizacao") or target
        kind = (inc.get("tipo_descricao") or "Incidente").lower()
        if supplier:
            title = f"Fornecedor/parceiro {target}: {kind}" + (" (possível, validar)" if possible else "")
        else:
            title = f"{org}: {kind}" + (" (possível menção, validar)" if possible else "")
        parts = [inc.get("titulo", "")]
        if inc.get("grupo"):
            parts.append(f"Grupo: {inc['grupo']}")
        if inc.get("dados_expostos"):
            parts.append(f"Dados expostos: {inc['dados_expostos']}")
        if inc.get("confianca"):
            parts.append(CONFIDENCE_PT.get(inc["confianca"], inc["confianca"]))
        if inc.get("resumo"):
            parts.append(inc["resumo"][:300])
        if possible:
            parts.append("Correspondência apenas pelo nome: pode se tratar de outra organização com nome parecido")
        if supplier:
            parts.append(f"Avaliar o impacto para {asset}: acessos, integrações e dados compartilhados com este fornecedor")
        return FindingData(
            source=self.name,
            category="terceiros" if supplier else "incidente_proprio",
            severity=self._severity(SEVERITY_SUPPLIER if supplier else SEVERITY_CLIENT, inc),
            asset=target if supplier else asset,
            title=title,
            detail=". ".join(p.rstrip(".") for p in parts if p) + ".",
            reference_url=inc.get("fonte_url", ""),
            event_date=inc.get("data_divulgacao") or inc.get("data_incidente") or "",
            fingerprint=f"catalogo:{'terceiro' if supplier else 'cliente'}:{target.lower()}:{inc.get('id')}",
        )

    @staticmethod
    def _keep(findings: dict, inc: dict, finding: FindingData) -> None:
        """O mesmo incidente achado por nome e por domínio fica com a correspondência mais forte."""
        current = findings.get(finding.fingerprint)
        if current is None or (inc.get("correspondencia") == "forte" and not current[0]):
            findings[finding.fingerprint] = (inc.get("correspondencia") == "forte", finding)

    def collect_client(self, client: ClientInfo) -> list[FindingData]:
        findings: dict[str, tuple[bool, FindingData]] = {}
        main_domain = client.domains[0] if client.domains else client.name
        # O próprio cliente: pelo nome e por cada domínio
        queries = [(client.name, "")] + [("", d) for d in client.domains]
        for name, domain in queries:
            for inc in self._search(name=name, domain=domain):
                self._keep(findings, inc, self._finding(inc, client.name, main_domain, supplier=False))
        # Fornecedores e parceiros
        for sup_name, sup_domain in client.suppliers:
            for inc in self._search(name=sup_name, domain=sup_domain):
                self._keep(findings, inc, self._finding(inc, sup_name, client.name, supplier=True))
        return [f for _, f in findings.values()]
