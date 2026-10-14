"""Contrato comum a todas as fontes.

Cada coletor recebe um domínio ou e-mail e devolve uma lista de FindingData,
sempre no mesmo formato. O scanner cuida de gravar, deduplicar e marcar o que
é novo; o coletor só precisa saber falar com a sua fonte.
"""

import time
from dataclasses import dataclass

import httpx


@dataclass
class FindingData:
    source: str
    category: str
    severity: str
    asset: str
    title: str
    fingerprint: str
    detail: str = ""
    reference_url: str = ""
    event_date: str = ""
    # Mesmo valor em fontes diferentes = mesmo achado (ex.: o mesmo vazamento no HIBP e no XposedOrNot)
    merge_key: str = ""


@dataclass
class ClientInfo:
    name: str
    domains: list[str]
    suppliers: list[tuple[str, str]]  # (nome, domínio opcional)


class CollectorError(Exception):
    """Falha numa fonte. `findings` guarda o que foi coletado antes do problema."""

    def __init__(self, message: str, findings: list[FindingData] | None = None):
        super().__init__(message)
        self.findings = findings or []


class Collector:
    name = "base"
    label = "Base"
    description = ""
    slow = False  # pode levar minutos (aparece marcada como "lenta" na escolha de fontes)
    # True = além dos e-mails cadastrados, consulta os e-mails do domínio do cliente
    # que outras fontes já encontraram (limitado a MAX_DISCOVERED_EMAILS por varredura)
    checks_discovered_emails = False

    def __init__(self, http: httpx.Client):
        self.http = http
        # Todos os domínios do cliente em varredura (o scanner preenche).
        self.client_domains: set[str] = set()

    def enabled(self) -> bool:
        return True

    def disabled_reason(self) -> str:
        return ""

    def status_note(self) -> str:
        """Observação exibida no painel (ex.: chave opcional ausente)."""
        return ""

    def supports(self, kind: str) -> bool:
        """A fonte consulta esse tipo de item ("domain", "email" ou "client")?"""
        method = {"domain": "collect_domain", "email": "collect_email", "client": "collect_client"}[kind]
        return getattr(type(self), method) is not getattr(Collector, method)

    def collect_client(self, client: "ClientInfo") -> list[FindingData]:
        """Consulta o cliente como um todo (nome, domínios e fornecedores)."""
        return []

    def collect_domain(self, domain: str) -> list[FindingData]:
        return []

    def collect_email(self, email: str) -> list[FindingData]:
        return []

    def request(self, method: str, url: str, *, headers: dict | None = None,
                params: dict | None = None, data=None, json=None, timeout: float | None = None,
                retries: int = 3) -> httpx.Response | None:
        """Requisição com tratamento de 404 (devolve None) e de limite de requisições
        (429, ou 403 do GitHub com x-ratelimit-remaining=0): espera e tenta de novo."""
        kwargs = {"headers": headers, "params": params, "data": data, "json": json}
        if timeout is not None:
            kwargs["timeout"] = timeout
        for attempt in range(retries + 1):
            try:
                resp = self.http.request(method, url, **{k: v for k, v in kwargs.items() if v is not None})
            except httpx.HTTPError as exc:
                raise CollectorError(f"{self.label}: falha de conexão ({exc.__class__.__name__})") from exc
            if resp.status_code == 404:
                return None
            limited = resp.status_code == 429 or (
                resp.status_code == 403 and resp.headers.get("x-ratelimit-remaining") == "0")
            if limited and attempt < retries:
                time.sleep(self._wait_seconds(resp, attempt))
                continue
            if limited:
                raise CollectorError(f"{self.label}: limite de requisições excedido em {url}")
            if resp.status_code >= 400:
                raise CollectorError(f"{self.label}: HTTP {resp.status_code} em {url}{self._reason(resp)}")
            return resp
        raise CollectorError(f"{self.label}: limite de requisições excedido em {url}")

    @staticmethod
    def _reason(resp: httpx.Response) -> str:
        """Motivo do erro informado pela fonte, quando houver (ex.: chave inválida)."""
        try:
            body = resp.json()
        except ValueError:
            return ""
        msg = (body.get("message") or body.get("error") or "") if isinstance(body, dict) else ""
        return f" ({str(msg)[:200]})" if msg else ""

    @staticmethod
    def _wait_seconds(resp: httpx.Response, attempt: int) -> float:
        retry_after = resp.headers.get("retry-after", "")
        if retry_after.replace(".", "", 1).isdigit():
            return min(float(retry_after), 60)
        reset = resp.headers.get("x-ratelimit-reset", "")
        if reset.isdigit():
            return min(max(int(reset) - time.time(), 1), 60)
        return min(2 ** (attempt + 1), 60)

    def get_json(self, url: str, *, not_found_value=None, method: str = "GET", **kwargs):
        resp = self.request(method, url, **kwargs)
        if resp is None:
            return not_found_value
        try:
            return resp.json()
        except ValueError as exc:
            raise CollectorError(f"{self.label}: resposta não é JSON em {url}") from exc

    def get_text(self, url: str, **kwargs) -> str:
        resp = self.request("GET", url, **kwargs)
        return resp.text if resp is not None else ""
