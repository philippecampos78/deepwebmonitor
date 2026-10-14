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


class CollectorError(Exception):
    """Falha numa fonte. `findings` guarda o que foi coletado antes do problema."""

    def __init__(self, message: str, findings: list[FindingData] | None = None):
        super().__init__(message)
        self.findings = findings or []


class Collector:
    name = "base"
    label = "Base"
    description = ""

    def __init__(self, http: httpx.Client):
        self.http = http

    def enabled(self) -> bool:
        return True

    def disabled_reason(self) -> str:
        return ""

    def collect_domain(self, domain: str) -> list[FindingData]:
        return []

    def collect_email(self, email: str) -> list[FindingData]:
        return []

    def get_json(self, url: str, *, headers: dict | None = None, params: dict | None = None,
                 not_found_value=None, retries: int = 3):
        """GET com tratamento de 404 (sem resultados) e 429 (limite de requisições)."""
        for attempt in range(retries + 1):
            try:
                resp = self.http.get(url, headers=headers, params=params)
            except httpx.HTTPError as exc:
                raise CollectorError(f"{self.label}: falha de conexão ({exc.__class__.__name__})") from exc
            if resp.status_code == 404:
                return not_found_value
            if resp.status_code == 429 and attempt < retries:
                wait = resp.headers.get("retry-after", "")
                time.sleep(min(float(wait) if wait.replace(".", "", 1).isdigit() else 2 ** (attempt + 1), 60))
                continue
            if resp.status_code >= 400:
                raise CollectorError(f"{self.label}: HTTP {resp.status_code} em {url}")
            try:
                return resp.json()
            except ValueError as exc:
                raise CollectorError(f"{self.label}: resposta não é JSON em {url}") from exc
        raise CollectorError(f"{self.label}: limite de requisições excedido em {url}")
