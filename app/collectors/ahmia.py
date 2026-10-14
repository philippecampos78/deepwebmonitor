"""Ahmia (https://ahmia.fi): buscador de sites .onion acessível pela internet comum.

Procura o domínio do cliente (termo exato) nas páginas da rede Tor indexadas
pelo Ahmia. Não acessa a rede Tor: os endereços .onion aparecem só como texto.
"""

import html
import re
from datetime import datetime, timezone

from .base import Collector, FindingData

SITE = "https://ahmia.fi"
LEAK_WORDS = ("leak", "dump", "database", "breach", "vazamento", "vazado", "credential", "combo",
              "password", "senha", "ransom", "hacked", "stealer", "logs", "sell", "venda")

_RESULT = re.compile(r'<li[^>]*class="[^"]*result[^"]*"[^>]*>(.*?)</li>', re.S | re.I)
_HIDDEN = re.compile(r'<input[^>]*type="hidden"[^>]*>', re.I)
_ATTR = re.compile(r'(name|value)="([^"]*)"', re.I)
_TAGS = re.compile(r"<[^>]+>")
_ONION = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.I)


def _text(fragment: str) -> str:
    return " ".join(html.unescape(_TAGS.sub(" ", fragment)).split())


def _hidden_fields(page: str) -> dict:
    """O formulário de busca do Ahmia tem um campo oculto anti-robô que muda periodicamente."""
    fields = {}
    for tag in _HIDDEN.findall(page):
        attrs = dict((k.lower(), v) for k, v in _ATTR.findall(tag))
        if attrs.get("name"):
            fields[attrs["name"]] = attrs.get("value", "")
    return fields


def parse_results(page: str) -> list[dict]:
    results = []
    for block in _RESULT.findall(page):
        title = re.search(r"<h4[^>]*>(.*?)</h4>", block, re.S | re.I)
        desc = re.search(r"<p[^>]*>(.*?)</p>", block, re.S | re.I)
        onion = _ONION.search(block)
        ts = re.search(r'data-timestamp="(\d+)"', block)
        results.append({
            "title": _text(title.group(1)) if title else "",
            "description": _text(desc.group(1)) if desc else "",
            "onion": onion.group(0).lower() if onion else "",
            "last_seen": (datetime.fromtimestamp(int(ts.group(1)), tz=timezone.utc).strftime("%Y-%m-%d")
                          if ts else ""),
        })
    return results


class AhmiaCollector(Collector):
    name = "ahmia"
    label = "Ahmia (dark web)"
    description = "Menções ao domínio do cliente em sites .onion indexados."

    def __init__(self, http):
        super().__init__(http)
        self._hidden: dict | None = None

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        if self._hidden is None:
            self._hidden = _hidden_fields(self.get_text(f"{SITE}/"))
        page = self.get_text(f"{SITE}/search/", params={"q": f'"{domain}"', **self._hidden})

        findings = []
        for r in parse_results(page):
            text = f"{r['title']} {r['description']}".lower()
            if domain not in text:
                continue  # o buscador às vezes devolve resultados aproximados
            leak = any(w in text for w in LEAK_WORDS)
            detail = (f"Página .onion menciona {domain}"
                      + (" em contexto de vazamento/venda de dados" if leak else "") + ". "
                      f"Trecho indexado: {r['description'][:400] or '—'}")
            if r["onion"]:
                detail += f" Endereço (rede Tor, não acessar da rede corporativa): {r['onion']}"
            findings.append(FindingData(
                source=self.name,
                category="dark_web",
                severity="alta" if leak else "media",
                asset=domain,
                title=f"Menção na dark web: {r['title'] or r['onion'] or 'página sem título'}",
                detail=detail,
                reference_url=f"{SITE}/search/?q={domain}",
                event_date=r["last_seen"],
                fingerprint=f"ahmia:{r['onion']}:{r['title'].lower()[:120]}",
            ))
        return findings
