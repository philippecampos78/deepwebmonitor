"""GitHub: código público que menciona o domínio do cliente, com busca de segredos.

1. A API de busca de código encontra arquivos públicos que citam o domínio.
2. Cada arquivo é baixado e analisado pelo gitleaks (se instalado) ou por regras
   internas mais simples, para achar senhas, tokens e chaves.
O valor do segredo nunca é gravado: só o tipo, o arquivo, a linha e uma máscara.
"""

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..config import settings
from .base import Collector, CollectorError, FindingData
from .matching import mask_secret as mask

API = "https://api.github.com"
MAX_FILES = 20
MAX_FILE_BYTES = 512_000

_PLACEHOLDERS = {"password", "senha", "changeme", "example", "xxxxxx", "********", "your_password",
                 "yourpassword", "secret", "token", "null", "none", "true", "false", "undefined"}
BUILTIN_RULES = [
    ("aws-access-key", "Chave de acesso AWS", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("private-key", "Chave privada", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)")),
    ("url-credentials", "Usuário e senha embutidos em URL",
     re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:([^\s:/@'\"]{4,})@", re.I)),
    ("generic-password", "Senha ou segredo atribuído no código",
     re.compile(r"(?i)\b[\w.-]*(?:pass(?:word)?|passwd|pwd|senha|secret|api[_-]?key|access[_-]?token)"
                r"[\w-]*[\"']?\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']")),
]


def builtin_scan(text: str) -> list[dict]:
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule_id, desc, rx in BUILTIN_RULES:
            for m in rx.finditer(line):
                value = m.group(1)
                if value.lower() in _PLACEHOLDERS or any(c in value for c in "${}<>"):
                    continue
                hits.append({"rule": rule_id, "description": desc, "line": lineno, "secret": value})
    return hits


class GitHubCodeCollector(Collector):
    name = "github"
    label = "GitHub (código público)"
    description = "Senhas, tokens e chaves do cliente expostos em repositórios públicos."

    def __init__(self, http, token: str | None = None, gitleaks: str | None = None):
        super().__init__(http)
        self.token = settings.github_token if token is None else token
        self.gitleaks = self._find_gitleaks(settings.gitleaks_path if gitleaks is None else gitleaks)

    @staticmethod
    def _find_gitleaks(path: str) -> str:
        if not path:
            return ""
        if os.path.isfile(path):
            return path
        return shutil.which(path) or ""

    def enabled(self) -> bool:
        return bool(self.token)

    def disabled_reason(self) -> str:
        return "defina GITHUB_TOKEN no .env (token gratuito, só leitura de repositórios públicos)"

    def status_note(self) -> str:
        if self.gitleaks:
            return "gitleaks encontrado"
        return "gitleaks não encontrado — usando regras internas (veja GITLEAKS_PATH no .env)"

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}

    def _download(self, item: dict) -> str:
        data = self.get_json(item["url"], headers=self._headers(), not_found_value={}) or {}
        if data.get("encoding") != "base64" or (data.get("size") or 0) > MAX_FILE_BYTES:
            return ""
        try:
            return base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
        except ValueError:
            return ""

    def _gitleaks_scan(self, files: dict[str, str]) -> dict[str, list[dict]]:
        """Roda o gitleaks numa pasta temporária. Devolve {nome_do_arquivo: [achados]}."""
        with tempfile.TemporaryDirectory(prefix="dwm-gitleaks-") as tmp:
            for fname, text in files.items():
                Path(tmp, fname).write_text(text, encoding="utf-8")
            report = Path(tmp, "_report.json")
            common = ["--report-format", "json", "--report-path", str(report), "--exit-code", "0",
                      "--no-banner", "--log-level", "error"]
            for args in ([self.gitleaks, "dir", tmp, *common],                      # gitleaks >= 8.19
                         [self.gitleaks, "detect", "--no-git", "--source", tmp, *common]):  # versões antigas
                try:
                    subprocess.run(args, capture_output=True, timeout=180, check=False)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise CollectorError(f"{self.label}: falha ao executar o gitleaks ({exc})") from exc
                if report.exists():
                    break
            else:
                raise CollectorError(f"{self.label}: o gitleaks não gerou relatório")
            raw = json.loads(report.read_text(encoding="utf-8") or "[]")
        out: dict[str, list[dict]] = {}
        for r in raw or []:
            out.setdefault(Path(r.get("File", "")).name, []).append({
                "rule": r.get("RuleID", "?"), "description": r.get("Description", ""),
                "line": r.get("StartLine", 0), "secret": r.get("Secret", ""),
            })
        return out

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        data = self.get_json(f"{API}/search/code", headers=self._headers(),
                             params={"q": f'"{domain}"', "per_page": 50}, not_found_value={}) or {}
        items = [i for i in data.get("items") or [] if isinstance(i, dict) and i.get("url")]

        files: dict[str, str] = {}
        meta: dict[str, dict] = {}
        for idx, item in enumerate(items[:MAX_FILES]):
            text = self._download(item)
            if domain not in text.lower():
                continue
            fname = f"{idx:03d}_{Path(item.get('path', 'arquivo')).name}"
            files[fname] = text
            meta[fname] = item

        engine = "regras internas"
        if self.gitleaks and files:
            hits_by_file = self._gitleaks_scan(files)
            engine = "gitleaks"
        else:
            hits_by_file = {f: builtin_scan(t) for f, t in files.items()}

        findings = []
        repos_without_secrets: dict[str, list[str]] = {}
        for fname, item in meta.items():
            repo = (item.get("repository") or {}).get("full_name", "?")
            path = item.get("path", "")
            url = item.get("html_url", "")
            hits = hits_by_file.get(fname, [])
            if not hits:
                repos_without_secrets.setdefault(repo, []).append(path)
                continue
            for h in hits:
                findings.append(FindingData(
                    source=self.name,
                    category="codigo_exposto",
                    severity="alta",
                    asset=domain,
                    title=f"Possível segredo exposto em {repo}/{path} (linha {h['line']})",
                    detail=(f"Tipo: {h['description'] or h['rule']} (detectado por {engine}). "
                            f"Valor mascarado: {mask(h['secret'])}. O arquivo é público e menciona {domain}. "
                            "Verificar se a credencial é do cliente e revogá-la."),
                    reference_url=f"{url}#L{h['line']}" if url else "",
                    fingerprint=f"gh:secret:{repo}:{path}:{h['rule']}:{h['line']}",
                ))
        for repo, paths in repos_without_secrets.items():
            findings.append(FindingData(
                source=self.name,
                category="codigo_exposto",
                severity="baixa",
                asset=domain,
                title=f"Repositório público menciona {domain}: {repo}",
                detail=(f"Arquivos: {', '.join(paths[:10])}. Nenhum segredo detectado ({engine}); "
                        "vale revisar se expõe informações internas (servidores, e-mails, configurações)."),
                reference_url=f"https://github.com/{repo}",
                fingerprint=f"gh:repo:{repo}",
            ))
        if data.get("total_count", 0) > MAX_FILES and findings:
            raise CollectorError(
                f"{self.label}: {data['total_count']} arquivos citam {domain}; só os {MAX_FILES} "
                "primeiros foram analisados.", findings=findings)
        return findings
