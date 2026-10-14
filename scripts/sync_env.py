"""Acrescenta ao .env as configurações novas do .env.example, sem alterar as existentes.

Roda a cada início do site (iniciar.bat). Valores já preenchidos nunca são tocados.
"""

import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEY = re.compile(r"^\s*([A-Z][A-Z0-9_]*)\s*=")


def blocks(lines: list[str]):
    """Cada configuração com os comentários logo acima dela."""
    comments: list[str] = []
    for line in lines:
        m = KEY.match(line)
        if m:
            yield m.group(1), comments + [line]
            comments = []
        elif line.strip().startswith("#"):
            comments.append(line)
        else:
            comments = []


def _read(path: Path) -> tuple[str, str]:
    """Lê aceitando UTF-8 com ou sem BOM (Bloco de Notas) ou a codificação antiga do Windows."""
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(enc), ("utf-8" if enc == "utf-8-sig" else enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1"), "latin-1"


def sync(env: Path, example: Path) -> list[str]:
    if not example.exists():
        return []
    if not env.exists():
        env.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
        return ["(arquivo .env criado a partir do .env.example)"]
    current, encoding = _read(env)
    existing = {m.group(1) for m in map(KEY.match, current.splitlines()) if m}
    missing = [(k, b) for k, b in blocks(example.read_text(encoding="utf-8").splitlines()) if k not in existing]
    if not missing:
        return []
    text = current.rstrip("\n") + f"\n\n# --- Configurações novas adicionadas em {date.today():%d/%m/%Y} ---\n"
    text += "\n".join("\n".join(b) for _, b in missing) + "\n"
    bom = env.read_bytes().startswith(b"\xef\xbb\xbf")
    env.write_bytes((b"\xef\xbb\xbf" if bom else b"") + text.encode(encoding, errors="replace"))
    return [k for k, _ in missing]


if __name__ == "__main__":
    added = sync(ROOT / ".env", ROOT / ".env.example")
    if added:
        print("Configurações novas acrescentadas ao .env: " + ", ".join(added))
        print("Abra o .env para preencher as que precisam de chave.")
    sys.exit(0)
