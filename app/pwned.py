"""Verificação de senha no Pwned Passwords (HIBP), gratuito e sem chave.

Usa k-anonimato: só os 5 primeiros caracteres do SHA-1 da senha são enviados;
a comparação com o restante acontece aqui. A senha nunca é gravada nem registrada.
"""

import hashlib

import httpx

API = "https://api.pwnedpasswords.com/range/"


class PwnedCheckError(Exception):
    pass


def pwned_count(http: httpx.Client, password: str) -> int:
    """Quantas vezes a senha aparece em vazamentos conhecidos (0 = não encontrada)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    try:
        # Add-Padding: a resposta tem tamanho constante, para não revelar nada pelo tamanho.
        resp = http.get(API + prefix, headers={"Add-Padding": "true"}, timeout=20)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise PwnedCheckError(f"Não foi possível consultar o Pwned Passwords ({exc.__class__.__name__}).") from exc
    for line in resp.text.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix:
            return int(count.strip() or 0)
    return 0
