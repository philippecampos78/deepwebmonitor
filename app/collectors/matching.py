"""Regras de correspondência compartilhadas entre as fontes que buscam por nome."""

# Segundo nível comum em TLDs de país (empresa.com.br, empresa.co.uk ...)
_SECOND_LEVEL = {"com", "net", "org", "gov", "edu", "co", "ind", "adv", "eng", "med", "art", "ac"}
MIN_KEYWORD_LEN = 4


def brand_keyword(domain: str) -> str:
    """empresa.com.br -> empresa; sub.empresa.com -> empresa."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in _SECOND_LEVEL:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


def search_term(domain: str) -> str:
    """Termo de busca: o nome da marca, ou o domínio inteiro se o nome for curto demais."""
    keyword = brand_keyword(domain)
    return keyword if len(keyword) >= MIN_KEYWORD_LEN else domain.lower()


def victim_match(domain: str, *texts: str) -> tuple[str, str] | None:
    """Classifica a correspondência de uma vítima publicada com o domínio do cliente.

    Devolve (gravidade, explicação) ou None se não corresponde.
    """
    domain = domain.lower()
    haystack = " ".join(t for t in texts if t).lower()
    if domain in haystack:
        return "critica", "Correspondência forte (domínio completo)"
    keyword = search_term(domain)
    if keyword in haystack:
        return "media", "Possível correspondência (somente o nome) — validar manualmente"
    return None


def first_value(record: dict, *keys) -> str:
    """Primeiro campo preenchido; as APIs mudam nomes de campos entre versões."""
    for k in keys:
        val = record.get(k)
        if val:
            return str(val)
    return ""


def mask_secret(secret: str) -> str:
    """Mantém só os 2 primeiros caracteres: suficiente para o cliente reconhecer a senha,
    inútil para quem tentar usá-la."""
    secret = str(secret).strip()
    if secret.startswith("-----BEGIN"):
        return secret
    return (secret[:2] + "*" * min(max(len(secret) - 2, 4), 12)) if secret else ""


def ensure_masked(value: str) -> str:
    """Valores que a fonte já entrega mascarados (com *) passam; os demais são mascarados aqui."""
    value = str(value).strip()
    return value if "*" in value else mask_secret(value)
