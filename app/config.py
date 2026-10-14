"""Configurações lidas do arquivo .env."""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "sim", "on")


@dataclass(frozen=True)
class Settings:
    app_user: str = os.getenv("APP_USER", "soc")
    app_password: str = os.getenv("APP_PASSWORD", "")
    company_name: str = os.getenv("COMPANY_NAME", "UXGUARD")
    company_logo: str = os.getenv("COMPANY_LOGO", "")              # versão para fundo claro
    company_logo_white: str = os.getenv("COMPANY_LOGO_BRANCA", "")  # versão para fundo escuro
    company_footer: str = os.getenv("COMPANY_FOOTER", "UXGUARD LTDA · CNPJ 57.270.568/0001-40")
    company_address: str = os.getenv(
        "COMPANY_ADDRESS", "Rua dos Guajajaras, 1570 · Sala 502 · Belo Horizonte/MG · CEP 30.180-099")
    hibp_api_key: str = os.getenv("HIBP_API_KEY", "")
    hibp_user_agent: str = os.getenv("HIBP_USER_AGENT", "DeepWebMonitor-SOC")
    dnstwist_enabled: bool = _bool(os.getenv("DNSTWIST_ENABLED"), True)
    github_token: str = os.getenv("GITHUB_TOKEN", "")
    gitleaks_path: str = os.getenv("GITLEAKS_PATH", "gitleaks")
    otx_api_key: str = os.getenv("OTX_API_KEY", "")
    abusech_auth_key: str = os.getenv("ABUSECH_AUTH_KEY", "")
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    urlscan_api_key: str = os.getenv("URLSCAN_API_KEY", "")
    urlscan_days: int = int(os.getenv("URLSCAN_DAYS", "90"))
    dns_mode: str = os.getenv("DNS_MODE", "doh").strip().lower()
    dns_doh_url: str = os.getenv("DNS_DOH_URL", "https://cloudflare-dns.com/dns-query")
    ransomlook_days: int = int(os.getenv("RANSOMLOOK_DAYS", "90"))
    crtsh_days: int = int(os.getenv("CRTSH_DAYS", "90"))
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///data/deepwebmonitor.db")
    http_timeout: float = float(os.getenv("HTTP_TIMEOUT", "30"))


settings = Settings()
