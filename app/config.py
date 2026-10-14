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
    company_name: str = os.getenv("COMPANY_NAME", "SOC")
    company_logo: str = os.getenv("COMPANY_LOGO", "")
    hibp_api_key: str = os.getenv("HIBP_API_KEY", "")
    hibp_user_agent: str = os.getenv("HIBP_USER_AGENT", "DeepWebMonitor-SOC")
    dnstwist_enabled: bool = _bool(os.getenv("DNSTWIST_ENABLED"), True)
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///data/deepwebmonitor.db")
    http_timeout: float = float(os.getenv("HTTP_TIMEOUT", "30"))


settings = Settings()
