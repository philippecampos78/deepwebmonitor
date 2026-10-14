import httpx

from ..config import settings
from .abusech import AbuseChCollector
from .ahmia import AhmiaCollector
from .base import Collector, CollectorError, FindingData
from .crtsh import CrtShCollector
from .github_code import GitHubCodeCollector
from .hibp import HIBPCollector
from .hudsonrock import HudsonRockCollector
from .lookalike import LookalikeCollector
from .otx import OTXCollector
from .ransomlook import RansomLookCollector
from .ransomware_live import RansomwareLiveCollector

COLLECTOR_CLASSES = [
    HIBPCollector,
    RansomwareLiveCollector,
    RansomLookCollector,
    HudsonRockCollector,
    AhmiaCollector,
    GitHubCodeCollector,
    AbuseChCollector,
    OTXCollector,
    CrtShCollector,
    LookalikeCollector,
]


def make_http_client() -> httpx.Client:
    # Algumas fontes (ex.: Ahmia) recusam a identificação padrão "python-httpx".
    return httpx.Client(timeout=settings.http_timeout, follow_redirects=True,
                        headers={"User-Agent": settings.hibp_user_agent})


def build_collectors(http: httpx.Client) -> list[Collector]:
    return [cls(http) for cls in COLLECTOR_CLASSES]


__all__ = ["Collector", "CollectorError", "FindingData", "build_collectors", "make_http_client",
           "COLLECTOR_CLASSES"]
