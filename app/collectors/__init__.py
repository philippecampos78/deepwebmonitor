import httpx

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


def build_collectors(http: httpx.Client) -> list[Collector]:
    return [cls(http) for cls in COLLECTOR_CLASSES]


__all__ = ["Collector", "CollectorError", "FindingData", "build_collectors", "COLLECTOR_CLASSES"]
