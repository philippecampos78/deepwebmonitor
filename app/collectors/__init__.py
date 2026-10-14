import httpx

from .base import Collector, CollectorError, FindingData
from .hibp import HIBPCollector
from .hudsonrock import HudsonRockCollector
from .lookalike import LookalikeCollector
from .ransomware_live import RansomwareLiveCollector

COLLECTOR_CLASSES = [HIBPCollector, RansomwareLiveCollector, HudsonRockCollector, LookalikeCollector]


def build_collectors(http: httpx.Client) -> list[Collector]:
    return [cls(http) for cls in COLLECTOR_CLASSES]


__all__ = ["Collector", "CollectorError", "FindingData", "build_collectors", "COLLECTOR_CLASSES"]
