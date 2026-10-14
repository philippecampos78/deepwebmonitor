"""Executa as fontes para um cliente e grava os achados sem duplicar."""

import threading

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .collectors import Collector, CollectorError, FindingData, build_collectors
from .config import settings
from .models import Client, Finding, ScanRun, utcnow

# Uma varredura por vez: algumas fontes têm limite de requisições e o dnstwist
# não é seguro para rodar em paralelo.
_scan_lock = threading.Lock()


def save_findings(db: Session, client: Client, items: list[FindingData]) -> int:
    """Insere achados novos e atualiza `last_seen` dos já conhecidos. Devolve quantos são novos."""
    if not items:
        return 0
    now = utcnow()
    existing = {
        f.fingerprint: f
        for f in db.scalars(select(Finding).where(Finding.client_id == client.id))
    }
    new = 0
    for item in items:
        found = existing.get(item.fingerprint)
        if found:
            found.last_seen = now
            continue
        f = Finding(client_id=client.id, first_seen=now, last_seen=now, **item.__dict__)
        db.add(f)
        existing[item.fingerprint] = f
        new += 1
    return new


def run_scan(db: Session, client_id: int, scan_id: int,
             collectors: list[Collector] | None = None) -> ScanRun:
    scan = db.get(ScanRun, scan_id)
    client = db.get(Client, client_id)
    log: list[str] = []

    def write_log(msg: str):
        log.append(msg)
        scan.log = "\n".join(log)
        db.commit()

    with _scan_lock:
        http = None
        if collectors is None:
            http = httpx.Client(timeout=settings.http_timeout, follow_redirects=True)
            collectors = build_collectors(http)
        try:
            for c in collectors:
                if not c.enabled():
                    write_log(f"[{c.label}] ignorado: {c.disabled_reason()}")
                    continue
                targets = [("domínio", d.name, c.collect_domain) for d in client.domains]
                targets += [("e-mail", e.address, c.collect_email) for e in client.emails]
                for kind, value, fn in targets:
                    try:
                        items = fn(value)
                        status = ""
                    except CollectorError as exc:
                        items, status = exc.findings, f" — aviso: {exc}"
                    except Exception as exc:  # uma fonte com problema não derruba as outras
                        items, status = [], f" — erro inesperado: {exc.__class__.__name__}: {exc}"
                    new = save_findings(db, client, items)
                    scan.new_findings += new
                    if items or status:
                        write_log(f"[{c.label}] {kind} {value}: {len(items)} achado(s), {new} novo(s){status}")
            scan.status = "concluida"
        except Exception as exc:
            scan.status = "falhou"
            log.append(f"Falha geral: {exc.__class__.__name__}: {exc}")
            scan.log = "\n".join(log)
        finally:
            if http:
                http.close()
            if not log:
                scan.log = "Nenhum achado nas fontes consultadas."
            scan.finished_at = utcnow()
            db.commit()
    return scan
