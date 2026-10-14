"""Executa as fontes para um cliente e grava os achados sem duplicar."""

import threading

from sqlalchemy import select
from sqlalchemy.orm import Session

from .collectors import COLLECTOR_CLASSES, Collector, CollectorError, FindingData, build_collectors, make_http_client
from .models import SEVERITIES, Client, Finding, ScanRun, utcnow

SOURCE_LABELS = {cls.name: cls.label for cls in COLLECTOR_CLASSES}

# Uma varredura por vez: algumas fontes têm limite de requisições e o dnstwist
# não é seguro para rodar em paralelo.
_scan_lock = threading.Lock()


def save_findings(db: Session, client: Client, items: list[FindingData]) -> int:
    """Insere achados novos e atualiza `last_seen` dos já conhecidos. Devolve quantos são novos."""
    if not items:
        return 0
    now = utcnow()
    current = list(db.scalars(select(Finding).where(Finding.client_id == client.id)))
    existing = {f.fingerprint: f for f in current}
    by_merge = {f.merge_key: f for f in current if f.merge_key}
    new = 0
    for item in items:
        found = existing.get(item.fingerprint)
        if found:
            found.last_seen = now
            if item.merge_key and not found.merge_key:
                found.merge_key = item.merge_key
                by_merge.setdefault(item.merge_key, found)
            continue
        same = by_merge.get(item.merge_key) if item.merge_key else None
        if same:  # o mesmo vazamento já veio de outra fonte: só registra a confirmação
            _confirm(same, item, now)
            existing[item.fingerprint] = same
            continue
        f = Finding(client_id=client.id, first_seen=now, last_seen=now, **item.__dict__)
        db.add(f)
        existing[item.fingerprint] = f
        if item.merge_key:
            by_merge[item.merge_key] = f
        new += 1
    return new


def _confirm(finding: Finding, item: FindingData, now) -> None:
    finding.last_seen = now
    if item.source != finding.source:
        label = SOURCE_LABELS.get(item.source, item.source)
        if "Confirmado também por: " not in finding.detail:
            finding.detail = f"{finding.detail} Confirmado também por: {label}."
        elif label not in finding.detail:
            finding.detail = finding.detail.rstrip(".") + f", {label}."
    order = {s: i for i, s in enumerate(SEVERITIES)}
    if order.get(item.severity, 9) < order.get(finding.severity, 9):  # fica com a gravidade maior
        finding.severity = item.severity


def run_scan(db: Session, client_id: int, scan_id: int,
             collectors: list[Collector] | None = None, only: set[str] | None = None) -> ScanRun:
    """Executa as fontes; `only` limita aos nomes escolhidos (None = todas)."""
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
            http = make_http_client()
            collectors = build_collectors(http)
        try:
            client_domains = {d.name.lower() for d in client.domains}
            if only is not None:
                collectors = [c for c in collectors if c.name in only]
                write_log("Fontes escolhidas: " + ", ".join(c.label for c in collectors))
            for c in collectors:
                c.client_domains = client_domains
                if not c.enabled():
                    write_log(f"[{c.label}] ignorado: {c.disabled_reason()}")
                    continue
                targets = []
                if c.supports("domain"):
                    targets += [("domínio", d.name, c.collect_domain) for d in client.domains]
                if c.supports("email"):
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
                    result = f"{len(items)} achado(s), {new} novo(s)" if items else "nenhum achado"
                    write_log(f"[{c.label}] {kind} {value}: {result}{status}")
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
