import re
import secrets
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import BackgroundTasks, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import db as dbmod
from .collectors import COLLECTOR_CLASSES
from .config import settings
from .models import (CATEGORY_LABELS, SEVERITIES, SEVERITY_LABELS, Client, Domain, MonitoredEmail, ScanRun,
                     Supplier)
from .collectors import make_http_client
from .pwned import PwnedCheckError, pwned_count
from .reports import build_report, public_text
from .scanner import run_scan

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
DEFAULT_LOGO = STATIC_DIR / "img" / "logo-uxguard-preto.png"          # para fundo claro
DEFAULT_LOGO_WHITE = STATIC_DIR / "img" / "logo-uxguard-branco.png"   # para fundo escuro
# Nomes usados por versões anteriores do site: apontam para a logo atual
LEGACY_LOGOS = {"img/logo-uxguard.png", "img/logo-uxguard.svg"}
LOGO_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".svg": "image/svg+xml",
              ".webp": "image/webp", ".gif": "image/gif"}


def resolve_logo(value: str, default: Path = DEFAULT_LOGO, setting: str = "COMPANY_LOGO") -> tuple[Path, str]:
    """Encontra o arquivo de logo configurado no .env.

    Aceita caminho relativo a app/static (com / ou \\, com ou sem "static/" no início)
    ou caminho completo do Windows/Linux. Se não achar, usa a logo padrão e devolve
    um aviso para o painel.
    """
    raw = (value or "").strip().strip('"').strip("'")
    if not raw:
        return default, ""
    rel = raw.replace("\\", "/")
    for prefix in ("app/static/", "static/", "/static/"):
        rel = rel.removeprefix(prefix)
    if rel in LEGACY_LOGOS:
        return default, ""
    candidates = [Path(raw), STATIC_DIR / rel]
    for path in candidates:
        try:
            if path.is_file() and path.suffix.lower() in LOGO_TYPES:
                return path, ""
        except OSError:
            continue
    return default, (f"A logo configurada em {setting} ({raw}) não foi encontrada ou não é uma imagem "
                     f"(.png, .jpg, .svg, .webp). Usando a logo padrão.")


def logo_for(background: str) -> tuple[Path, bool]:
    """Arquivo de logo para o fundo ("claro" ou "escuro") e se precisa ser clareado por CSS.

    Fundo escuro usa COMPANY_LOGO_BRANCA. Se só a logo preta for personalizada, ela é
    usada também no fundo escuro, clareada pelo navegador.
    """
    dark_path, _ = resolve_logo(settings.company_logo)
    if background != "escuro":
        return dark_path, False
    if settings.company_logo_white.strip():
        return resolve_logo(settings.company_logo_white, DEFAULT_LOGO_WHITE, "COMPANY_LOGO_BRANCA")[0], False
    if dark_path == DEFAULT_LOGO:
        return DEFAULT_LOGO_WHITE, False
    return dark_path, True


def logo_warnings() -> list[str]:
    warnings = [resolve_logo(settings.company_logo)[1]]
    if settings.company_logo_white.strip():
        warnings.append(resolve_logo(settings.company_logo_white, DEFAULT_LOGO_WHITE, "COMPANY_LOGO_BRANCA")[1])
    return [w for w in warnings if w]
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,63}$")

security = HTTPBasic(auto_error=False)


def require_auth(credentials: HTTPBasicCredentials | None = Depends(security)):
    if not settings.app_password:
        return
    ok = credentials is not None and secrets.compare_digest(
        credentials.username.encode(), settings.app_user.encode()
    ) and secrets.compare_digest(credentials.password.encode(), settings.app_password.encode())
    if not ok:
        raise HTTPException(status_code=401, detail="Acesso negado",
                            headers={"WWW-Authenticate": 'Basic realm="DeepWebMonitor"'})


def get_db():
    db = dbmod.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app):
    dbmod.init_db()
    # Varreduras interrompidas (site fechado no meio) não devem travar novas varreduras.
    with dbmod.SessionLocal() as db:
        for s in db.scalars(select(ScanRun).where(ScanRun.status == "executando")):
            s.status = "interrompida"
        db.commit()
    yield


app = FastAPI(title="DeepWebMonitor", lifespan=lifespan, dependencies=[Depends(require_auth)])
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
templates = Jinja2Templates(directory=APP_DIR / "templates")
templates.env.globals.update(
    settings=settings, SEVERITY_LABELS=SEVERITY_LABELS, CATEGORY_LABELS=CATEGORY_LABELS,
)


def fmt_dt(value):
    return value.strftime("%d/%m/%Y %H:%M") + " UTC" if value else "—"


templates.env.filters["dt"] = fmt_dt
# Relatório do cliente: textos sem nomes das ferramentas de coleta
templates.env.filters["publico"] = public_text
# A logo precisa ser clareada por CSS no fundo escuro? (só quando não há versão branca)
templates.env.globals["logo_needs_filter"] = lambda: logo_for("escuro")[1]
# Links vêm de fontes externas: só exibe http(s), nunca "javascript:" etc.
templates.env.filters["is_http"] = lambda u: bool(u) and u.lower().startswith(("https://", "http://"))


def redirect(url: str, msg: str = "") -> RedirectResponse:
    if msg:
        url += ("&" if "?" in url else "?") + "msg=" + quote(msg)
    return RedirectResponse(url, status_code=303)


def get_client(db: Session, client_id: int) -> Client:
    client = db.get(Client, client_id)
    if not client:
        raise HTTPException(404, "Cliente não encontrado")
    return client


def normalize_domain(value: str) -> str:
    d = value.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0]
    return d.removeprefix("www.")


def collectors_status():
    out = []
    for cls in COLLECTOR_CLASSES:
        c = cls(http=None)
        out.append({"name": c.name, "label": c.label, "description": c.description, "slow": c.slow,
                    "enabled": c.enabled(), "reason": c.disabled_reason(), "note": c.status_note()})
    return out


def selected_sources(client: Client) -> set[str]:
    """Fontes marcadas para o cliente: a última escolha, ou todas na primeira vez."""
    names = {c.name for c in COLLECTOR_CLASSES}
    chosen = {s for s in (client.scan_sources or "").split(",") if s in names}
    return chosen or names


@app.get("/", response_class=HTMLResponse)
def index(request: Request, msg: str = "", db: Session = Depends(get_db)):
    clients = db.scalars(select(Client).order_by(Client.name)).all()
    rows = []
    for c in clients:
        sev = Counter(f.severity for f in c.findings)
        rows.append({"client": c, "sev": sev, "total": len(c.findings),
                     "last_scan": c.scans[0] if c.scans else None})
    return templates.TemplateResponse(request, "index.html", {
        "rows": rows, "msg": msg, "collectors": collectors_status(), "severities": SEVERITIES,
        "logo_warnings": logo_warnings(),
    })


@app.post("/clients")
def create_client(name: str = Form(...), notes: str = Form(""), db: Session = Depends(get_db)):
    name = name.strip()
    if not name:
        return redirect("/", "Informe o nome do cliente.")
    client = Client(name=name, notes=notes.strip())
    db.add(client)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return redirect("/", "Já existe um cliente com esse nome.")
    return redirect(f"/clients/{client.id}", "Cliente criado. Cadastre os domínios e e-mails.")


@app.get("/clients/{client_id}", response_class=HTMLResponse)
def client_detail(request: Request, client_id: int, msg: str = "", db: Session = Depends(get_db)):
    client = get_client(db, client_id)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings = sorted(client.findings, key=lambda f: (order.get(f.severity, 9), -f.first_seen.timestamp()))
    running = any(s.status == "executando" for s in client.scans)
    return templates.TemplateResponse(request, "client.html", {
        "client": client, "findings": findings, "msg": msg, "running": running,
        "scans": client.scans[:10], "sources": collectors_status(), "selected": selected_sources(client),
        # Crescente = da menos grave para a mais grave
        "severity_rank": {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)},
    })


@app.post("/clients/{client_id}/delete")
def delete_client(client_id: int, db: Session = Depends(get_db)):
    db.delete(get_client(db, client_id))
    db.commit()
    return redirect("/", "Cliente excluído.")


@app.post("/clients/{client_id}/domains")
def add_domain(client_id: int, name: str = Form(...), db: Session = Depends(get_db)):
    client = get_client(db, client_id)
    domain = normalize_domain(name)
    if not DOMAIN_RE.match(domain):
        return redirect(f"/clients/{client_id}", f"Domínio inválido: {name}")
    db.add(Domain(client_id=client.id, name=domain))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return redirect(f"/clients/{client_id}", "Domínio já cadastrado.")
    return redirect(f"/clients/{client_id}")


@app.post("/clients/{client_id}/domains/{domain_id}/delete")
def delete_domain(client_id: int, domain_id: int, db: Session = Depends(get_db)):
    d = db.get(Domain, domain_id)
    if d and d.client_id == client_id:
        db.delete(d)
        db.commit()
    return redirect(f"/clients/{client_id}")


@app.post("/clients/{client_id}/emails")
def add_emails(client_id: int, addresses: str = Form(...), db: Session = Depends(get_db)):
    client = get_client(db, client_id)
    known = {e.address for e in client.emails}
    invalid, added = [], 0
    for raw in re.split(r"[\s,;]+", addresses):
        addr = raw.strip().lower()
        if not addr:
            continue
        if not EMAIL_RE.match(addr):
            invalid.append(raw)
            continue
        if addr not in known:
            db.add(MonitoredEmail(client_id=client.id, address=addr))
            known.add(addr)
            added += 1
    db.commit()
    msg = f"{added} e-mail(s) adicionado(s)."
    if invalid:
        msg += " Inválidos: " + ", ".join(invalid[:5])
    return redirect(f"/clients/{client_id}", msg)


@app.post("/clients/{client_id}/suppliers")
def add_supplier(client_id: int, name: str = Form(...), domain: str = Form(""), db: Session = Depends(get_db)):
    client = get_client(db, client_id)
    name = name.strip()
    dom = normalize_domain(domain) if domain.strip() else ""
    if not name:
        return redirect(f"/clients/{client_id}", "Informe o nome do fornecedor ou parceiro.")
    if dom and not DOMAIN_RE.match(dom):
        return redirect(f"/clients/{client_id}", f"Domínio inválido: {domain}")
    if any(s.name.lower() == name.lower() for s in client.suppliers):
        return redirect(f"/clients/{client_id}", "Fornecedor já cadastrado.")
    db.add(Supplier(client_id=client.id, name=name, domain=dom))
    db.commit()
    return redirect(f"/clients/{client_id}")


@app.post("/clients/{client_id}/suppliers/{supplier_id}/delete")
def delete_supplier(client_id: int, supplier_id: int, db: Session = Depends(get_db)):
    s = db.get(Supplier, supplier_id)
    if s and s.client_id == client_id:
        db.delete(s)
        db.commit()
    return redirect(f"/clients/{client_id}")


@app.post("/clients/{client_id}/emails/{email_id}/delete")
def delete_email(client_id: int, email_id: int, db: Session = Depends(get_db)):
    e = db.get(MonitoredEmail, email_id)
    if e and e.client_id == client_id:
        db.delete(e)
        db.commit()
    return redirect(f"/clients/{client_id}")


def _scan_in_background(client_id: int, scan_id: int, only: set[str] | None = None):
    db = dbmod.SessionLocal()
    try:
        run_scan(db, client_id, scan_id, only=only)
    finally:
        db.close()


@app.post("/clients/{client_id}/scan")
def start_scan(client_id: int, background: BackgroundTasks, fontes: list[str] = Form(default=[]),
               db: Session = Depends(get_db)):
    client = get_client(db, client_id)
    available = {c["name"] for c in collectors_status() if c["enabled"]}
    chosen = {f for f in fontes if f in available}
    if not chosen:
        return redirect(f"/clients/{client_id}", "Selecione ao menos uma fonte para a varredura.")
    if not client.domains and not client.emails and not client.suppliers:
        return redirect(f"/clients/{client_id}", "Cadastre ao menos um domínio ou e-mail antes de varrer.")
    if any(s.status == "executando" for s in client.scans):
        return redirect(f"/clients/{client_id}", "Já existe uma varredura em andamento.")
    client.scan_sources = ",".join(sorted(chosen))
    scan = ScanRun(client_id=client.id)
    db.add(scan)
    db.commit()
    background.add_task(_scan_in_background, client.id, scan.id, chosen)
    return redirect(f"/clients/{client_id}",
                    f"Varredura iniciada com {len(chosen)} fonte(s). A página se atualiza sozinha.")


@app.get("/clients/{client_id}/report", response_class=HTMLResponse)
def report(request: Request, client_id: int, dias: int = 30, tema: str = "", db: Session = Depends(get_db)):
    client = get_client(db, client_id)
    ctx = build_report(client, max(1, min(dias, 3650)))
    ctx["light"] = tema == "claro"
    return templates.TemplateResponse(request, "report.html", ctx)


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/senhas", response_class=HTMLResponse)
def senhas_form(request: Request):
    return _no_store(templates.TemplateResponse(request, "senhas.html", {"count": None, "error": ""}))


@app.post("/senhas", response_class=HTMLResponse)
def senhas_check(request: Request, senha: str = Form(...)):
    count, error = None, ""
    try:
        with make_http_client() as http:
            count = pwned_count(http, senha)
    except PwnedCheckError as exc:
        error = str(exc)
    finally:
        del senha
    return _no_store(templates.TemplateResponse(request, "senhas.html", {"count": count, "error": error}))


@app.get("/marca/logo")
def logo(fundo: str = "claro"):
    path, _ = logo_for(fundo)
    if not path.is_file():  # nem a logo padrão existe (instalação incompleta): mostra o nome em texto
        from html import escape
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="360" height="80"><text x="0" y="56" '
               f'font-family="Poppins,Arial,sans-serif" font-size="48" font-weight="700" '
               f'fill="{"#fff" if fundo == "escuro" else "#000"}">'
               f'{escape(settings.company_name)}</text></svg>')
        return Response(svg, media_type="image/svg+xml")
    return FileResponse(path, media_type=LOGO_TYPES.get(path.suffix.lower(), "image/png"),
                        headers={"Cache-Control": "max-age=300"})


@app.get("/health")
def health():
    return {"status": "ok"}
