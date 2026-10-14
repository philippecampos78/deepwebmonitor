import os

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["APP_PASSWORD"] = ""
os.environ["HIBP_API_KEY"] = ""

import httpx  # noqa: E402
import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app import db as dbmod  # noqa: E402
from app.collectors.base import Collector  # noqa: E402
from app.collectors.hibp import HIBPCollector  # noqa: E402
from app.collectors.hudsonrock import HudsonRockCollector  # noqa: E402
from app.collectors.lookalike import LookalikeCollector  # noqa: E402
from app.collectors.ransomware_live import RansomwareLiveCollector, brand_keyword  # noqa: E402
from app.models import Client, Domain, MonitoredEmail, ScanRun  # noqa: E402
from app.reports import build_report  # noqa: E402
from app.scanner import run_scan  # noqa: E402

BREACHES = [
    {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
     "PwnCount": 152445165, "DataClasses": ["Email addresses", "Passwords"], "IsSpamList": False},
    {"Name": "Spam1", "Title": "Spam List", "Domain": "", "BreachDate": "2020-01-01",
     "PwnCount": 10, "DataClasses": ["Email addresses"], "IsSpamList": True},
]


def http_for(routes: dict):
    def handler(request: httpx.Request):
        for prefix, (status, body) in routes.items():
            if str(request.url).startswith(prefix):
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={})
    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    dbmod.init_db(engine)
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    yield s
    s.close()


def test_brand_keyword():
    assert brand_keyword("empresa.com.br") == "empresa"
    assert brand_keyword("sub.empresa.com") == "empresa"
    assert brand_keyword("empresa.co.uk") == "empresa"


def test_hibp_free_catalog_finds_own_breach():
    c = HIBPCollector(http_for({"https://haveibeenpwned.com/api/v3/breaches": (200, BREACHES)}), api_key="")
    found = c.collect_domain("adobe.com")
    assert len(found) == 1
    assert found[0].category == "incidente_proprio"
    assert found[0].severity == "critica"
    assert "152.445.165 contas" in found[0].detail
    assert "e-mails, senhas" in found[0].detail
    assert c.collect_email("x@adobe.com") == []  # sem chave, não consulta e-mails


def test_hibp_domain_search_with_key():
    c = HIBPCollector(http_for({
        "https://haveibeenpwned.com/api/v3/breaches": (200, BREACHES),
        "https://haveibeenpwned.com/api/v3/subscribeddomains": (200, [{"DomainName": "empresa.com.br"}]),
        "https://haveibeenpwned.com/api/v3/breacheddomain/empresa.com.br": (200, {"joao": ["Adobe", "Spam1"]}),
    }), api_key="k")
    found = c.collect_domain("empresa.com.br")
    assert {f.asset for f in found} == {"joao@empresa.com.br"}
    assert sorted(f.severity for f in found) == ["alta", "baixa"]


def test_hibp_unverified_domain_reports_warning():
    from app.collectors.base import CollectorError

    c = HIBPCollector(http_for({
        "https://haveibeenpwned.com/api/v3/breaches": (200, BREACHES),
        "https://haveibeenpwned.com/api/v3/subscribeddomains": (200, []),
    }), api_key="k")
    with pytest.raises(CollectorError, match="não está verificado"):
        c.collect_domain("empresa.com.br")


def test_ransomware_live_match_strength():
    c = RansomwareLiveCollector(http_for({"https://api.ransomware.live/v2/searchvictims/empresa": (200, [
        {"victim": "empresa.com.br", "group": "lockbit3", "attackdate": "2026-09-01 10:00:00",
         "url": "http://abc.onion/post"},
        {"victim": "Empresa Logistics Inc", "group": "akira", "discovered": "2026-08-01"},
        {"victim": "Outra Coisa", "group": "play"},
    ])}))
    found = c.collect_domain("empresa.com.br")
    assert [f.severity for f in found] == ["critica", "media"]
    assert found[0].event_date == "2026-09-01"


def test_hudsonrock_domain_and_email():
    c = HudsonRockCollector(http_for({
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain": (200, {
            "employees": 2, "users": 0, "third_parties": 5,
            "last_employee_compromised": "2026-07-10T00:00:00.000Z",
            "data": {"employees_urls": [{"url": "https://vpn.empresa.com.br", "occurrence": 2}]},
            "stealerFamilies": {"total": 7, "RedLine": 4, "Lumma": 3},
        }),
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email": (200, {
            "stealers": [{"date_compromised": "2026-01-02T00:00:00.000Z", "stealer_family": "Lumma",
                          "computer_name": "PC-01", "top_passwords": ["ab*****", "SenhaSemMascara1"],
                          "top_logins": ["j***@empresa.com.br"]}],
        }),
    }))
    dom = c.collect_domain("empresa.com.br")
    assert [f.severity for f in dom] == ["critica", "baixa"]
    assert "vpn.empresa.com.br" in dom[0].detail and "RedLine (4)" in dom[0].detail
    em = c.collect_email("ceo@empresa.com.br")
    assert len(em) == 1 and "Lumma" in em[0].detail
    assert "ab*****" in em[0].detail and "j***@empresa.com.br" in em[0].detail
    assert "SenhaSemMascara1" not in em[0].detail and "Se**" in em[0].detail  # nunca grava senha completa


def test_lookalike():
    fake = lambda d: [  # noqa: E731
        {"fuzzer": "*original", "domain": d, "dns_a": ["1.1.1.1"]},
        {"fuzzer": "omission", "domain": "empesa.com.br", "dns_a": ["2.2.2.2"], "dns_mx": ["mx.evil"]},
        {"fuzzer": "tld-swap", "domain": "empresa.net", "dns_ns": ["ns1.x"]},
    ]
    found = LookalikeCollector(None, run=fake, enabled=True).collect_domain("empresa.com.br")
    assert [(f.title.split(": ")[1], f.severity) for f in found] == [("empesa.com.br", "alta"), ("empresa.net", "media")]


class FakeCollector(Collector):
    name, label = "fake", "Fake"

    def __init__(self):
        super().__init__(None)
        self.calls = 0

    def enabled(self):
        return True

    def collect_domain(self, domain):
        from app.collectors.base import FindingData
        self.calls += 1
        return [FindingData(source="fake", category="vazamento", severity="alta", asset=domain,
                            title=f"t{i}", fingerprint=f"fp{i}") for i in range(self.calls + 1)]

    def collect_email(self, email):
        raise RuntimeError("fonte fora do ar")


def test_scan_dedupes_and_survives_errors(session):
    client = Client(name="ACME", domains=[Domain(name="acme.com")], emails=[MonitoredEmail(address="a@acme.com")])
    session.add(client)
    session.commit()
    fake = FakeCollector()

    s1 = ScanRun(client_id=client.id)
    session.add(s1)
    session.commit()
    run_scan(session, client.id, s1.id, collectors=[fake])
    assert s1.status == "concluida" and s1.new_findings == 2
    assert "fonte fora do ar" in s1.log

    s2 = ScanRun(client_id=client.id)
    session.add(s2)
    session.commit()
    run_scan(session, client.id, s2.id, collectors=[fake])
    assert s2.new_findings == 1  # só fp2 é novo
    session.refresh(client)
    assert len(client.findings) == 3

    report = build_report(client, days=30)
    assert report["risk"] == "alta" and report["total"] == 3


def test_web_flow():
    from fastapi.testclient import TestClient

    from app.main import app

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    dbmod.SessionLocal.configure(bind=engine)
    dbmod.engine = engine
    with TestClient(app) as tc:
        dbmod.init_db(engine)
        r = tc.post("/clients", data={"name": "Cliente <b>X</b>"})
        assert r.status_code == 200 and "Cliente &lt;b&gt;X&lt;/b&gt;" in r.text
        cid = int(str(r.url).rstrip("/").split("/clients/")[1].split("?")[0])
        r = tc.post(f"/clients/{cid}/domains", data={"name": "https://www.Empresa.com.br/contato"})
        assert "empresa.com.br" in r.text
        r = tc.post(f"/clients/{cid}/domains", data={"name": "não é domínio"})
        assert "Domínio inválido" in r.text
        r = tc.post(f"/clients/{cid}/emails", data={"addresses": "ceo@empresa.com.br, ruim"})
        assert "ceo@empresa.com.br" in r.text and "Inválidos: ruim" in r.text
        r = tc.get(f"/clients/{cid}/report")
        assert r.status_code == 200 and "Resumo <span class=\"hl\">executivo</span>" in r.text
        assert "theme-light" in tc.get(f"/clients/{cid}/report?tema=claro").text
        assert tc.get("/").status_code == 200


def test_supports_only_implemented_kinds():
    from app.collectors.ransomware_live import RansomwareLiveCollector
    assert RansomwareLiveCollector(None).supports("domain")
    assert not RansomwareLiveCollector(None).supports("email")
    assert HudsonRockCollector(None).supports("email")
    assert not HIBPCollector(None, api_key="").supports("email")
    assert HIBPCollector(None, api_key="k").supports("email")


def test_scan_only_selected_sources(session):
    client = Client(name="Seleção", domains=[Domain(name="acme.com")])
    session.add(client)
    session.commit()
    a, b = FakeCollector(), FakeCollector()
    b.name, b.label = "outra", "Outra"
    scan = ScanRun(client_id=client.id)
    session.add(scan)
    session.commit()
    run_scan(session, client.id, scan.id, collectors=[a, b], only={"fake"})
    assert a.calls == 1 and b.calls == 0
    assert "Fontes escolhidas: Fake" in scan.log


def test_old_database_gets_new_column(tmp_path):
    from sqlalchemy import create_engine, inspect, text
    engine = create_engine(f"sqlite:///{tmp_path}/old.db")
    with engine.begin() as conn:  # tabela como era antes da escolha de fontes
        conn.execute(text("CREATE TABLE clients (id INTEGER PRIMARY KEY, name VARCHAR(200) UNIQUE, notes TEXT, created_at DATETIME)"))
        conn.execute(text("INSERT INTO clients (name, notes) VALUES ('Cliente antigo', '')"))
    dbmod.init_db(engine)
    assert "scan_sources" in {c["name"] for c in inspect(engine).get_columns("clients")}
    with engine.connect() as conn:
        assert conn.execute(text("SELECT name, scan_sources FROM clients")).one() == ("Cliente antigo", "")
    dbmod.init_db(engine)  # rodar de novo não dá erro


def test_web_source_picker(monkeypatch):
    from fastapi.testclient import TestClient

    import app.main as main

    started = []
    monkeypatch.setattr(main, "_scan_in_background", lambda cid, sid, only=None: started.append(only))
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    dbmod.SessionLocal.configure(bind=engine)
    dbmod.engine = engine
    with TestClient(main.app) as tc:
        dbmod.init_db(engine)
        r = tc.post("/clients", data={"name": "Picker"})
        cid = int(str(r.url).split("/clients/")[1].split("?")[0])
        tc.post(f"/clients/{cid}/domains", data={"name": "picker.com.br"})
        page = tc.get(f"/clients/{cid}").text
        assert 'value="ransomware_live" data-slow="0"\n               checked' in page  # 1ª vez: todas marcadas
        assert 'value="lookalike" data-slow="1"' in page
        r = tc.post(f"/clients/{cid}/scan", data={"fontes": []})
        assert "Selecione ao menos uma fonte" in r.text and not started
        r = tc.post(f"/clients/{cid}/scan", data={"fontes": ["ransomware_live", "hudsonrock", "inexistente"]})
        assert started == [{"ransomware_live", "hudsonrock"}] and "2 fonte(s)" in r.text
        page = tc.get(f"/clients/{cid}").text  # a escolha fica salva
        assert 'value="hudsonrock" data-slow="0"\n               checked' in page
        assert 'value="ahmia" data-slow="0"\n               checked' not in page


def test_logo_resolution(tmp_path):
    from app.main import DEFAULT_LOGO, resolve_logo
    custom = tmp_path / "minha-logo.PNG"
    custom.write_bytes(b"\x89PNG")
    assert resolve_logo("") == (DEFAULT_LOGO, "")
    assert resolve_logo("img/logo-uxguard.png")[0] == DEFAULT_LOGO
    assert resolve_logo("static\\img\\logo-uxguard.png")[0] == DEFAULT_LOGO  # barra invertida do Windows
    assert resolve_logo(f'"{custom}"') == (custom, "")  # caminho completo, com aspas
    path, warning = resolve_logo("logo.png")
    assert path == DEFAULT_LOGO and "não foi encontrada" in warning
    assert resolve_logo(str(tmp_path))[1]  # pasta não é imagem


def test_logo_route_serves_image():
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as tc:
        r = tc.get("/marca/logo")
        assert r.status_code == 200 and r.headers["content-type"] == "image/png" and r.content[:4] == b"\x89PNG"
        assert 'src="/marca/logo"' in tc.get("/").text
