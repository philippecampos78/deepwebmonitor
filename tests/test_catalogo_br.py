from datetime import date, timedelta

import httpx

from app.collectors.base import ClientInfo
from app.collectors.catalogo import CatalogoBRCollector
from app.models import Client, Domain, ScanRun, Supplier
from app.scanner import run_scan

RECENT = (date.today() - timedelta(days=10)).isoformat()
OLD = (date.today() - timedelta(days=800)).isoformat()


def catalog_api(results_by_query: dict, seen: list):
    def handler(request):
        seen.append((dict(request.url.params), request.headers.get("X-API-Key")))
        key = request.url.params.get("dominio") or request.url.params.get("nome")
        return httpx.Response(200, json={"resultados": results_by_query.get(key, [])})
    return httpx.Client(transport=httpx.MockTransport(handler))


def inc(i, tipo, match, when=RECENT, **kw):
    return {"id": i, "tipo": tipo, "tipo_descricao": {"ransomware": "Ransomware / extorsão",
            "vazamento": "Vazamento de dados", "noticia": "Notícia de incidente"}[tipo],
            "correspondencia": match, "titulo": f"titulo {i}", "data_divulgacao": when, "confianca": "alegado", **kw}


def test_client_and_suppliers():
    seen = []
    api = catalog_api({
        "empresa.com.br": [inc(1, "ransomware", "forte", organizacao="Empresa SA", grupo="akira")],
        "Empresa": [inc(1, "ransomware", "possivel"), inc(2, "noticia", "possivel")],
        "folha.com.br": [inc(3, "ransomware", "forte", dados_expostos="CPFs")],
        "Contabil XYZ": [inc(4, "vazamento", "forte", when=OLD)],
    }, seen)
    c = CatalogoBRCollector(api, url="http://cat:8001", api_key="k")
    found = c.collect_client(ClientInfo("Empresa", ["empresa.com.br"], [("Folha Pag", "folha.com.br"), ("Contabil XYZ", "")]))
    by = {f.fingerprint: f for f in found}
    assert len(found) == 4  # incidente 1 achado por nome e domínio vira um só
    assert by["catalogo:cliente:empresa:1"].severity == "critica" and by["catalogo:cliente:empresa:1"].category == "incidente_proprio"
    assert by["catalogo:cliente:empresa:2"].severity == "baixa" and "validar" in by["catalogo:cliente:empresa:2"].title
    folha = next(f for f in found if f.asset == "Folha Pag")
    assert folha.category == "terceiros" and folha.severity == "alta" and "Avaliar o impacto para Empresa" in folha.detail
    assert next(f for f in found if f.asset == "Contabil XYZ").severity == "baixa"  # vazamento antigo: rebaixado
    assert all(key == "k" for _, key in seen)


def test_disabled_and_offline():
    assert not CatalogoBRCollector(None, url="").enabled()

    def down(request):
        raise httpx.ConnectError("recusado")
    c = CatalogoBRCollector(httpx.Client(transport=httpx.MockTransport(down)), url="http://127.0.0.1:8001", api_key="")
    try:
        c.collect_client(ClientInfo("X", [], []))
        raise AssertionError("deveria falhar")
    except Exception as exc:
        assert "Catálogo de Vazamentos BR está aberto" in str(exc)


def test_scan_calls_client_level_collector(session):
    client = Client(name="Empresa", domains=[Domain(name="empresa.com.br")],
                    suppliers=[Supplier(name="Folha Pag", domain="folha.com.br")])
    session.add(client)
    session.commit()
    seen = []
    api = catalog_api({"folha.com.br": [inc(9, "ransomware", "forte")]}, seen)
    scan = ScanRun(client_id=client.id)
    session.add(scan)
    session.commit()
    run_scan(session, client.id, scan.id, collectors=[CatalogoBRCollector(api, url="http://cat", api_key="")])
    assert "cliente e fornecedores Empresa: 1 achado(s)" in scan.log
    session.refresh(client)
    assert [f.category for f in client.findings] == ["terceiros"]


def test_supplier_routes():
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool

    from app import db as dbmod
    from app.main import app
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    dbmod.SessionLocal.configure(bind=engine)
    dbmod.engine = engine
    with TestClient(app) as tc:
        dbmod.init_db(engine)
        r = tc.post("/clients", data={"name": "Cliente F"})
        cid = int(str(r.url).split("/clients/")[1].split("?")[0])
        r = tc.post(f"/clients/{cid}/suppliers", data={"name": "Folha Pag", "domain": "https://www.folha.com.br/x"})
        assert "Folha Pag" in r.text and "folha.com.br" in r.text
        assert "já cadastrado" in tc.post(f"/clients/{cid}/suppliers", data={"name": "folha pag"}).text
        assert "Domínio inválido" in tc.post(f"/clients/{cid}/suppliers", data={"name": "Y", "domain": "nao e dominio"}).text
