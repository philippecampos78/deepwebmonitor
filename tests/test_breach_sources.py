import httpx

from app.collectors.base import Collector, FindingData
from app.collectors.leakcheck import LeakCheckCollector
from app.collectors.matching import breach_key
from app.collectors.xposedornot import XposedOrNotCollector
from app.models import Client, MonitoredEmail, ScanRun
from app.scanner import run_scan


def http_for(routes: dict):
    def handler(request):
        for prefix, (status, body) in routes.items():
            if str(request.url).startswith(prefix):
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={})
    return httpx.Client(transport=httpx.MockTransport(handler))


XON = {"ExposedBreaches": {"breaches_details": [
    {"breach": "Adobe", "domain": "adobe.com", "xposed_date": "2013", "password_risk": "easytocrack",
     "xposed_data": "Email addresses;Passwords;Usernames"},
    {"breach": "Canva", "domain": "canva.com", "xposed_date": "2019", "password_risk": "hardtocrack",
     "xposed_data": "Email addresses;Names"},
]}}
LC = {"success": True, "found": 2, "fields": ["password", "ip2", "phone", "province"],
      "sources": [{"name": "Adobe.com", "date": "2013-10"}, {"name": "SiteX.net", "date": ""}]}


def test_breach_key_normalizes_names():
    assert breach_key("A@X.com", "Adobe") == breach_key("a@x.com", "adobe.com") == "vazamento:a@x.com:adobe"
    assert breach_key("a@x.com", "DCEmu.co.uk") == "vazamento:a@x.com:dcemu"


def test_xposedornot():
    found = XposedOrNotCollector(http_for({"https://api.xposedornot.com/v1/breach-analytics": (200, XON)}),
                                 min_interval=0).collect_email("Ceo@Empresa.com.br")
    assert [(f.severity, f.asset) for f in found] == [("alta", "ceo@empresa.com.br"), ("media", "ceo@empresa.com.br")]
    assert "e-mails, senhas, nomes de usuário" in found[0].detail and "fáceis de descobrir" in found[0].detail
    empty = {"ExposedBreaches": None}
    assert XposedOrNotCollector(http_for({"https://api.xposedornot.com/": (200, empty)}), min_interval=0).collect_email("x@y.com") == []


def test_leakcheck():
    c = LeakCheckCollector(http_for({"https://leakcheck.io/api/public": (200, LC)}), min_interval=0)
    found = c.collect_email("ceo@empresa.com.br")
    assert [f.severity for f in found] == ["media", "media"]
    assert "senha, telefone" in found[0].detail and "ip2" not in found[0].detail and "Verificar senha" in found[0].detail
    nf = LeakCheckCollector(http_for({"https://leakcheck.io/": (200, {"success": False, "error": "Not found"})}), min_interval=0)
    assert nf.collect_email("x@y.com") == []


class _Fixed(Collector):
    def __init__(self, name, items):
        super().__init__(None)
        self.name, self.label, self.items = name, name.upper(), items

    def collect_email(self, email):
        return self.items


def test_same_breach_from_two_sources_is_one_finding(session):
    client = Client(name="Merge", emails=[MonitoredEmail(address="ceo@empresa.com.br")])
    session.add(client)
    session.commit()
    a = _Fixed("hibp", [FindingData("hibp", "vazamento", "media", "ceo@empresa.com.br", "no Adobe", "h1",
                                    detail="Incidente: Adobe.", merge_key=breach_key("ceo@empresa.com.br", "Adobe"))])
    b = _Fixed("xposedornot", [FindingData("xposedornot", "vazamento", "alta", "ceo@empresa.com.br", "no Adobe", "x1",
                                           detail="X", merge_key=breach_key("ceo@empresa.com.br", "adobe.com")),
                               FindingData("xposedornot", "vazamento", "media", "ceo@empresa.com.br", "no Canva", "x2",
                                           merge_key=breach_key("ceo@empresa.com.br", "Canva"))])
    for _ in range(2):  # a segunda varredura não duplica nada
        scan = ScanRun(client_id=client.id)
        session.add(scan)
        session.commit()
        run_scan(session, client.id, scan.id, collectors=[a, b])
    session.refresh(client)
    adobe = [f for f in client.findings if "Adobe" in f.title]
    assert len(client.findings) == 2 and len(adobe) == 1
    assert adobe[0].severity == "alta"  # fica com a maior gravidade
    assert adobe[0].detail.count("Confirmado também por: XposedOrNot.") == 1


def test_hudson_checks_emails_discovered_by_other_sources(session):
    from app.collectors.hudsonrock import HudsonRockCollector

    client = Client(name="Descoberta", emails=[MonitoredEmail(address="ceo@empresa.com.br")])
    from app.models import Domain
    client.domains = [Domain(name="empresa.com.br")]
    session.add(client)
    session.commit()
    # 1ª fonte: a busca por domínio revela e-mails que não estavam cadastrados
    class DomainLeak(Collector):
        name, label = "hibp", "HIBP"

        def collect_domain(self, domain):
            return [
                FindingData("hibp", "vazamento", "media", "joao@empresa.com.br", "joao no Canva", "l1"),
                FindingData("hibp", "vazamento", "media", "maria@filial.empresa.com.br", "maria no Adobe", "l2"),
                FindingData("hibp", "vazamento", "media", "fulano@gmail.com", "outro domínio", "l3"),
            ]
    leak = DomainLeak(None)
    asked = []

    def handler(request):
        asked.append(request.url.params.get("email") or request.url.params.get("domain"))
        if request.url.params.get("email") == "joao@empresa.com.br":
            return httpx.Response(200, json={"stealers": [{"date_compromised": "2026-10-01T00:00:00Z",
                                                           "top_logins": ["j***@empresa.com.br"],
                                                           "top_passwords": ["Se******"]}]})
        return httpx.Response(200, json={"stealers": []})
    hr = HudsonRockCollector(httpx.Client(transport=httpx.MockTransport(handler)), min_interval=0)
    scan = ScanRun(client_id=client.id)
    session.add(scan)
    session.commit()
    run_scan(session, client.id, scan.id, collectors=[leak, hr])
    assert set(asked) == {"empresa.com.br", "ceo@empresa.com.br", "joao@empresa.com.br", "maria@filial.empresa.com.br"}
    assert "verificando também 2 e-mail(s)" in scan.log
    session.refresh(client)
    joao = [f for f in client.findings if f.source == "hudsonrock" and f.asset == "joao@empresa.com.br"]
    assert len(joao) == 1 and "j***@empresa.com.br" in joao[0].detail and "Se******" in joao[0].detail
