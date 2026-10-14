import httpx
import pytest

from app.collectors.dnsquery import TYPES, _txt
from app.collectors.email_security import EmailSecurityCollector
from app.collectors.internetdb import KEV_URL, InternetDBCollector
from app.collectors.urlscan import UrlscanCollector
from app.collectors.virustotal import VirusTotalCollector


def fake_http(dns: dict, routes: dict | None = None, seen: list | None = None):
    """dns: {(nome, tipo): [valores]}; routes: {prefixo_url: (status, json)}"""
    def handler(request: httpx.Request):
        if seen is not None:
            seen.append(request)
        url = str(request.url)
        if url.startswith("https://cloudflare-dns.com/dns-query"):
            name, rtype = request.url.params["name"], request.url.params["type"]
            values = dns.get((name, rtype), [])
            data = [f'"{v}"' if rtype == "TXT" else (f"10 {v}." if rtype == "MX" else v) for v in values]
            return httpx.Response(200, json={"Status": 0 if values else 3,
                                             "Answer": [{"type": TYPES[rtype], "data": d} for d in data]})
        for prefix, (status, body) in (routes or {}).items():
            if url.startswith(prefix):
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_txt_chunks_are_joined():
    assert _txt('"v=spf1 include:a.com " "include:b.com -all"') == "v=spf1 include:a.com include:b.com -all"


def _email(dns):
    found = EmailSecurityCollector(fake_http(dns)).collect_domain("empresa.com.br")
    return {f.fingerprint.split(":")[-1]: f.severity for f in found}


def test_email_security_missing_everything():
    assert _email({}) == {"spf-ausente": "alta", "dmarc-ausente": "alta", "dkim-nao-encontrado": "info"}


def test_email_security_weak_and_good_configs():
    dkim = {("selector1._domainkey.empresa.com.br", "TXT"): ["v=DKIM1; k=rsa; p=MIIB"]}
    assert _email({("empresa.com.br", "TXT"): ["v=spf1 +all"], **dkim}) == {"spf-all": "critica", "dmarc-ausente": "alta"}
    assert _email({("empresa.com.br", "TXT"): ["v=spf1 include:_spf.google.com ?all"],
                   ("_dmarc.empresa.com.br", "TXT"): ["v=DMARC1; p=none"], **dkim}) == {
        "spf-neutro": "media", "dmarc-none": "media", "dmarc-sem-rua": "baixa"}
    assert _email({("empresa.com.br", "TXT"): ["google-site-verification=x", "v=spf1 include:spf.protection.outlook.com -all"],
                   ("_dmarc.empresa.com.br", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@empresa.com.br"], **dkim}) == {}
    # "all" dentro de outro nome não conta como política
    assert "spf-sem-all" in _email({("empresa.com.br", "TXT"): ["v=spf1 include:mailall.net"], **dkim})


def test_internetdb_risky_ports_kev_and_third_party_mx():
    dns = {("empresa.com.br", "A"): ["200.1.1.1"], ("www.empresa.com.br", "A"): ["200.1.1.1"],
           ("empresa.com.br", "MX"): ["mail.empresa.com.br", "aspmx.l.google.com"],
           ("mail.empresa.com.br", "A"): ["200.1.1.2"], ("aspmx.l.google.com", "A"): ["8.8.8.8"]}
    seen = []
    c = InternetDBCollector(fake_http(dns, {
        "https://internetdb.shodan.io/200.1.1.1": (200, {"ports": [80, 443, 3389], "vulns": ["CVE-2024-1", "CVE-2019-2"],
                                                          "cpes": ["cpe:/a:apache:http_server:2.4.7"], "tags": []}),
        "https://internetdb.shodan.io/200.1.1.2": (200, {"ports": [25, 587], "vulns": [], "tags": []}),
        KEV_URL: (200, {"vulnerabilities": [{"cveID": "CVE-2024-1", "vendorProject": "Apache", "product": "HTTP Server"}]}),
    }, seen))
    found = c.collect_domain("empresa.com.br")
    assert sorted(f.severity for f in found) == ["alta", "critica", "info"]
    assert "3389 RDP" in next(f.detail for f in found if f.severity == "alta")
    assert "CVE-2024-1 (Apache HTTP Server)" in next(f.detail for f in found if f.severity == "critica")
    assert not any("8.8.8.8" in str(r.url) for r in seen)  # MX de terceiros não é analisado


def test_internetdb_cdn_lowers_severity():
    dns = {("empresa.com.br", "A"): ["104.16.1.1"]}
    c = InternetDBCollector(fake_http(dns, {
        "https://internetdb.shodan.io/104.16.1.1": (200, {"ports": [80, 443], "vulns": ["CVE-2020-1"], "tags": ["cdn"]}),
        KEV_URL: (200, {"vulnerabilities": []})}))
    found = c.collect_domain("empresa.com.br")
    assert [f.severity for f in found] == ["media"] and "CDN" in found[0].detail


def test_virustotal(monkeypatch):
    sleeps = []
    monkeypatch.setattr("app.collectors.virustotal.time.sleep", sleeps.append)
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 60, "undetected": 30},
                                    "last_analysis_results": {"Fortinet": {"category": "malicious", "result": "phishing"},
                                                              "Kaspersky": {"category": "clean", "result": "clean"}},
                                    "last_analysis_date": 1790000000, "reputation": -5}}}
    seen = []
    c = VirusTotalCollector(fake_http({}, {"https://www.virustotal.com/api/v3/domains/": (200, body)}, seen), api_key="k")
    found = c.collect_domain("empresa.com.br")
    assert found[0].severity == "alta" and "Fortinet (phishing)" in found[0].detail
    assert seen[0].headers["x-apikey"] == "k"
    c.collect_domain("empresa.com.br")
    assert sleeps and sleeps[-1] > 10  # respeita 4 consultas/minuto
    body["data"]["attributes"]["last_analysis_stats"] = {"malicious": 0, "suspicious": 0}
    assert c.collect_domain("empresa.com.br") == []
    assert not VirusTotalCollector(None, api_key="").enabled()


def _scan(domain, task_tags=None, title="Login"):
    return {"_id": f"id-{domain}", "page": {"domain": domain, "url": f"https://{domain}/", "title": title},
            "task": {"time": "2026-10-10T00:00:00Z", "tags": task_tags or []}}


@pytest.mark.parametrize("key, expected_query", [("", "page.domain:empresa*"), ("k", "page.domain:*empresa*")])
def test_urlscan(key, expected_query):
    seen = []
    results = [_scan("empresa-login.com", ["phishing"]), _scan("loja.empresa.com.br"), _scan("empresa.cn"),
               _scan("parceiro.com")]
    c = UrlscanCollector(fake_http({}, {"https://urlscan.io/api/v1/search/": (200, {"results": results})}, seen),
                         api_key=key, days=30)
    c.client_domains = {"empresa.com.br", "empresa.cn"}
    found = {f.title.split(": ")[1]: f.severity for f in c.collect_domain("empresa.com.br")}
    assert found == {"empresa-login.com": "critica", "parceiro.com": "alta"}
    queries = [r.url.params["q"] for r in seen]
    assert any(expected_query in q for q in queries) and all("date:>now-30d" in q for q in queries)
