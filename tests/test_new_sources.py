import base64
import json
import os
import stat
import sys
from datetime import timedelta

import httpx
import pytest

from app.collectors.abusech import AbuseChCollector
from app.collectors.ahmia import AhmiaCollector, parse_results
from app.collectors.base import CollectorError
from app.collectors.crtsh import CrtShCollector
from app.collectors.github_code import GitHubCodeCollector, builtin_scan, mask
from app.collectors.otx import OTXCollector
from app.collectors.ransomlook import RansomLookCollector
from app.models import utcnow


def http_for(routes: dict, seen: list | None = None):
    def handler(request: httpx.Request):
        if seen is not None:
            seen.append(request)
        for prefix, (status, body) in routes.items():
            if str(request.url).startswith(prefix):
                if isinstance(body, str):
                    return httpx.Response(status, text=body)
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_ransomlook_local_match():
    c = RansomLookCollector(http_for({"https://www.ransomlook.io/api/last/30": (200, [
        {"post_title": "Empresa S.A. - empresa.com.br", "group_name": "qilin", "discovered": "2026-10-01 08:00:00.000"},
        {"post_title": "Outra Empresa Ltd", "group_name": "play", "discovered": "2026-09-01"},
        {"post_title": "Sem relação", "group_name": "akira"},
    ])}), days=30)
    found = c.collect_domain("empresa.com.br")
    assert [f.severity for f in found] == ["critica", "media"]
    assert found[0].event_date == "2026-10-01"
    c.collect_domain("empresa.com.br")  # segunda chamada usa o cache


def test_crtsh_filters_own_domain_and_old_certs():
    recent = (utcnow() - timedelta(days=3)).isoformat()
    old = (utcnow() - timedelta(days=400)).isoformat()
    c = CrtShCollector(http_for({"https://crt.sh/": (200, [
        {"id": 1, "name_value": "www.empresa.com.br\nempresa.com.br", "not_before": recent},
        {"id": 2, "name_value": "empresa-login.com\n*.empresa-login.com", "not_before": recent, "issuer_name": "R3"},
        {"id": 3, "name_value": "minhaempresa.net", "not_before": recent},
        {"id": 4, "name_value": "empresa-antigo.com", "not_before": old},
    ])}), days=90)
    found = {f.title.split(": ")[1]: f.severity for f in c.collect_domain("empresa.com.br")}
    assert found == {"empresa-login.com": "alta", "minhaempresa.net": "media"}


AHMIA_HOME = '<form id="searchForm"><input type="text" name="q"><input type="hidden" name="a1b2" value="x9y8"></form>'
AHMIA_RESULTS = """
<ol class="searchResults">
<li class="result"><h4><a href="/search/redirect?x">Database dump &amp; leaks</a></h4>
  <p>Selling empresa.com.br customer database 2026</p>
  <cite>abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcd.onion</cite>
  <span class="lastSeen" data-timestamp="1790000000">1 day</span></li>
<li class="result"><h4><a href="#">Forum</a></h4><p>empresa generic text</p><cite>qrstuvwxyzqrstuv.onion</cite></li>
</ol>"""


def test_ahmia_parses_and_sends_hidden_token():
    seen = []
    c = AhmiaCollector(http_for({"https://ahmia.fi/search/": (200, AHMIA_RESULTS),
                                 "https://ahmia.fi/": (200, AHMIA_HOME)}, seen))
    found = c.collect_domain("empresa.com.br")
    assert len(parse_results(AHMIA_RESULTS)) == 2
    assert len(found) == 1 and found[0].severity == "alta"
    assert found[0].title == "Menção na dark web: Database dump & leaks"
    assert "a1b2=x9y8" in str(seen[-1].url)


def test_builtin_secret_rules_and_mask():
    text = 'db_url = "postgres://admin:S3cretPass@db.empresa.com.br/app"\npassword: "changeme"\nkey=AKIAABCDEFGHIJKLMNOP'
    rules = sorted(h["rule"] for h in builtin_scan(text))
    assert rules == ["aws-access-key", "url-credentials"]
    assert mask("S3cretPass") == "S3********"


def _github_routes(content: str):
    return {
        "https://api.github.com/search/code": (200, {"total_count": 2, "items": [
            {"url": "https://api.github.com/repos/dev/app/contents/config.py", "path": "config.py",
             "html_url": "https://github.com/dev/app/blob/main/config.py", "repository": {"full_name": "dev/app"}},
            {"url": "https://api.github.com/repos/x/site/contents/README.md", "path": "README.md",
             "html_url": "https://github.com/x/site/blob/main/README.md", "repository": {"full_name": "x/site"}},
        ]}),
        "https://api.github.com/repos/dev/app/contents/config.py": (200, {
            "encoding": "base64", "size": 100, "content": base64.b64encode(content.encode()).decode()}),
        "https://api.github.com/repos/x/site/contents/README.md": (200, {
            "encoding": "base64", "size": 10, "content": base64.b64encode(b"Contato: site.empresa.com.br").decode()}),
    }


def test_github_builtin_engine():
    content = 'SMTP_HOST = "mail.empresa.com.br"\nSMTP_PASSWORD = "Sup3rS3nha!"\n'
    c = GitHubCodeCollector(http_for(_github_routes(content)), token="t", gitleaks="")
    found = c.collect_domain("empresa.com.br")
    secret = [f for f in found if f.severity == "alta"]
    assert len(secret) == 1 and "Su**" in secret[0].detail and "Sup3rS3nha!" not in secret[0].detail
    assert any(f.title.endswith("x/site") and f.severity == "baixa" for f in found)
    assert not GitHubCodeCollector(None, token="", gitleaks="").enabled()


@pytest.mark.skipif(sys.platform == "win32", reason="gitleaks falso é um script shell")
def test_github_with_gitleaks_binary(tmp_path):
    fake = tmp_path / "gitleaks"
    fake.write_text(f"""#!{sys.executable}
import json, os, sys
args = sys.argv[1:]
if args[0] != "dir":
    sys.exit(1)
src = args[1]; out = args[args.index("--report-path") + 1]
files = sorted(f for f in os.listdir(src) if f.endswith("config.py"))
json.dump([{{"RuleID": "generic-api-key", "Description": "Generic API Key", "File": os.path.join(src, files[0]),
            "StartLine": 2, "Secret": "abcd1234efgh"}}], open(out, "w"))
""")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    c = GitHubCodeCollector(http_for(_github_routes("host=empresa.com.br\nk=1\n")), token="t", gitleaks=str(fake))
    found = [f for f in c.collect_domain("empresa.com.br") if f.severity == "alta"]
    assert len(found) == 1
    assert "gitleaks" in found[0].detail and "ab**" in found[0].detail and "abcd1234efgh" not in found[0].detail
    assert found[0].reference_url.endswith("#L2")


def test_otx_pulses_and_whitelist():
    body = {"pulse_info": {"count": 1, "pulses": [
        {"id": "p1", "name": "Phishing kit BR", "created": "2026-05-01T00:00:00", "tags": ["phishing"],
         "malware_families": [{"display_name": "Grandoreiro"}]}]}, "validation": []}
    c = OTXCollector(http_for({"https://otx.alienvault.com/api/v1/indicators/domain/empresa.com.br/general": (200, body)}),
                     api_key="")
    found = c.collect_domain("empresa.com.br")
    assert found[0].severity == "media" and "Grandoreiro" in found[0].detail
    body["validation"] = [{"source": "alexa"}]
    assert c.collect_domain("empresa.com.br")[0].severity == "info"


def test_abusech_partial_failure_keeps_results():
    c = AbuseChCollector(http_for({
        "https://urlhaus-api.abuse.ch/v1/host/": (200, {"query_status": "ok", "urls": [
            {"url": "http://empresa.com.br/wp-content/x.exe", "url_status": "online", "threat": "malware_download",
             "date_added": "2026-10-10 10:00:00 UTC", "tags": ["exe"]}]}),
        "https://threatfox-api.abuse.ch/api/v1/": (500, {}),
    }), auth_key="k")
    with pytest.raises(CollectorError) as exc:
        c.collect_domain("empresa.com.br")
    assert len(exc.value.findings) == 1 and exc.value.findings[0].severity == "critica"
    assert not AbuseChCollector(None, auth_key="").enabled()


def test_threatfox_match():
    c = AbuseChCollector(http_for({
        "https://urlhaus-api.abuse.ch/v1/host/": (200, {"query_status": "no_results"}),
        "https://threatfox-api.abuse.ch/api/v1/": (200, {"query_status": "ok", "data": [
            {"id": 77, "ioc": "c2.empresa.com.br", "threat_type_desc": "Botnet C&C", "malware_printable": "AsyncRAT",
             "confidence_level": 90, "first_seen": "2026-09-09 00:00:00 UTC"}]}),
    }), auth_key="k")
    found = c.collect_domain("empresa.com.br")
    assert len(found) == 1 and found[0].reference_url == "https://threatfox.abuse.ch/ioc/77/"


def test_builtin_rule_variable_names():
    hits = builtin_scan('SMTP_PASSWORD = "Sup3rS3nha!"\n"db.password": "outraSenha1"\nsenha_admin="abc"\n')
    assert [h["secret"] for h in hits] == ["Sup3rS3nha!", "outraSenha1"]


def test_crtsh_suspicious_words_are_whole_tokens():
    from app.collectors.crtsh import looks_suspicious
    assert not looks_suspicious("app.ericssonnikolatesla.com", "tesla.com")
    assert looks_suspicious("tesla-sso.net", "tesla.com")
    assert looks_suspicious("teslalogin.com", "tesla.com")
    assert looks_suspicious("tesla.com.verify-account.xyz", "tesla.com")


def test_ahmia_text_dates():
    from app.collectors.ahmia import _last_seen
    assert _last_seen("Oct. 1, 2026, 1:53 a.m.") == "2026-10-01"
    assert _last_seen("Sept. 30, 2026, noon") == "2026-09-30"
    assert _last_seen("May 5, 2026") == "2026-05-05"


def test_http_client_has_own_user_agent():
    from app.collectors import make_http_client
    assert "python-httpx" not in make_http_client().headers["User-Agent"]


def test_crtsh_ignores_other_client_domains():
    recent = (utcnow() - timedelta(days=1)).isoformat()
    c = CrtShCollector(http_for({"https://crt.sh/": (200, [
        {"id": 1, "name_value": "auth.empresa.cn\nempresa-login.com", "not_before": recent}])}), days=30)
    c.client_domains = {"empresa.com.br", "empresa.cn"}
    assert [f.title.split(": ")[1] for f in c.collect_domain("empresa.com.br")] == ["empresa-login.com"]


def test_pwned_count_k_anonymity():
    import hashlib
    from app.pwned import pwned_count
    digest = hashlib.sha1(b"Senha@123").hexdigest().upper()
    seen = []
    http = http_for({"https://api.pwnedpasswords.com/range/": (200, f"00000AAA:1\n{digest[5:]}:156842\n")}, seen)
    assert pwned_count(http, "Senha@123") == 156842
    assert str(seen[0].url).endswith("/" + digest[:5])  # só o prefixo sai do servidor
    assert "Senha@123" not in str(seen[0].url) and seen[0].headers["Add-Padding"] == "true"
    assert pwned_count(http, "outra-senha") == 0
