import re

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from app import db as dbmod
from app.models import CATEGORY_LABELS, Client, Domain, Finding
from app.reports import TOOL_NAMES, public_text

# Textos no formato que os coletores gravam
SAMPLES = [
    ("URL do domínio listada no URLhaus distribuindo malware (ONLINE)", "URL: http://x. Indica site comprometido."),
    ("Indicador de ameaça no ThreatFox: c2.empresa.com.br", "Tipo: Botnet C&C."),
    ("empresa.com.br marcado como malicioso/suspeito por 3 analisador(es) no VirusTotal", "Quem marcou: Fortinet (phishing)."),
    ("Possível segredo exposto em dev/app/config.py (linha 2)",
     "Tipo: Senha (detectado por gitleaks). Valor mascarado: Su****. Nenhum segredo detectado (regras internas); revise."),
    ("2 vulnerabilidade(s) em 1.1.1.1", "EXPLORADAS ATIVAMENTE (catálogo KEV da CISA): CVE-2024-1."),
    ("empresa.com.br citado no relatório de ameaça \"X\"", "O OTX marca este domínio como confiável."),
    ("Página suspeita usando a marca: empresa-login.com", "Classificação do urlscan: phishing."),
    ("ceo@empresa.com.br aparece no vazamento Adobe", "Incidente: Adobe. Confirmado também por: XposedOrNot, LeakCheck."),
    ("Outro achado", "Visto no Have I Been Pwned, HIBP, Hudson Rock, ransomware.live, RansomLook, Ahmia, AlienVault, "
                     "Shodan InternetDB, crt.sh, dnstwist e Pwned Passwords."),
]


def test_public_text_rewrites():
    assert public_text("Indicador de ameaça no ThreatFox: x") == "Indicador de ameaça em base pública de indicadores de ameaça: x"
    assert public_text("Incidente: Adobe. Confirmado também por: XposedOrNot, LeakCheck.") == \
        "Incidente: Adobe. Confirmado por mais de uma fonte."
    assert public_text("Tipo: Senha (detectado por gitleaks). Valor") == "Tipo: Senha. Valor"
    assert "Fortinet" in public_text("Quem marcou: Fortinet (phishing).")  # antivírus é evidência, não ferramenta


def test_client_report_never_names_collection_tools():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    dbmod.SessionLocal.configure(bind=engine)
    dbmod.engine = engine
    from app.main import app
    with TestClient(app) as tc:
        dbmod.init_db(engine)
        with dbmod.SessionLocal() as s:
            c = Client(name="Privacidade", domains=[Domain(name="empresa.com.br")])
            s.add(c)
            s.flush()
            categories = list(CATEGORY_LABELS)  # todas as seções do relatório, com suas recomendações
            for i, (title, detail) in enumerate(SAMPLES + [("t", "d")] * len(categories)):
                s.add(Finding(client_id=c.id, source="x", category=categories[i % len(categories)],
                              severity="alta", asset="empresa.com.br",
                              title=title, detail=detail, fingerprint=f"f{i}"))
            s.commit()
            cid = c.id
        for theme in ("", "&tema=claro"):
            html = tc.get(f"/clients/{cid}/report?dias=30{theme}").text
            text = re.sub(r"<[^>]+>", " ", html)
            leaked = [t for t in TOOL_NAMES if re.search(rf"\b{re.escape(t)}\b", text, re.I)]
            assert leaked == [], leaked
            assert "Metodologia de" in html and "fontes abertas (OSINT)" in html
        # a tela interna continua mostrando a origem para o analista
        assert "URLhaus" in tc.get(f"/clients/{cid}").text
