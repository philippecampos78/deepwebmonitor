"""Monta os dados do relatório de um cliente."""

import re
from collections import Counter
from datetime import timedelta

from .models import CATEGORY_LABELS, CATEGORY_TITLES, SEVERITIES, SEVERITY_LABELS, Client, utcnow

RECOMMENDATIONS = {
    "ransomware": [
        "Acionar imediatamente o plano de resposta a incidentes e confirmar se houve intrusão.",
        "Identificar quais dados foram publicados e avaliar a comunicação à ANPD e aos titulares (LGPD, art. 48).",
        "Não acessar o site do grupo a partir da rede corporativa; usar ambiente isolado.",
    ],
    "infostealer": [
        "Redefinir as senhas de todas as contas listadas e encerrar as sessões ativas (tokens e cookies roubados permitem acesso sem senha).",
        "Exigir MFA em VPN, e-mail, SSO e sistemas expostos à internet.",
        "Localizar e limpar ou reinstalar os computadores infectados; verificar se são equipamentos pessoais usados para trabalho.",
    ],
    "vazamento": [
        "Forçar a troca de senha das contas afetadas, principalmente onde senhas foram expostas.",
        "Orientar os usuários a não reutilizar a senha corporativa em serviços pessoais.",
        "Monitorar tentativas de login com essas contas (credential stuffing).",
    ],
    "dark_web": [
        "Analisar o contexto da menção em ambiente isolado (máquina virtual, fora da rede corporativa).",
        "Se houver indício de venda ou vazamento de dados, tratar como incidente e preservar evidências.",
    ],
    "codigo_exposto": [
        "Revogar e substituir imediatamente qualquer credencial, token ou chave encontrada.",
        "Pedir a remoção do conteúdo ao dono do repositório ou ao GitHub; apagar o arquivo não remove o histórico.",
        "Adotar varredura automática de segredos nos repositórios e pipelines de desenvolvimento.",
    ],
    "ioc": [
        "Verificar se servidores do domínio foram comprometidos (web shells, arquivos alterados, contas novas).",
        "Remover o conteúdo malicioso e corrigir a vulnerabilidade explorada.",
        "Solicitar a remoção do domínio das listas após a limpeza, para evitar bloqueios de reputação.",
    ],
    "exposicao": [
        "Fechar no firewall as portas de administração e bancos de dados expostos; acesso só por VPN.",
        "Aplicar imediatamente os patches das vulnerabilidades exploradas ativamente (KEV) e priorizar as demais.",
        "Revisar se cada serviço publicado é necessário e tem dono responsável.",
    ],
    "phishing": [
        "Avaliar cada página e, se confirmada a fraude, pedir a remoção ao provedor e ao registrador.",
        "Alertar funcionários e clientes sobre o endereço falso.",
        "Bloquear os domínios no proxy, DNS e gateway de e-mail.",
    ],
    "email_seguranca": [
        "Publicar SPF terminando em \"-all\" com todos os serviços que enviam e-mail pelo domínio.",
        "Ativar DKIM em todos os provedores de e-mail usados.",
        "Implantar DMARC: começar com p=none e relatórios (rua), evoluir para p=quarantine e p=reject.",
    ],
    "incidente_proprio": [
        "Confirmar se o incidente já foi tratado e comunicado.",
        "Garantir que as senhas dos usuários afetados foram redefinidas.",
    ],
    "dominio_similar": [
        "Avaliar cada domínio; os que têm servidor de e-mail (MX) podem ser usados para phishing.",
        "Solicitar a remoção (takedown) ao registrador/provedor dos domínios maliciosos.",
        "Configurar SPF, DKIM e DMARC com política 'reject' e alertar os usuários.",
    ],
}

# Escopo descrito no relatório do cliente: o QUE foi analisado, nunca COM QUAIS ferramentas
METHOD_SCOPE = [
    "Vazamentos de dados públicos envolvendo contas e domínios da organização",
    "Credenciais corporativas capturadas por malware do tipo infostealer",
    "Publicações em sites de extorsão mantidos por grupos de ransomware",
    "Menções à organização em fóruns e páginas da dark web",
    "Credenciais, chaves e dados expostos em repositórios de código público",
    "Reputação do domínio e presença em bases de indicadores de ameaça",
    "Serviços e vulnerabilidades expostos à internet",
    "Domínios, certificados e páginas que imitam a marca (phishing)",
    "Proteção do domínio contra falsificação de e-mails (SPF, DKIM e DMARC)",
]

# Trocas aplicadas aos textos dos achados no relatório do cliente, para não revelar as
# ferramentas de coleta. A tela interna do site continua mostrando a origem de cada achado.
_PUBLIC_REWRITES = [
    (r"\s*Confirmado também por: [^.]*\.", " Confirmado por mais de uma fonte."),
    (r"\s*\((?:detectado por )?(?:gitleaks|regras internas)\)", ""),
    (r"\bno URLhaus\b", "em base pública de URLs maliciosas"),
    (r"\bno ThreatFox\b", "em base pública de indicadores de ameaça"),
    (r"\bcatálogo KEV da CISA\b", "catálogo público de vulnerabilidades exploradas ativamente"),
    (r"\bO OTX marca\b", "As bases de reputação marcam"),
    (r"\bClassificação do urlscan\b", "Classificação em base pública"),
    (r"\s+no VirusTotal\b", " de reputação"),
]
TOOL_NAMES = ["Have I Been Pwned", "HIBP", "XposedOrNot", "LeakCheck", "Hudson Rock", "Cavalier",
              "ransomware.live", "RansomLook", "Ahmia", "gitleaks", "abuse.ch", "URLhaus", "ThreatFox",
              "AlienVault", "OTX", "VirusTotal", "Shodan", "InternetDB", "CISA", "KEV", "urlscan",
              "crt.sh", "dnstwist", "Pwned Passwords"]
_TOOLS_RE = re.compile(r"\b(?:" + "|".join(re.escape(t) for t in sorted(TOOL_NAMES, key=len, reverse=True)) + r")\b",
                       re.I)


def public_text(text: str) -> str:
    """Versão do texto para o cliente: sem nomes de ferramentas de coleta."""
    out = text or ""
    for pattern, repl in _PUBLIC_REWRITES:
        out = re.sub(pattern, repl, out, flags=re.I)
    return _TOOLS_RE.sub("fonte pública", out)


def build_report(client: Client, days: int) -> dict:
    cutoff = utcnow() - timedelta(days=days)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings = sorted(client.findings, key=lambda f: (order.get(f.severity, 9), f.category, f.asset, f.title))
    new_ids = {f.id for f in findings if f.first_seen >= cutoff}

    by_severity = Counter(f.severity for f in findings)
    sections = []
    for cat, label in CATEGORY_LABELS.items():
        items = [f for f in findings if f.category == cat]
        if items:
            sections.append({
                "key": cat,
                "label": label,
                "title": CATEGORY_TITLES.get(cat, (label, "")),
                "items": items,
                "new": sum(1 for f in items if f.id in new_ids),
                "recommendations": RECOMMENDATIONS.get(cat, []),
            })

    if by_severity.get("critica"):
        risk = "critica"
    elif by_severity.get("alta"):
        risk = "alta"
    elif by_severity.get("media"):
        risk = "media"
    elif findings:
        risk = "baixa"
    else:
        risk = "info"

    last_scan = next((s for s in client.scans if s.status == "concluida"), None)
    return {
        "client": client,
        "days": days,
        "generated_at": utcnow(),
        "last_scan": last_scan,
        "total": len(findings),
        "new_total": len(new_ids),
        "new_ids": new_ids,
        "by_severity": [(s, SEVERITY_LABELS[s], by_severity.get(s, 0)) for s in SEVERITIES],
        "risk": risk,
        "risk_label": SEVERITY_LABELS[risk],
        "sections": sections,
        "method_scope": METHOD_SCOPE,
    }
