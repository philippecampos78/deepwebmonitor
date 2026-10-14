"""Monta os dados do relatório de um cliente."""

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
        "Adotar varredura de segredos (ex.: gitleaks) nos repositórios e pipelines do cliente.",
    ],
    "ioc": [
        "Verificar se servidores do domínio foram comprometidos (web shells, arquivos alterados, contas novas).",
        "Remover o conteúdo malicioso e corrigir a vulnerabilidade explorada.",
        "Solicitar a remoção do domínio das listas após a limpeza, para evitar bloqueios de reputação.",
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

SOURCES = [
    ("Have I Been Pwned", "Catálogo de vazamentos de dados públicos e busca por domínio verificado."),
    ("ransomware.live", "Monitoramento de sites de vazamento mantidos por grupos de ransomware."),
    ("Hudson Rock (OSINT)", "Base de computadores infectados por malware do tipo infostealer."),
    ("RansomLook", "Segunda base de sites de vazamento de ransomware, com outros grupos monitorados."),
    ("Ahmia", "Buscador de páginas da rede Tor (.onion)."),
    ("GitHub + gitleaks", "Busca de código público que menciona o domínio e detecção de segredos."),
    ("abuse.ch (URLhaus e ThreatFox)", "Bases de URLs maliciosas e indicadores de ameaça."),
    ("AlienVault OTX", "Relatórios de ameaças compartilhados pela comunidade."),
    ("crt.sh", "Logs públicos de certificados TLS (Certificate Transparency)."),
    ("dnstwist", "Geração de variações do domínio e verificação de registro no DNS."),
]


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
        "sources": SOURCES,
    }
