"""Hudson Rock (ferramentas OSINT gratuitas do Cavalier).

Indica computadores infectados por malware do tipo infostealer que tinham
credenciais ligadas ao domínio ou e-mail consultado. As senhas que a API
devolve (já mascaradas) não são gravadas.
"""

from .base import Collector, FindingData
from .matching import ensure_masked

API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
SITE = "https://www.hudsonrock.com/free-tools"


def _families(data: dict) -> str:
    fam = data.get("stealerFamilies") or {}
    if not isinstance(fam, dict):
        return ""
    items = [(k, v) for k, v in fam.items() if k != "total" and isinstance(v, (int, float))]
    items.sort(key=lambda kv: -kv[1])
    return ", ".join(f"{k} ({v})" for k, v in items[:5])


_EMPTY = {"", "not found", "none", "null", "n/a"}


def _filled(value) -> bool:
    if isinstance(value, list):
        return any(_filled(v) for v in value)
    return str(value).strip().lower() not in _EMPTY


def _password_strength(stats) -> str:
    """Resumo da força das senhas roubadas (a API devolve só estatísticas, não as senhas)."""
    if not isinstance(stats, dict) or not stats.get("totalPass"):
        return ""
    labels = [("too_weak", "muito fracas"), ("weak", "fracas"), ("medium", "médias"), ("strong", "fortes")]
    parts = [f"{stats[k]['perc']}% {label}" for k, label in labels
             if isinstance(stats.get(k), dict) and stats[k].get("perc") is not None]
    return f"{stats['totalPass']} senhas analisadas: " + ", ".join(parts) if parts else ""


def _urls(entries) -> str:
    out = []
    for e in (entries or [])[:10]:
        if isinstance(e, dict) and e.get("url"):
            n = e.get("occurrence")
            out.append(f"{e['url']} ({n}x)" if n else e["url"])
    return "; ".join(out)


class HudsonRockCollector(Collector):
    name = "hudsonrock"
    label = "Hudson Rock"
    description = "Computadores infectados por infostealer (credenciais roubadas por malware)."

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        data = self.get_json(f"{API}/search-by-domain", params={"domain": domain},
                             not_found_value={}) or {}
        urls = data.get("data") or {}
        families = _families(data)
        findings = []

        groups = [
            ("employees", "critica", "funcionário(s)", "last_employee_compromised", "employees_urls",
             "Computadores de funcionários infectados com credenciais corporativas de", "employeePasswords"),
            ("users", "media", "usuário(s)/cliente(s)", "last_user_compromised", "clients_urls",
             "Usuários dos serviços de", "userPasswords"),
            ("third_parties", "baixa", "terceiro(s)", "", "",
             "Terceiros com credenciais ligadas a", ""),
        ]
        for key, severity, who, last_key, urls_key, phrase, pass_key in groups:
            count = data.get(key) or 0
            if not isinstance(count, int) or count <= 0:
                continue
            last = str(data.get(last_key) or "")[:10] if last_key else ""
            detail = f"{count} {who} com credenciais de {domain} encontradas em logs de infostealer."
            if last:
                detail += f" Infecção mais recente: {last}."
            if urls_key and _urls(urls.get(urls_key)):
                detail += f" Serviços afetados: {_urls(urls.get(urls_key))}."
            if families:
                detail += f" Famílias de malware: {families}."
            strength = _password_strength(data.get(pass_key)) if pass_key else ""
            if strength:
                detail += f" Força das senhas roubadas: {strength}."
            findings.append(FindingData(
                source=self.name,
                category="infostealer",
                severity=severity,
                asset=domain,
                title=f"{phrase} {domain}: {count}",
                detail=detail,
                reference_url=SITE,
                event_date=last,
                fingerprint=f"hr:domain:{domain}:{key}:{count}:{last}",
            ))
        return findings

    def collect_email(self, email: str) -> list[FindingData]:
        data = self.get_json(f"{API}/search-by-email", params={"email": email},
                             not_found_value={}) or {}
        findings = []
        for s in data.get("stealers") or []:
            if not isinstance(s, dict):
                continue
            date = str(s.get("date_compromised") or "")[:10]
            computer = str(s.get("computer_name") or "") if _filled(s.get("computer_name")) else ""
            parts = [f"Data da infecção: {date or 'desconhecida'}"]
            for label, key in [("Malware", "stealer_family"), ("Computador", "computer_name"),
                               ("Sistema", "operating_system"), ("Caminho do malware", "malware_path"),
                               ("IP", "ip")]:
                if s.get(key) and _filled(s[key]):
                    parts.append(f"{label}: {s[key]}")
            av = s.get("antiviruses")
            if av and _filled(av):
                parts.append("Antivírus: " + (", ".join(a for a in av if _filled(a)) if isinstance(av, list) else str(av)))
            passwords = [ensure_masked(p) for p in s.get("top_passwords") or [] if _filled(p)]
            if passwords:
                parts.append("Senhas encontradas no computador (mascaradas): " + ", ".join(passwords[:5]))
            logins = [ensure_masked(u) for u in s.get("top_logins") or [] if _filled(u)]
            if logins:
                parts.append("Logins encontrados (mascarados): " + ", ".join(logins[:5]))
            if s.get("total_corporate_services") is not None:
                parts.append(f"Serviços corporativos com credencial roubada: {s['total_corporate_services']}")
            if s.get("total_user_services") is not None:
                parts.append(f"Serviços pessoais com credencial roubada: {s['total_user_services']}")
            findings.append(FindingData(
                source=self.name,
                category="infostealer",
                severity="critica",
                asset=email,
                title=f"{email} estava em um computador infectado por infostealer",
                detail=". ".join(parts) + ".",
                reference_url=SITE,
                event_date=date,
                fingerprint=f"hr:email:{email.lower()}:{date}:{computer.lower()}:{s.get('ip', '')}",
            ))
        return findings
