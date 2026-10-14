"""Hudson Rock (ferramentas OSINT gratuitas do Cavalier).

Indica computadores infectados por malware do tipo infostealer que tinham
credenciais ligadas ao domínio ou e-mail consultado. As senhas que a API
devolve (já mascaradas) não são gravadas.
"""

from .base import Collector, FindingData

API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
SITE = "https://www.hudsonrock.com/free-tools"


def _families(data: dict) -> str:
    fam = data.get("stealerFamilies") or {}
    if not isinstance(fam, dict):
        return ""
    items = [(k, v) for k, v in fam.items() if k != "total" and isinstance(v, (int, float))]
    items.sort(key=lambda kv: -kv[1])
    return ", ".join(f"{k} ({v})" for k, v in items[:5])


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
             "Computadores de funcionários infectados com credenciais corporativas de"),
            ("users", "media", "usuário(s)/cliente(s)", "last_user_compromised", "clients_urls",
             "Usuários dos serviços de"),
            ("third_parties", "baixa", "terceiro(s)", "", "",
             "Terceiros com credenciais ligadas a"),
        ]
        for key, severity, who, last_key, urls_key, phrase in groups:
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
            computer = str(s.get("computer_name") or "")
            parts = [f"Data da infecção: {date or 'desconhecida'}"]
            for label, key in [("Malware", "stealer_family"), ("Computador", "computer_name"),
                               ("Sistema", "operating_system"), ("Caminho do malware", "malware_path"),
                               ("IP", "ip")]:
                if s.get(key):
                    parts.append(f"{label}: {s[key]}")
            if s.get("antiviruses"):
                av = s["antiviruses"]
                parts.append("Antivírus: " + (", ".join(av) if isinstance(av, list) else str(av)))
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
                fingerprint=f"hr:email:{email.lower()}:{date}:{computer.lower()}",
            ))
        return findings
