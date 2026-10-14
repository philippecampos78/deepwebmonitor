"""Shodan InternetDB: portas abertas e vulnerabilidades (CVE) nos servidores do cliente.

Gratuito e sem chave. Os IPs vêm do DNS do domínio (domínio, www e servidores
de e-mail). As CVEs são cruzadas com o catálogo KEV da CISA (falhas exploradas
ativamente), que vira gravidade crítica.
"""

from .base import Collector, CollectorError, FindingData
from .dnsquery import DNSError, resolve

API = "https://internetdb.shodan.io"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_IPS = 10

# Serviços que raramente deveriam estar abertos para a internet
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 135: "RPC Windows", 139: "NetBIOS", 445: "SMB (compartilhamento Windows)",
    1433: "SQL Server", 1521: "Oracle", 2375: "Docker sem TLS", 3306: "MySQL", 3389: "RDP (área de trabalho remota)",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 5601: "Kibana", 8291: "MikroTik Winbox", 161: "SNMP",
}


class InternetDBCollector(Collector):
    name = "internetdb"
    label = "Shodan InternetDB"
    description = "Portas abertas e vulnerabilidades conhecidas nos servidores do cliente."

    def __init__(self, http):
        super().__init__(http)
        self._kev: dict[str, dict] | None = None

    def kev(self) -> dict[str, dict]:
        if self._kev is None:
            try:
                data = self.get_json(KEV_URL, not_found_value={}, timeout=60) or {}
                self._kev = {v["cveID"]: v for v in data.get("vulnerabilities", []) if v.get("cveID")}
            except CollectorError:
                self._kev = {}  # sem o catálogo, as CVEs continuam aparecendo, só sem a marcação KEV
        return self._kev

    def _targets(self, domain: str) -> dict[str, set[str]]:
        """{ip: {nomes que apontam para ele}}"""
        own = self.client_domains | {domain}
        # Servidores de e-mail só contam se forem do cliente (não os do Google/Microsoft, por exemplo)
        mx = [m.lower() for m in resolve(self.http, domain, "MX")
              if any(m.lower() == d or m.lower().endswith("." + d) for d in own)]
        names = [domain, f"www.{domain}"] + mx
        ips: dict[str, set[str]] = {}
        for name in names:
            for ip in resolve(self.http, name, "A"):
                ips.setdefault(ip, set()).add(name)
        return dict(list(ips.items())[:MAX_IPS])

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        try:
            targets = self._targets(domain)
        except DNSError as exc:
            raise CollectorError(f"{self.label}: {exc}") from exc

        findings = []
        for ip, names in targets.items():
            data = self.get_json(f"{API}/{ip}", not_found_value=None)
            if not data:
                continue
            tags = set(data.get("tags") or [])
            shared = bool(tags & {"cdn", "cloud"}) and not (set(data.get("ports") or []) & set(RISKY_PORTS))
            where = f"{ip} ({', '.join(sorted(names))})"
            note = (" IP de CDN/nuvem compartilhada: a exposição pode ser do provedor, não do cliente."
                    if "cdn" in tags else "")

            ports = sorted(data.get("ports") or [])
            risky = [f"{p} {RISKY_PORTS[p]}" for p in ports if p in RISKY_PORTS]
            if risky:
                findings.append(FindingData(
                    source=self.name, category="exposicao", severity="alta", asset=domain,
                    title=f"Serviços sensíveis expostos na internet em {where}",
                    detail=(f"Portas de risco abertas: {', '.join(risky)}. Todas as portas: {', '.join(map(str, ports))}."
                            " Esses serviços não deveriam ser acessíveis publicamente; restrinja por firewall ou VPN." + note),
                    reference_url=f"https://www.shodan.io/host/{ip}",
                    fingerprint=f"internetdb:{ip}:risky:{','.join(str(p) for p in ports if p in RISKY_PORTS)}",
                ))
            elif ports and not shared:
                findings.append(FindingData(
                    source=self.name, category="exposicao", severity="info", asset=domain,
                    title=f"Portas abertas em {where}: {', '.join(map(str, ports))}",
                    detail="Inventário de serviços publicados. Confirme com o cliente se todos são esperados." + note,
                    reference_url=f"https://www.shodan.io/host/{ip}",
                    fingerprint=f"internetdb:{ip}:ports:{','.join(map(str, ports))}",
                ))

            vulns = sorted(set(data.get("vulns") or []), reverse=True)
            if vulns:
                kev = self.kev()
                exploited = [v for v in vulns if v in kev]
                severity = "critica" if exploited else "alta"
                if "cdn" in tags and not exploited:
                    severity = "media"
                detail = f"{len(vulns)} vulnerabilidade(s) conhecida(s) pelas versões de software detectadas."
                if exploited:
                    detail += (" EXPLORADAS ATIVAMENTE (catálogo KEV da CISA): "
                               + "; ".join(f"{v} ({kev[v].get('vendorProject', '')} {kev[v].get('product', '')})"
                                           for v in exploited[:10]) + ".")
                detail += f" CVEs: {', '.join(vulns[:25])}{' …' if len(vulns) > 25 else ''}."
                if data.get("cpes"):
                    detail += f" Software: {', '.join(data['cpes'][:8])}."
                detail += " A detecção é por versão; confirme se o patch já foi aplicado." + note
                findings.append(FindingData(
                    source=self.name, category="exposicao", severity=severity, asset=domain,
                    title=f"{len(vulns)} vulnerabilidade(s) em {where}" + (f", {len(exploited)} explorada(s) ativamente" if exploited else ""),
                    detail=detail,
                    reference_url=f"https://www.shodan.io/host/{ip}",
                    fingerprint=f"internetdb:{ip}:vulns:{len(vulns)}:{','.join(exploited)}",
                ))
        return findings
