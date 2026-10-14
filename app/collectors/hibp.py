"""Have I Been Pwned (https://haveibeenpwned.com/API/v3).

Sem chave: usa só o catálogo público de incidentes para descobrir se o
próprio site do cliente já sofreu um vazamento.
Com chave (plano já contratado): também lista os e-mails vazados de domínios
verificados no painel do HIBP e consulta os e-mails monitorados.
"""

from urllib.parse import quote

from ..config import settings
from .base import Collector, CollectorError, FindingData

API = "https://haveibeenpwned.com/api/v3"

DATA_CLASSES_PT = {
    "Email addresses": "e-mails",
    "Passwords": "senhas",
    "Usernames": "nomes de usuário",
    "Names": "nomes",
    "Phone numbers": "telefones",
    "Physical addresses": "endereços",
    "IP addresses": "endereços IP",
    "Dates of birth": "datas de nascimento",
    "Genders": "gênero",
    "Credit cards": "cartões de crédito",
    "Partial credit card data": "dados parciais de cartão",
    "Bank account numbers": "contas bancárias",
    "Government issued IDs": "documentos de identidade",
    "Security questions and answers": "perguntas de segurança",
    "Auth tokens": "tokens de autenticação",
    "Job titles": "cargos",
    "Password hints": "dicas de senha",
    "Geographic locations": "localizações",
    "Social media profiles": "perfis em redes sociais",
    "Device information": "informações do dispositivo",
    "Browser user agent details": "dados do navegador",
    "Purchases": "compras",
    "Website activity": "atividade no site",
    "Education levels": "escolaridade",
    "Salutations": "pronomes de tratamento",
    "Spoken languages": "idiomas",
    "Time zones": "fusos horários",
    "Marital statuses": "estado civil",
    "Passport numbers": "números de passaporte",
    "Income levels": "faixa de renda",
    "Payment histories": "histórico de pagamentos",
    "Private messages": "mensagens privadas",
    "Credit card CVV": "CVV de cartão",
    "Employers": "empregadores",
}


def describe_classes(classes: list[str]) -> str:
    return ", ".join(DATA_CLASSES_PT.get(c, c) for c in classes)


class HIBPCollector(Collector):
    name = "hibp"
    label = "Have I Been Pwned"
    description = "Vazamentos de dados públicos catalogados pelo HIBP."

    def __init__(self, http, api_key: str | None = None):
        super().__init__(http)
        self.api_key = settings.hibp_api_key if api_key is None else api_key
        self._catalog: dict[str, dict] | None = None
        self._verified: set[str] | None = None

    def status_note(self) -> str:
        if self.api_key:
            return "chave configurada: busca por domínio verificado e por e-mail ativas"
        return "sem chave: apenas o catálogo público de incidentes"

    def _headers(self, auth: bool = False) -> dict:
        h = {"user-agent": settings.hibp_user_agent}
        if auth:
            h["hibp-api-key"] = self.api_key
        return h

    def catalog(self) -> dict[str, dict]:
        if self._catalog is None:
            data = self.get_json(f"{API}/breaches", headers=self._headers(), not_found_value=[])
            self._catalog = {b["Name"]: b for b in data or []}
        return self._catalog

    def verified_domains(self) -> set[str]:
        if self._verified is None:
            data = self.get_json(f"{API}/subscribeddomains", headers=self._headers(auth=True),
                                 not_found_value=[])
            self._verified = {d["DomainName"].lower() for d in data or []}
        return self._verified

    def _account_finding(self, email: str, breach_name: str) -> FindingData:
        b = self.catalog().get(breach_name, {"Name": breach_name, "Title": breach_name})
        classes = b.get("DataClasses", [])
        if b.get("IsSpamList"):
            severity = "baixa"
        elif "Passwords" in classes:
            severity = "alta"
        else:
            severity = "media"
        detail = f"Incidente: {b.get('Title', breach_name)}"
        if b.get("BreachDate"):
            detail += f" (ocorrido em {b['BreachDate']})"
        if classes:
            detail += f". Dados expostos: {describe_classes(classes)}."
        return FindingData(
            source=self.name,
            category="vazamento",
            severity=severity,
            asset=email,
            title=f"{email} aparece no vazamento {b.get('Title', breach_name)}",
            detail=detail,
            reference_url=f"https://haveibeenpwned.com/Breach/{quote(breach_name)}",
            event_date=b.get("BreachDate", ""),
            fingerprint=f"hibp:account:{email.lower()}:{breach_name}",
        )

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        findings = []

        # Gratuito: o próprio site do cliente já foi vazado?
        for b in self.catalog().values():
            bd = (b.get("Domain") or "").lower()
            if bd and (bd == domain or bd.endswith("." + domain)):
                findings.append(FindingData(
                    source=self.name,
                    category="incidente_proprio",
                    severity="critica" if "Passwords" in b.get("DataClasses", []) else "alta",
                    asset=domain,
                    title=f"O serviço {b.get('Title')} ({bd}) sofreu um vazamento de dados",
                    detail=(f"{b.get('PwnCount', 0):,}".replace(",", ".") + " contas afetadas. "
                            f"Dados expostos: {describe_classes(b.get('DataClasses', []))}."),
                    reference_url=f"https://haveibeenpwned.com/Breach/{quote(b['Name'])}",
                    event_date=b.get("BreachDate", ""),
                    fingerprint=f"hibp:own:{b['Name']}",
                ))

        if not self.api_key:
            return findings

        if domain not in self.verified_domains():
            raise CollectorError(
                f"{self.label}: {domain} não está verificado no painel do HIBP; "
                "a busca de e-mails do domínio foi ignorada.",
                findings=findings,
            )

        data = self.get_json(f"{API}/breacheddomain/{quote(domain)}",
                             headers=self._headers(auth=True), not_found_value={})
        for alias, breaches in (data or {}).items():
            for breach_name in breaches:
                findings.append(self._account_finding(f"{alias}@{domain}", breach_name))
        return findings

    def supports(self, kind: str) -> bool:
        return kind == "domain" or bool(self.api_key)  # e-mail só com a chave do plano

    def collect_email(self, email: str) -> list[FindingData]:
        if not self.api_key:
            return []
        data = self.get_json(f"{API}/breachedaccount/{quote(email)}",
                             headers=self._headers(auth=True),
                             params={"truncateResponse": "true"}, not_found_value=[])
        return [self._account_finding(email, b["Name"]) for b in data or []]

