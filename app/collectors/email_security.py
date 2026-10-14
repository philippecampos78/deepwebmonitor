"""SPF, DKIM e DMARC: o domínio do cliente pode ser falsificado em e-mails?

Sem DMARC com política "reject" (ou "quarantine"), qualquer pessoa consegue
mandar e-mail como se fosse diretoria@cliente.com.br. Tudo é consultado no DNS
público; nenhuma API externa é usada além da resolução DNS.
"""

import re

from .base import Collector, CollectorError, FindingData
from .dnsquery import DNSError, resolve

# Seletores DKIM mais comuns (Microsoft 365, Google Workspace, provedores de e-mail marketing...)
DKIM_SELECTORS = ["selector1", "selector2", "google", "default", "dkim", "mail", "k1", "k2", "s1", "s2",
                  "smtp", "mx", "zoho", "mandrill", "everlytickey1", "protonmail", "sendgrid", "amazonses"]
REF = "https://www.cloudflare.com/pt-br/learning/email-security/dmarc-dkim-spf/"


def _tag(record: str, name: str) -> str:
    m = re.search(rf"(?:^|;)\s*{name}\s*=\s*([^;]+)", record, re.I)
    return m.group(1).strip().lower() if m else ""


class EmailSecurityCollector(Collector):
    name = "email_security"
    label = "SPF / DKIM / DMARC"
    description = "Se o domínio do cliente pode ser falsificado em e-mails de phishing."

    def _finding(self, domain, key, severity, title, detail) -> FindingData:
        return FindingData(source=self.name, category="email_seguranca", severity=severity, asset=domain,
                           title=title, detail=detail, reference_url=REF,
                           fingerprint=f"email:{domain}:{key}")

    def _spf(self, domain: str) -> list[FindingData]:
        records = [t for t in resolve(self.http, domain, "TXT") if t.lower().startswith("v=spf1")]
        if not records:
            return [self._finding(domain, "spf-ausente", "alta", f"{domain} não tem registro SPF",
                                  "Sem SPF, servidores de e-mail não conseguem saber quem pode enviar em nome do domínio. "
                                  "Se o domínio não envia e-mail, publique \"v=spf1 -all\".")]
        if len(records) > 1:
            return [self._finding(domain, "spf-multiplo", "media", f"{domain} tem {len(records)} registros SPF",
                                  "Mais de um registro SPF invalida todos (erro permanente). Junte-os em um só: "
                                  + " | ".join(records))]
        spf = records[0]
        policy = re.search(r"(?:^|\s)([+\-~?]?)all\b", spf)
        qualifier = policy.group(1) if policy else None
        if qualifier in ("+", ""):
            return [self._finding(domain, "spf-all", "critica", f"SPF de {domain} autoriza qualquer servidor (+all)",
                                  f"Registro: {spf}. \"+all\" permite que qualquer um envie e-mail como o domínio.")]
        if qualifier == "?":
            return [self._finding(domain, "spf-neutro", "media", f"SPF de {domain} é neutro (?all)",
                                  f"Registro: {spf}. \"?all\" não bloqueia remetentes não autorizados; use \"-all\".")]
        if qualifier is None:
            return [self._finding(domain, "spf-sem-all", "media", f"SPF de {domain} não termina com \"all\"",
                                  f"Registro: {spf}. Sem \"-all\" ou \"~all\" o SPF não diz o que fazer com outros remetentes.")]
        return []

    def _dmarc(self, domain: str) -> list[FindingData]:
        records = [t for t in resolve(self.http, f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
        if not records:
            return [self._finding(domain, "dmarc-ausente", "alta", f"{domain} não tem DMARC",
                                  "Sem DMARC, e-mails falsificados com o domínio do cliente chegam às caixas de entrada. "
                                  "Comece com \"v=DMARC1; p=none; rua=mailto:...\" para monitorar e evolua para \"p=reject\".")]
        dmarc = records[0]
        p, pct = _tag(dmarc, "p"), _tag(dmarc, "pct")
        out = []
        if p in ("", "none"):
            out.append(self._finding(domain, "dmarc-none", "media", f"DMARC de {domain} só monitora (p=none)",
                                     f"Registro: {dmarc}. Com p=none os e-mails falsificados são entregues normalmente; "
                                     "após validar os relatórios, mude para p=quarantine e depois p=reject."))
        elif pct and pct.isdigit() and int(pct) < 100:
            out.append(self._finding(domain, "dmarc-pct", "baixa", f"DMARC de {domain} vale para só {pct}% dos e-mails",
                                     f"Registro: {dmarc}. O restante dos e-mails falsificados não é bloqueado."))
        if not _tag(dmarc, "rua"):
            out.append(self._finding(domain, "dmarc-sem-rua", "baixa", f"DMARC de {domain} não recebe relatórios (rua)",
                                     f"Registro: {dmarc}. Sem \"rua=\" ninguém fica sabendo das tentativas de falsificação."))
        return out

    def _dkim(self, domain: str) -> list[FindingData]:
        for sel in DKIM_SELECTORS:
            for value in resolve(self.http, f"{sel}._domainkey.{domain}", "TXT") + \
                    resolve(self.http, f"{sel}._domainkey.{domain}", "CNAME"):
                if "p=" in value.lower() or value.endswith((".onmicrosoft.com", ".dkim.amazonses.com")) \
                        or "domainkey" in value.lower():
                    return []
        return [self._finding(domain, "dkim-nao-encontrado", "info", f"Nenhum DKIM encontrado nos seletores comuns de {domain}",
                              "Foram testados os seletores mais usados (Microsoft 365, Google, provedores de e-mail). "
                              "O domínio pode usar um seletor próprio: confirme com o cliente se o DKIM está ativo.")]

    def collect_domain(self, domain: str) -> list[FindingData]:
        domain = domain.lower()
        findings, errors = [], []
        for check in (self._spf, self._dmarc, self._dkim):
            try:
                findings += check(domain)
            except DNSError as exc:
                errors.append(str(exc))
        if errors:
            raise CollectorError(f"{self.label}: " + "; ".join(errors), findings=findings)
        return findings
