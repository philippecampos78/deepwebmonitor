from datetime import datetime, timezone

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


SEVERITIES = ["critica", "alta", "media", "baixa", "info"]
SEVERITY_LABELS = {
    "critica": "Crítica",
    "alta": "Alta",
    "media": "Média",
    "baixa": "Baixa",
    "info": "Informativa",
}
CATEGORY_LABELS = {
    "ransomware": "Exposição em sites de ransomware",
    "infostealer": "Computadores infectados por infostealer",
    "vazamento": "Contas em vazamentos de dados",
    "dark_web": "Menções na dark web",
    "codigo_exposto": "Credenciais e dados expostos em código público",
    "ioc": "Domínio em bases de indicadores de ameaça",
    "exposicao": "Serviços e vulnerabilidades expostos na internet",
    "phishing": "Páginas falsas usando a marca",
    "email_seguranca": "Proteção do domínio contra e-mails falsificados",
    "incidente_proprio": "Incidentes envolvendo o próprio domínio",
    "dominio_similar": "Domínios e certificados parecidos (possível phishing)",
}

# Títulos das seções do relatório no padrão da proposta: (parte branca, parte azul)
CATEGORY_TITLES = {
    "ransomware": ("Sites de", "ransomware"),
    "infostealer": ("Credenciais em", "infostealer"),
    "vazamento": ("Contas em", "vazamentos"),
    "dark_web": ("Menções na", "dark web"),
    "codigo_exposto": ("Código", "exposto"),
    "ioc": ("Indicadores de", "ameaça"),
    "exposicao": ("Serviços", "expostos"),
    "phishing": ("Páginas de", "phishing"),
    "email_seguranca": ("Segurança de", "e-mail"),
    "incidente_proprio": ("Incidentes do", "próprio domínio"),
    "dominio_similar": ("Domínios", "parecidos"),
}

class Client(Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    # Fontes escolhidas na última varredura, separadas por vírgula ("" = todas)
    scan_sources: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    domains: Mapped[list["Domain"]] = relationship(
        back_populates="client", cascade="all, delete-orphan", order_by="Domain.name"
    )
    emails: Mapped[list["MonitoredEmail"]] = relationship(
        back_populates="client", cascade="all, delete-orphan", order_by="MonitoredEmail.address"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )
    scans: Mapped[list["ScanRun"]] = relationship(
        back_populates="client", cascade="all, delete-orphan", order_by="ScanRun.id.desc()"
    )


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (UniqueConstraint("client_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(253))

    client: Mapped[Client] = relationship(back_populates="domains")


class MonitoredEmail(Base):
    """E-mails importantes (diretoria, TI, financeiro) consultados um a um."""

    __tablename__ = "monitored_emails"
    __table_args__ = (UniqueConstraint("client_id", "address"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"))
    address: Mapped[str] = mapped_column(String(320))

    client: Mapped[Client] = relationship(back_populates="emails")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("client_id", "fingerprint"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(50))
    category: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    asset: Mapped[str] = mapped_column(String(320))
    title: Mapped[str] = mapped_column(String(500))
    detail: Mapped[str] = mapped_column(Text, default="")
    reference_url: Mapped[str] = mapped_column(String(1000), default="")
    event_date: Mapped[str] = mapped_column(String(40), default="")
    fingerprint: Mapped[str] = mapped_column(String(500))
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)

    client: Mapped[Client] = relationship(back_populates="findings")

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, self.severity)

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS.get(self.category, self.category)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"))
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    status: Mapped[str] = mapped_column(String(20), default="executando")
    new_findings: Mapped[int] = mapped_column(default=0)
    log: Mapped[str] = mapped_column(Text, default="")

    client: Mapped[Client] = relationship(back_populates="scans")
