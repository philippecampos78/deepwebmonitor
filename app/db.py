from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import BASE_DIR, settings


class Base(DeclarativeBase):
    pass


def make_engine(url: str):
    if url.startswith("sqlite:///") and not url.startswith("sqlite:///:memory:"):
        path = Path(url.removeprefix("sqlite:///"))
        if not path.is_absolute():
            path = BASE_DIR / path
        path.parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{path.as_posix()}"
    engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    return engine


engine = make_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db(bind=None) -> None:
    from . import models  # noqa: F401  (registra as tabelas)

    bind = bind or engine
    Base.metadata.create_all(bind=bind)
    _add_missing_columns(bind)


# Colunas criadas depois da primeira versão: (tabela, coluna, definição SQL)
_NEW_COLUMNS = [
    ("clients", "scan_sources", "TEXT NOT NULL DEFAULT ''"),
    ("findings", "merge_key", "VARCHAR(500) NOT NULL DEFAULT ''"),
]


def _add_missing_columns(bind) -> None:
    """Atualiza bancos criados por versões anteriores sem apagar dados."""
    from sqlalchemy import inspect, text

    insp = inspect(bind)
    with bind.begin() as conn:
        for table, column, ddl in _NEW_COLUMNS:
            if table in insp.get_table_names() and column not in {c["name"] for c in insp.get_columns(table)}:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
