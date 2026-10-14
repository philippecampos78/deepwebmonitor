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

    Base.metadata.create_all(bind=bind or engine)
