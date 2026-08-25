"""SQLAlchemy engine and session wiring."""

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.models import Base

_engine = None
_SessionLocal: sessionmaker | None = None


def connect_args(database_url: str) -> dict:
    """Driver options for this database URL.

    Postgres takes the statement timeout as a server option on the connection,
    so every statement on it is bounded without each call site remembering to
    ask. SQLite, which the tests run on, has no such option and gets none.
    """
    if database_url.startswith("postgresql"):
        return {"options": f"-c statement_timeout={get_settings().query_timeout_ms}"}
    return {}


def engine():
    global _engine
    if _engine is None:
        url = get_settings().database_url
        _engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args(url))
    return _engine


def session_factory() -> sessionmaker:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=engine(), autoflush=False, expire_on_commit=False)
    return _SessionLocal


def create_schema() -> None:
    Base.metadata.create_all(engine())


def get_session() -> Iterator[Session]:
    with session_factory()() as session:
        yield session
