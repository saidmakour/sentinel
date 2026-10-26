from sqlalchemy import create_engine

from sentinel.config.settings import settings

engine = create_engine(
    settings.database_url,
    future=True,
    echo=False,
    pool_pre_ping=True,
)
