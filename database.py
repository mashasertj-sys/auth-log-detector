from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone

Base = declarative_base()


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(10), unique=True, index=True)
    rule_name = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    indicator = Column(String(100), nullable=False)
    count = Column(Integer, default=1)
    technique = Column(String(20))
    description = Column(Text)
    is_new = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# Создаем движок и сессию
engine = create_engine("sqlite:///security_alerts.db", echo=False)
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()