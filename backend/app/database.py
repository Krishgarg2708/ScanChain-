from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import datetime

DATABASE_URL = "sqlite:///./scanchain.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="developer")  # admin, analyst, developer, viewer


class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    source_type = Column(String)  # upload, git
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    scans = relationship("Scan", back_populates="project")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    status = Column(String, default="queued")  # queued, running, completed, failed
    risk_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    summary_json = Column(Text, default="{}")
    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    scanner = Column(String)  # dependency, secrets, binary, license, container
    severity = Column(String)  # critical, high, medium, low, info
    title = Column(String)
    description = Column(Text)
    location = Column(String, nullable=True)
    cve_id = Column(String, nullable=True)
    cvss = Column(Float, nullable=True)
    remediation = Column(Text, nullable=True)
    scan = relationship("Scan", back_populates="findings")


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"
    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String)
    repo_url = Column(String)
    interval_minutes = Column(Integer, default=1440)  # default: daily
    enabled = Column(Integer, default=1)
    last_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
