"""
Aegis AI — Database Models
SQLAlchemy ORM models for all scan data, vulnerabilities, and reports.
"""
from datetime import datetime
from typing import Optional, List
from enum import Enum as PyEnum

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    Text, ForeignKey, JSON, Enum, Index, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class ScanStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnStatus(str, PyEnum):
    POSSIBLE = "possible"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


class ScanJob(Base):
    """Represents a complete scan job against a target."""
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True)
    target_url = Column(String, nullable=False, index=True)
    target_name = Column(String, nullable=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    scan_depth = Column(Integer, default=3)
    scan_types = Column(JSON, default=list)  # ["sqli", "xss", "headers", ...]
    authorized = Column(Boolean, default=False)

    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # Summary counts (denormalized for fast dashboard queries)
    total_endpoints = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Relationships
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    agent_logs = relationship("AgentLog", back_populates="scan", cascade="all, delete-orphan")
    report = relationship("Report", back_populates="scan", uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScanJob id={self.id} target={self.target_url} status={self.status}>"


class Endpoint(Base):
    """Represents a discovered endpoint during reconnaissance."""
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    url = Column(String, nullable=False)
    path = Column(String, nullable=False)
    method = Column(String, default="GET")
    status_code = Column(Integer, nullable=True)
    response_time_ms = Column(Float, nullable=True)
    content_type = Column(String, nullable=True)
    endpoint_type = Column(String, nullable=True)  # auth, upload, admin, api, etc.
    parameters = Column(JSON, default=list)
    forms = Column(JSON, default=list)
    technologies = Column(JSON, default=list)
    risk_score = Column(Float, default=0.0)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("ScanJob", back_populates="endpoints")
    vulnerabilities = relationship("Vulnerability", back_populates="endpoint")

    __table_args__ = (
        Index("idx_endpoint_scan_path", "scan_id", "path"),
    )


class Vulnerability(Base):
    """Represents a detected vulnerability."""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"), nullable=True)
    vuln_type = Column(String, nullable=False, index=True)
    severity = Column(Enum(Severity), nullable=False, index=True)
    status = Column(Enum(VulnStatus), default=VulnStatus.POSSIBLE)
    confidence = Column(Float, default=0.5)  # 0.0 - 1.0

    # Exploit details
    url = Column(String, nullable=False)
    parameter = Column(String, nullable=True)
    payload = Column(Text, nullable=True)
    http_method = Column(String, default="GET")

    # Response evidence
    response_code = Column(Integer, nullable=True)
    response_snippet = Column(Text, nullable=True)
    response_time_delta_ms = Column(Float, nullable=True)

    # Classification
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    cwe_id = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)

    # ML classifier output
    ml_prediction = Column(String, nullable=True)
    ml_confidence = Column(Float, nullable=True)
    anomaly_score = Column(Float, nullable=True)

    detected_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("ScanJob", back_populates="vulnerabilities")
    endpoint = relationship("Endpoint", back_populates="vulnerabilities")


class AgentLog(Base):
    """Audit log of all agent activities during a scan."""
    __tablename__ = "agent_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    agent_name = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    level = Column(String, default="INFO")
    timestamp = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanJob", back_populates="agent_logs")

    __table_args__ = (
        Index("idx_agent_log_scan_agent", "scan_id", "agent_name"),
    )


class Report(Base):
    """Generated security report for a scan."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scan_jobs.id"), unique=True, nullable=False)
    title = Column(String, nullable=False)
    executive_summary = Column(Text, nullable=True)
    methodology = Column(Text, nullable=True)
    risk_rating = Column(String, nullable=True)

    # Report file paths
    pdf_path = Column(String, nullable=True)
    json_path = Column(String, nullable=True)
    markdown_path = Column(String, nullable=True)

    generated_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanJob", back_populates="report")


def init_db(database_url: str):
    """Initialize database and create all tables."""
    from pathlib import Path
    # Ensure directory exists for SQLite
    if "sqlite" in database_url:
        db_path = database_url.replace("sqlite:///", "").replace("sqlite+aiosqlite:///", "")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        database_url.replace("+aiosqlite", ""),
        echo=False,
        connect_args={"check_same_thread": False} if "sqlite" in database_url else {}
    )
    Base.metadata.create_all(engine)
    return engine
