"""
database.py — SQLite ORM with SQLAlchemy for storing NIDS alerts.

Provides:
  - AlertRecord model mapped to 'alerts' table
  - DatabaseManager class for CRUD + pruning + analytical queries
  - Thread-safe session management via scoped_session
"""

import os
import datetime
from typing import Optional

from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Float, Text,
    desc, func, inspect, select
)
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

# Declarative base for ORM models
Base = declarative_base()


class AlertRecord(Base):
    """ORM model representing a single detection alert stored in SQLite."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.datetime.now(datetime.UTC), index=True)
    src_ip = Column(String(45), nullable=False, index=True)        # IPv4 or IPv6
    dst_ip = Column(String(45), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)                   # TCP, UDP, ICMP, ARP …
    attack_type = Column(String(50), nullable=False, index=True)   # port_scan, syn_flood …
    severity = Column(String(10), nullable=False)                  # LOW / MEDIUM / HIGH / CRITICAL
    description = Column(Text, nullable=True)                      # Human-readable summary
    raw_packet = Column(Text, nullable=True)                       # Optional hex dump
    detection_source = Column(String(20), nullable=True)           # rule_engine / ml_detector
    confidence = Column(Float, nullable=True)                      # ML confidence score 0-1

    def __repr__(self) -> str:
        return (
            f"<Alert #{self.id} {self.attack_type} "
            f"{self.src_ip}->{self.dst_ip} [{self.severity}]>"
        )

    def to_dict(self) -> dict:
        """Serialize record to a plain dictionary for JSON / dashboard use."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "description": self.description,
            "detection_source": self.detection_source,
            "confidence": self.confidence,
        }


class DatabaseManager:
    """
    Manages all database interactions for the NIDS.

    Usage:
        db = DatabaseManager("data/nids_alerts.db")
        db.insert_alert(src_ip="10.0.0.1", attack_type="port_scan", severity="HIGH")
        recent = db.get_recent_alerts(limit=20)
        db.close()
    """

    def __init__(self, db_path: str = "data/nids_alerts.db", echo: bool = False,
                 max_alerts: int = 100_000):
        # Ensure parent directory exists
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)

        self.db_path = db_path
        self.max_alerts = max_alerts

        # SQLite connection string; check_same_thread=False needed for multi-thread access
        engine_url = f"sqlite:///{db_path}"
        self.engine = create_engine(engine_url, echo=echo,
                                    connect_args={"check_same_thread": False})

        # Create tables if they don't exist yet
        Base.metadata.create_all(self.engine)

        # scoped_session ensures each thread gets its own session
        session_factory = sessionmaker(bind=self.engine)
        self.Session = scoped_session(session_factory)

    # ------------------------------------------------------------------
    # INSERT
    # ------------------------------------------------------------------
    def insert_alert(
        self,
        src_ip: str,
        attack_type: str,
        severity: str,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        description: Optional[str] = None,
        raw_packet: Optional[str] = None,
        detection_source: Optional[str] = None,
        confidence: Optional[float] = None,
        timestamp: Optional[datetime.datetime] = None,
    ) -> AlertRecord:
        """Insert a new alert and return the created record."""
        session = self.Session()
        try:
            record = AlertRecord(
                timestamp=timestamp or datetime.datetime.now(datetime.UTC),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                attack_type=attack_type,
                severity=severity,
                description=description,
                raw_packet=raw_packet,
                detection_source=detection_source,
                confidence=confidence,
            )
            session.add(record)
            session.commit()
            # Refresh to populate auto-generated fields (id, default timestamp)
            session.refresh(record)
            return record
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    # ------------------------------------------------------------------
    # READ
    # ------------------------------------------------------------------
    def get_recent_alerts(self, limit: int = 20) -> list[AlertRecord]:
        """Return the N most recent alerts, newest first."""
        session = self.Session()
        try:
            return (
                session.query(AlertRecord)
                .order_by(desc(AlertRecord.timestamp))
                .limit(limit)
                .all()
            )
        finally:
            self.Session.remove()

    def get_alerts_by_type(self, attack_type: str, limit: int = 50) -> list[AlertRecord]:
        """Retrieve alerts filtered by attack type."""
        session = self.Session()
        try:
            return (
                session.query(AlertRecord)
                .filter(AlertRecord.attack_type == attack_type)
                .order_by(desc(AlertRecord.timestamp))
                .limit(limit)
                .all()
            )
        finally:
            self.Session.remove()

    def get_alerts_by_severity(self, severity: str, limit: int = 50) -> list[AlertRecord]:
        """Retrieve alerts filtered by severity level."""
        session = self.Session()
        try:
            return (
                session.query(AlertRecord)
                .filter(AlertRecord.severity == severity)
                .order_by(desc(AlertRecord.timestamp))
                .limit(limit)
                .all()
            )
        finally:
            self.Session.remove()

    def get_alerts_since(self, since: datetime.datetime) -> list[AlertRecord]:
        """Return all alerts after the given timestamp."""
        session = self.Session()
        try:
            return (
                session.query(AlertRecord)
                .filter(AlertRecord.timestamp >= since)
                .order_by(desc(AlertRecord.timestamp))
                .all()
            )
        finally:
            self.Session.remove()

    # ------------------------------------------------------------------
    # ANALYTICS
    # ------------------------------------------------------------------
    def count_alerts(self) -> int:
        """Total number of stored alerts."""
        session = self.Session()
        try:
            return session.query(func.count(AlertRecord.id)).scalar() or 0
        finally:
            self.Session.remove()

    def count_by_attack_type(self) -> dict[str, int]:
        """Return {attack_type: count} mapping."""
        session = self.Session()
        try:
            rows = (
                session.query(AlertRecord.attack_type, func.count(AlertRecord.id))
                .group_by(AlertRecord.attack_type)
                .all()
            )
            return {row[0]: row[1] for row in rows}
        finally:
            self.Session.remove()

    def count_by_severity(self) -> dict[str, int]:
        """Return {severity: count} mapping."""
        session = self.Session()
        try:
            rows = (
                session.query(AlertRecord.severity, func.count(AlertRecord.id))
                .group_by(AlertRecord.severity)
                .all()
            )
            return {row[0]: row[1] for row in rows}
        finally:
            self.Session.remove()

    def top_source_ips(self, limit: int = 10) -> list[tuple[str, int]]:
        """Return top source IPs by alert count."""
        session = self.Session()
        try:
            rows = (
                session.query(AlertRecord.src_ip, func.count(AlertRecord.id).label("cnt"))
                .group_by(AlertRecord.src_ip)
                .order_by(desc("cnt"))
                .limit(limit)
                .all()
            )
            return [(row[0], row[1]) for row in rows]
        finally:
            self.Session.remove()

    # ------------------------------------------------------------------
    # MAINTENANCE
    # ------------------------------------------------------------------
    def prune_old_alerts(self) -> int:
        """Delete oldest alerts if total exceeds max_alerts. Returns rows deleted."""
        total = self.count_alerts()
        if total <= self.max_alerts:
            return 0

        excess = total - self.max_alerts
        session = self.Session()
        try:
            # Find the ids of the oldest excess alerts to delete
            oldest_ids = (
                session.query(AlertRecord.id)
                .order_by(AlertRecord.id)
                .limit(excess)
                .all()
            )
            ids_to_delete = [row[0] for row in oldest_ids]
            deleted = (
                session.query(AlertRecord)
                .filter(AlertRecord.id.in_(ids_to_delete))
                .delete(synchronize_session="fetch")
            )
            session.commit()
            return deleted
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def close(self):
        """Dispose of the engine and release all connections."""
        self.Session.remove()
        self.engine.dispose()
