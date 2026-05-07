import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Index
from sqlalchemy.orm import mapped_column, Mapped
from ..database import Base


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dest_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    dest_port: Mapped[int | None] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw_log: Mapped[str | None] = mapped_column(Text)
    log_source: Mapped[str | None] = mapped_column(String(100), index=True)
    log_format: Mapped[str | None] = mapped_column(String(50))
    mitre_technique: Mapped[str | None] = mapped_column(String(20), index=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(100))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    username: Mapped[str | None] = mapped_column(String(255), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    country: Mapped[str | None] = mapped_column(String(100))
    city: Mapped[str | None] = mapped_column(String(100))
    _extra_fields: Mapped[str | None] = mapped_column("extra_fields", Text)

    __table_args__ = (
        Index("ix_events_timestamp_severity", "timestamp", "severity"),
        Index("ix_events_source_ip_timestamp", "source_ip", "timestamp"),
    )

    @property
    def extra_fields(self) -> dict:
        if self._extra_fields:
            return json.loads(self._extra_fields)
        return {}

    @extra_fields.setter
    def extra_fields(self, value: dict):
        self._extra_fields = json.dumps(value) if value else None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "event_type": self.event_type,
            "severity": self.severity,
            "message": self.message,
            "raw_log": self.raw_log,
            "log_source": self.log_source,
            "log_format": self.log_format,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "risk_score": self.risk_score,
            "username": self.username,
            "hostname": self.hostname,
            "country": self.country,
            "city": self.city,
            "extra_fields": self.extra_fields,
        }
