import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import mapped_column, Mapped
from ..database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(20))
    mitre_tactic: Mapped[str | None] = mapped_column(String(100))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    _source_ips: Mapped[str | None] = mapped_column("source_ips", Text)
    _affected_users: Mapped[str | None] = mapped_column("affected_users", Text)
    _event_ids: Mapped[str | None] = mapped_column("event_ids", Text)

    @property
    def source_ips(self) -> list[str]:
        return json.loads(self._source_ips) if self._source_ips else []

    @source_ips.setter
    def source_ips(self, value: list[str]):
        self._source_ips = json.dumps(list(set(value))) if value else "[]"

    @property
    def affected_users(self) -> list[str]:
        return json.loads(self._affected_users) if self._affected_users else []

    @affected_users.setter
    def affected_users(self, value: list[str]):
        self._affected_users = json.dumps(list(set(v for v in value if v))) if value else "[]"

    @property
    def event_ids(self) -> list[int]:
        return json.loads(self._event_ids) if self._event_ids else []

    @event_ids.setter
    def event_ids(self, value: list[int]):
        self._event_ids = json.dumps(value) if value else "[]"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "risk_score": self.risk_score,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "source_ips": self.source_ips,
            "affected_users": self.affected_users,
            "event_ids": self.event_ids,
        }
