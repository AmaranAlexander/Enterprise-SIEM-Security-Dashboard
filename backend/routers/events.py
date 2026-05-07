import csv
import io
import json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from ..database import get_db
from ..models.event import Event

router = APIRouter(prefix="/api/events", tags=["events"])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _build_query(
    db: Session,
    start_time: Optional[str],
    end_time: Optional[str],
    severity: Optional[list[str]],
    source_ip: Optional[str],
    event_type: Optional[str],
    mitre_technique: Optional[str],
    search: Optional[str],
    log_source: Optional[str],
):
    q = db.query(Event)
    filters = []

    if start_time:
        try:
            filters.append(Event.timestamp >= datetime.fromisoformat(start_time))
        except ValueError:
            pass
    if end_time:
        try:
            filters.append(Event.timestamp <= datetime.fromisoformat(end_time))
        except ValueError:
            pass
    if severity:
        filters.append(Event.severity.in_(severity))
    if source_ip:
        filters.append(Event.source_ip == source_ip)
    if event_type:
        filters.append(Event.event_type == event_type)
    if mitre_technique:
        filters.append(Event.mitre_technique == mitre_technique)
    if log_source:
        filters.append(Event.log_source == log_source)
    if search:
        filters.append(
            or_(
                Event.message.ilike(f"%{search}%"),
                Event.source_ip.ilike(f"%{search}%"),
                Event.username.ilike(f"%{search}%"),
                Event.hostname.ilike(f"%{search}%"),
            )
        )

    if filters:
        q = q.filter(and_(*filters))

    return q


@router.get("")
def list_events(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    severity: Optional[list[str]] = Query(default=None),
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    search: Optional[str] = None,
    log_source: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    q = _build_query(db, start_time, end_time, severity, source_ip, event_type, mitre_technique, search, log_source)
    total = q.count()
    events = q.order_by(Event.timestamp.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "events": [e.to_dict() for e in events],
    }


@router.get("/export")
def export_events(
    format: str = Query(default="csv", regex="^(csv|json)$"),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    severity: Optional[list[str]] = Query(default=None),
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = _build_query(db, start_time, end_time, severity, source_ip, event_type, None, None, None)
    events = q.order_by(Event.timestamp.desc()).limit(10000).all()

    if format == "json":
        content = json.dumps([e.to_dict() for e in events], indent=2)
        return StreamingResponse(
            io.StringIO(content),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=events.json"},
        )

    output = io.StringIO()
    fields = ["id", "timestamp", "source_ip", "dest_ip", "event_type", "severity",
              "message", "mitre_technique", "mitre_tactic", "risk_score", "username", "country"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for e in events:
        writer.writerow(e.to_dict())

    output.seek(0)
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"},
    )


@router.get("/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    related = (
        db.query(Event)
        .filter(
            Event.id != event_id,
            or_(
                Event.source_ip == event.source_ip if event.source_ip else False,
                Event.username == event.username if event.username else False,
            ),
            Event.timestamp >= event.timestamp - timedelta(hours=1),
            Event.timestamp <= event.timestamp + timedelta(hours=1),
        )
        .order_by(Event.timestamp.desc())
        .limit(10)
        .all()
    )

    result = event.to_dict()
    result["related_events"] = [e.to_dict() for e in related]
    return result
