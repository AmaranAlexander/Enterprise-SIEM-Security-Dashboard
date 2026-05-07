from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import and_
from ..database import get_db
from ..models.alert import Alert
from ..models.event import Event

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

VALID_STATUSES = {"open", "acknowledged", "closed", "false_positive"}


class AlertUpdate(BaseModel):
    status: str


@router.get("")
def list_alerts(
    status: Optional[list[str]] = Query(default=None),
    severity: Optional[list[str]] = Query(default=None),
    rule_id: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    q = db.query(Alert)
    filters = []

    if status:
        filters.append(Alert.status.in_(status))
    if severity:
        filters.append(Alert.severity.in_(severity))
    if rule_id:
        filters.append(Alert.rule_id == rule_id)

    if filters:
        q = q.filter(and_(*filters))

    total = q.count()
    alerts = q.order_by(Alert.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "alerts": [a.to_dict() for a in alerts],
    }


@router.get("/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.to_dict()


@router.patch("/{alert_id}")
def update_alert(alert_id: int, update: AlertUpdate, db: Session = Depends(get_db)):
    if update.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {VALID_STATUSES}")

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = update.status
    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert.to_dict()


@router.get("/{alert_id}/events")
def get_alert_events(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    event_ids = alert.event_ids
    if not event_ids:
        return {"events": []}

    events = db.query(Event).filter(Event.id.in_(event_ids)).order_by(Event.timestamp.desc()).all()
    return {"events": [e.to_dict() for e in events]}
