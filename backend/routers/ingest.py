from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ..database import get_db
from ..services.ingestion import ingest_batch
from ..services.correlation import run_correlation

router = APIRouter(prefix="/api/ingest", tags=["ingest"])


class LogBatch(BaseModel):
    lines: list[str]
    format: Optional[str] = None
    run_correlation: bool = True


class SingleLog(BaseModel):
    raw: str
    format: Optional[str] = None


def _run_correlation_task(db_factory):
    db = db_factory()
    try:
        run_correlation(db, lookback_minutes=60)
    finally:
        db.close()


@router.post("")
def ingest_logs(
    batch: LogBatch,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    if len(batch.lines) > 10000:
        raise HTTPException(status_code=400, detail="Maximum 10,000 lines per batch")

    events = ingest_batch(batch.lines, db, force_format=batch.format)

    if batch.run_correlation and events:
        from ..database import SessionLocal
        background_tasks.add_task(_run_correlation_task, SessionLocal)

    return {
        "ingested": len(events),
        "failed": len(batch.lines) - len(events),
        "event_ids": [e.id for e in events],
    }


@router.post("/single")
def ingest_single(log: SingleLog, db: Session = Depends(get_db)):
    events = ingest_batch([log.raw], db, force_format=log.format)
    if not events:
        raise HTTPException(status_code=422, detail="Could not parse log line")
    return events[0].to_dict()


@router.post("/correlate")
def trigger_correlation(
    lookback_minutes: int = 60,
    db: Session = Depends(get_db),
):
    alerts = run_correlation(db, lookback_minutes=lookback_minutes)
    return {
        "new_alerts": len(alerts),
        "alert_ids": [a.id for a in alerts],
    }
