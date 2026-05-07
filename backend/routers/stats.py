from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from ..database import get_db
from ..models.event import Event
from ..models.alert import Alert
from ..services.correlation import load_rules

router = APIRouter(prefix="/api/stats", tags=["stats"])


def _get_time_range(hours: int) -> datetime:
    return datetime.utcnow() - timedelta(hours=hours)


@router.get("/summary")
def get_summary(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    total_events = db.query(func.count(Event.id)).scalar() or 0
    events_today = db.query(func.count(Event.id)).filter(Event.timestamp >= today_start).scalar() or 0
    events_24h = db.query(func.count(Event.id)).filter(Event.timestamp >= last_24h).scalar() or 0
    events_7d = db.query(func.count(Event.id)).filter(Event.timestamp >= last_7d).scalar() or 0

    open_alerts = db.query(func.count(Alert.id)).filter(Alert.status == "open").scalar() or 0
    critical_alerts = db.query(func.count(Alert.id)).filter(
        Alert.status == "open", Alert.severity == "critical"
    ).scalar() or 0

    severity_counts = dict(
        db.query(Event.severity, func.count(Event.id))
        .filter(Event.timestamp >= last_24h)
        .group_by(Event.severity)
        .all()
    )

    critical_events_24h = severity_counts.get("critical", 0)
    high_events_24h = severity_counts.get("high", 0)

    unique_sources_24h = db.query(func.count(func.distinct(Event.source_ip))).filter(
        Event.timestamp >= last_24h, Event.source_ip.isnot(None)
    ).scalar() or 0

    return {
        "total_events": total_events,
        "events_today": events_today,
        "events_24h": events_24h,
        "events_7d": events_7d,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "critical_events_24h": critical_events_24h,
        "high_events_24h": high_events_24h,
        "unique_sources_24h": unique_sources_24h,
        "severity_breakdown": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
        },
        "generated_at": now.isoformat(),
    }


@router.get("/timeline")
def get_timeline(
    hours: int = Query(default=24, ge=1, le=168),
    bucket_minutes: int = Query(default=60, ge=5, le=1440),
    db: Session = Depends(get_db),
):
    since = datetime.utcnow() - timedelta(hours=hours)
    events = (
        db.query(Event.timestamp, Event.severity)
        .filter(Event.timestamp >= since)
        .order_by(Event.timestamp)
        .all()
    )

    buckets: dict[str, dict] = {}
    bucket_delta = timedelta(minutes=bucket_minutes)

    for ts, severity in events:
        bucket_time = ts - timedelta(
            minutes=ts.minute % bucket_minutes,
            seconds=ts.second,
            microseconds=ts.microsecond,
        )
        key = bucket_time.isoformat()
        if key not in buckets:
            buckets[key] = {"time": key, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        buckets[key][severity] = buckets[key].get(severity, 0) + 1
        buckets[key]["total"] += 1

    return {"timeline": sorted(buckets.values(), key=lambda x: x["time"])}


@router.get("/top-sources")
def get_top_sources(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=10, ge=1, le=50),
    db: Session = Depends(get_db),
):
    since = _get_time_range(hours)
    rows = (
        db.query(
            Event.source_ip,
            Event.country,
            func.count(Event.id).label("event_count"),
            func.avg(Event.risk_score).label("avg_risk"),
            func.max(Event.risk_score).label("max_risk"),
        )
        .filter(Event.timestamp >= since, Event.source_ip.isnot(None))
        .group_by(Event.source_ip, Event.country)
        .order_by(func.count(Event.id).desc())
        .limit(limit)
        .all()
    )

    return {
        "sources": [
            {
                "source_ip": r.source_ip,
                "country": r.country,
                "event_count": r.event_count,
                "avg_risk_score": round(r.avg_risk or 0, 1),
                "max_risk_score": round(r.max_risk or 0, 1),
            }
            for r in rows
        ]
    }


@router.get("/event-types")
def get_event_types(hours: int = Query(default=24, ge=1, le=168), db: Session = Depends(get_db)):
    since = _get_time_range(hours)
    rows = (
        db.query(Event.event_type, func.count(Event.id).label("count"))
        .filter(Event.timestamp >= since)
        .group_by(Event.event_type)
        .order_by(func.count(Event.id).desc())
        .all()
    )
    return {"event_types": [{"type": r.event_type, "count": r.count} for r in rows]}


@router.get("/mitre-coverage")
def get_mitre_coverage(hours: int = Query(default=168, ge=1, le=720), db: Session = Depends(get_db)):
    since = _get_time_range(hours)
    rows = (
        db.query(
            Event.mitre_technique,
            Event.mitre_tactic,
            func.count(Event.id).label("event_count"),
        )
        .filter(Event.timestamp >= since, Event.mitre_technique.isnot(None))
        .group_by(Event.mitre_technique, Event.mitre_tactic)
        .order_by(func.count(Event.id).desc())
        .all()
    )

    rules = load_rules()
    rule_techniques = {r.get("mitre_technique"): r for r in rules if r.get("mitre_technique")}

    coverage = []
    for r in rows:
        rule = rule_techniques.get(r.mitre_technique, {})
        coverage.append({
            "technique": r.mitre_technique,
            "tactic": r.mitre_tactic,
            "event_count": r.event_count,
            "has_rule": r.mitre_technique in rule_techniques,
            "rule_name": rule.get("name", ""),
        })

    return {"coverage": coverage, "total_techniques": len(coverage)}


@router.get("/investigation/ip/{ip_address}")
def investigate_ip(ip_address: str, hours: int = Query(default=168), db: Session = Depends(get_db)):
    since = _get_time_range(hours)

    events = (
        db.query(Event)
        .filter(Event.source_ip == ip_address, Event.timestamp >= since)
        .order_by(Event.timestamp.desc())
        .limit(200)
        .all()
    )

    event_type_counts = {}
    severity_counts = {}
    for e in events:
        event_type_counts[e.event_type] = event_type_counts.get(e.event_type, 0) + 1
        severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1

    alerts = (
        db.query(Alert)
        .filter(Alert._source_ips.ilike(f'%"{ip_address}"%'))
        .order_by(Alert.created_at.desc())
        .all()
    )

    first_event = events[-1] if events else None
    return {
        "ip_address": ip_address,
        "country": first_event.country if first_event else None,
        "city": first_event.city if first_event else None,
        "total_events": len(events),
        "event_type_breakdown": event_type_counts,
        "severity_breakdown": severity_counts,
        "first_seen": events[-1].timestamp.isoformat() if events else None,
        "last_seen": events[0].timestamp.isoformat() if events else None,
        "associated_alerts": [a.to_dict() for a in alerts],
        "recent_events": [e.to_dict() for e in events[:50]],
    }


@router.get("/investigation/user/{username}")
def investigate_user(username: str, hours: int = Query(default=168), db: Session = Depends(get_db)):
    since = _get_time_range(hours)

    events = (
        db.query(Event)
        .filter(Event.username == username, Event.timestamp >= since)
        .order_by(Event.timestamp.desc())
        .limit(200)
        .all()
    )

    source_ips = list(set(e.source_ip for e in events if e.source_ip))
    event_type_counts = {}
    for e in events:
        event_type_counts[e.event_type] = event_type_counts.get(e.event_type, 0) + 1

    return {
        "username": username,
        "total_events": len(events),
        "unique_source_ips": source_ips,
        "event_type_breakdown": event_type_counts,
        "first_seen": events[-1].timestamp.isoformat() if events else None,
        "last_seen": events[0].timestamp.isoformat() if events else None,
        "recent_events": [e.to_dict() for e in events[:50]],
    }
