from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..database import get_db
from ..models.alert import Alert
from ..services.correlation import load_rules

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("")
def list_rules(db: Session = Depends(get_db)):
    rules = load_rules()

    alert_counts = dict(
        db.query(Alert.rule_id, func.count(Alert.id))
        .group_by(Alert.rule_id)
        .all()
    )
    open_alert_counts = dict(
        db.query(Alert.rule_id, func.count(Alert.id))
        .filter(Alert.status == "open")
        .group_by(Alert.rule_id)
        .all()
    )

    result = []
    for rule in rules:
        rule_id = rule["id"]
        conditions = rule.get("conditions", [])
        condition_summary = []
        for c in conditions:
            parts = []
            if c.get("min_count"):
                parts.append(f"≥{c['min_count']} {c['event_type'].replace('_', ' ')} events")
            if c.get("window_minutes"):
                parts.append(f"within {c['window_minutes']} min")
            if c.get("group_by"):
                parts.append(f"per {c['group_by']}")
            if c.get("distinct_dest_min"):
                parts.append(f"to ≥{c['distinct_dest_min']} distinct destinations")
            condition_summary.append(" ".join(parts))

        result.append({
            "id": rule_id,
            "name": rule["name"],
            "description": rule.get("description", "").strip(),
            "mitre_technique": rule.get("mitre_technique"),
            "mitre_tactic": rule.get("mitre_tactic"),
            "severity": rule["severity"],
            "risk_score": rule.get("risk_score", 50),
            "total_alerts": alert_counts.get(rule_id, 0),
            "open_alerts": open_alert_counts.get(rule_id, 0),
            "conditions": conditions,
            "condition_summary": condition_summary,
        })

    return {"rules": result, "total": len(result)}
