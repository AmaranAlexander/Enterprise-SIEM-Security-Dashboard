import yaml
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_, func
from ..models.event import Event
from ..models.alert import Alert
from ..config import settings

logger = logging.getLogger(__name__)


def load_rules() -> list[dict]:
    rules = []
    rules_path = Path(settings.rules_dir)
    for yaml_file in rules_path.glob("*.yaml"):
        try:
            with open(yaml_file) as f:
                rule = yaml.safe_load(f)
                rules.append(rule)
        except Exception as e:
            logger.error(f"Failed to load rule {yaml_file}: {e}")
    return rules


def _query_events_in_window(
    db: Session,
    event_type: str,
    window_minutes: int,
    group_by: str,
    group_value: str,
    reference_time: Optional[datetime] = None,
) -> list[Event]:
    ref = reference_time or datetime.utcnow()
    since = ref - timedelta(minutes=window_minutes)

    query = db.query(Event).filter(
        Event.event_type == event_type,
        Event.timestamp >= since,
        Event.timestamp <= ref,
    )

    if group_by == "source_ip":
        query = query.filter(Event.source_ip == group_value)
    elif group_by == "username":
        query = query.filter(Event.username == group_value)
    elif group_by == "hostname":
        query = query.filter(Event.hostname == group_value)

    return query.order_by(Event.timestamp).all()


def _alert_exists(db: Session, rule_id: str, group_value: str, window_minutes: int) -> bool:
    since = datetime.utcnow() - timedelta(minutes=window_minutes * 2)
    existing = db.query(Alert).filter(
        Alert.rule_id == rule_id,
        Alert.last_seen >= since,
        Alert.status.in_(["open", "acknowledged"]),
    ).first()

    if existing and group_value in (existing.source_ips + existing.affected_users):
        return True
    return False


def _evaluate_brute_force(db: Session, rule: dict, events: list[Event]) -> list[dict]:
    conditions = rule["conditions"]
    fail_cond = next((c for c in conditions if c["event_type"] == "failed_login"), None)
    ok_cond = next((c for c in conditions if c["event_type"] == "successful_login"), None)

    if not fail_cond or not ok_cond:
        return []

    window = fail_cond.get("window_minutes", 10)
    min_fails = fail_cond.get("min_count", 5)
    triggers = []

    # Group failed logins by source IP
    by_ip: dict[str, list[Event]] = {}
    for e in events:
        if e.source_ip and e.event_type == "failed_login":
            by_ip.setdefault(e.source_ip, []).append(e)

    for ip, failed_all in by_ip.items():
        # Slide window over the failed events to find windows with enough failures
        failed_sorted = sorted(failed_all, key=lambda e: e.timestamp)
        window_delta = timedelta(minutes=window)

        i = 0
        while i < len(failed_sorted):
            window_start = failed_sorted[i].timestamp
            window_end = window_start + window_delta
            failed_in_window = [e for e in failed_sorted if window_start <= e.timestamp <= window_end]

            if len(failed_in_window) >= min_fails:
                # Look for successful login within the same window from same IP (from all events)
                success_in_window = [
                    e for e in events
                    if e.source_ip == ip
                    and e.event_type == "successful_login"
                    and window_start <= e.timestamp <= window_end + window_delta
                ]
                if len(success_in_window) >= ok_cond.get("min_count", 1):
                    all_evs = failed_in_window + success_in_window
                    users = list(set(e.username for e in all_evs if e.username))
                    triggers.append({
                        "group_value": ip,
                        "event_ids": [e.id for e in all_evs],
                        "source_ips": [ip],
                        "affected_users": users,
                        "event_count": len(all_evs),
                        "failed_count": len(failed_in_window),
                        "template_vars": {
                            "source_ip": ip,
                            "failed_count": len(failed_in_window),
                            "window": window,
                        },
                        "first_seen": min(e.timestamp for e in all_evs),
                        "last_seen": max(e.timestamp for e in all_evs),
                    })
                    break  # one alert per IP
            i += max(1, len(failed_in_window))

    return triggers


def _evaluate_port_scan(db: Session, rule: dict, events: list[Event]) -> list[dict]:
    condition = rule["conditions"][0]
    min_count = condition.get("min_count", 10)

    source_ips = set(e.source_ip for e in events if e.source_ip and e.event_type == "port_scan")
    triggers = []

    for ip in source_ips:
        scan_events = [e for e in events if e.source_ip == ip and e.event_type == "port_scan"]
        if len(scan_events) >= min_count:
            triggers.append({
                "group_value": ip,
                "event_ids": [e.id for e in scan_events],
                "source_ips": [ip],
                "affected_users": [],
                "event_count": len(scan_events),
                "template_vars": {
                    "source_ip": ip,
                    "event_count": len(scan_events),
                    "window": condition.get("window_minutes", 5),
                },
                "first_seen": min(e.timestamp for e in scan_events),
                "last_seen": max(e.timestamp for e in scan_events),
            })

    return triggers


def _evaluate_priv_esc(db: Session, rule: dict, events: list[Event]) -> list[dict]:
    condition = rule["conditions"][0]
    triggers = []

    priv_events = [e for e in events if e.event_type == "privilege_escalation"]
    by_user: dict[str, list[Event]] = {}
    for e in priv_events:
        key = e.username or e.source_ip or "unknown"
        by_user.setdefault(key, []).append(e)

    for user, user_events in by_user.items():
        if len(user_events) >= condition.get("min_count", 1):
            hostname = user_events[0].hostname or "unknown"
            triggers.append({
                "group_value": user,
                "event_ids": [e.id for e in user_events],
                "source_ips": list(set(e.source_ip for e in user_events if e.source_ip)),
                "affected_users": [user],
                "event_count": len(user_events),
                "template_vars": {"username": user, "hostname": hostname},
                "first_seen": min(e.timestamp for e in user_events),
                "last_seen": max(e.timestamp for e in user_events),
            })

    return triggers


def _evaluate_lateral_movement(db: Session, rule: dict, events: list[Event]) -> list[dict]:
    condition = rule["conditions"][0]
    min_count = condition.get("min_count", 3)
    distinct_dest_min = condition.get("distinct_dest_min", 3)

    source_ips = set(e.source_ip for e in events if e.source_ip and e.event_type == "successful_login")
    triggers = []

    for ip in source_ips:
        login_events = [e for e in events if e.source_ip == ip and e.event_type == "successful_login"]
        distinct_dests = set(e.dest_ip or e.hostname for e in login_events if (e.dest_ip or e.hostname))

        if len(login_events) >= min_count and len(distinct_dests) >= distinct_dest_min:
            users = list(set(e.username for e in login_events if e.username))
            triggers.append({
                "group_value": ip,
                "event_ids": [e.id for e in login_events],
                "source_ips": [ip],
                "affected_users": users,
                "event_count": len(login_events),
                "template_vars": {
                    "source_ip": ip,
                    "dest_count": len(distinct_dests),
                },
                "first_seen": min(e.timestamp for e in login_events),
                "last_seen": max(e.timestamp for e in login_events),
            })

    return triggers


EVALUATORS = {
    "brute_force_001": _evaluate_brute_force,
    "port_scan_001": _evaluate_port_scan,
    "priv_esc_001": _evaluate_priv_esc,
    "lateral_movement_001": _evaluate_lateral_movement,
}


def run_correlation(db: Session, lookback_minutes: int = 60) -> list[Alert]:
    rules = load_rules()
    new_alerts = []
    since = datetime.utcnow() - timedelta(minutes=lookback_minutes)
    recent_events = db.query(Event).filter(Event.timestamp >= since).all()

    for rule in rules:
        rule_id = rule["id"]
        evaluator = EVALUATORS.get(rule_id)
        if not evaluator:
            continue

        try:
            triggers = evaluator(db, rule, recent_events)
        except Exception as e:
            logger.error(f"Error evaluating rule {rule_id}: {e}")
            continue

        for trigger in triggers:
            if _alert_exists(db, rule_id, trigger["group_value"], lookback_minutes):
                continue

            template = rule.get("alert_template", rule["name"])
            try:
                title = template.format(**trigger.get("template_vars", {}))
            except KeyError:
                title = rule["name"]

            alert = Alert(
                rule_id=rule_id,
                title=title,
                description=rule["description"].strip(),
                severity=rule["severity"],
                status="open",
                mitre_technique=rule.get("mitre_technique"),
                mitre_tactic=rule.get("mitre_tactic"),
                risk_score=rule.get("risk_score", 50),
                event_count=trigger["event_count"],
                first_seen=trigger["first_seen"],
                last_seen=trigger["last_seen"],
            )
            alert.source_ips = trigger["source_ips"]
            alert.affected_users = trigger["affected_users"]
            alert.event_ids = trigger["event_ids"]

            db.add(alert)
            new_alerts.append(alert)

    if new_alerts:
        db.commit()

    return new_alerts
