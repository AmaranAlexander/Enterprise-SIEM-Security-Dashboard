import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

EVENT_ID_MAP = {
    4624: ("successful_login", "info", None, None),
    4625: ("failed_login", "medium", "T1110", "credential-access"),
    4648: ("successful_login", "low", None, None),
    4672: ("privilege_escalation", "medium", "T1078", "privilege-escalation"),
    4688: ("process_creation", "low", None, None),
    4697: ("service_install", "high", "T1543", "persistence"),
    4698: ("scheduled_task", "medium", "T1053", "persistence"),
    4702: ("scheduled_task", "medium", "T1053", "persistence"),
    4719: ("audit_policy_change", "high", "T1562", "defense-evasion"),
    4720: ("account_created", "medium", "T1136", "persistence"),
    4726: ("account_deleted", "medium", None, None),
    4732: ("group_membership_change", "medium", "T1098", "persistence"),
    4740: ("account_lockout", "medium", "T1110", "credential-access"),
    4768: ("kerberos_ticket", "low", None, None),
    4776: ("credential_validation", "low", None, None),
    4798: ("group_enumeration", "medium", "T1087", "discovery"),
    4799: ("group_enumeration", "medium", "T1087", "discovery"),
    7045: ("service_install", "high", "T1543", "persistence"),
    1102: ("log_cleared", "critical", "T1070", "defense-evasion"),
    104:  ("log_cleared", "critical", "T1070", "defense-evasion"),
}

WINLOG_SIMPLE_RE = re.compile(
    r"EventID=(\d+).*?Computer=([^\s,]+).*?(?:SubjectUserName|TargetUserName)=([^\s,]+)",
    re.IGNORECASE | re.DOTALL,
)


def _find(elem, path: str, ns: dict) -> Optional[str]:
    found = elem.find(path, ns)
    return found.text if found is not None else None


def parse(raw: str) -> Optional[dict]:
    raw = raw.strip()

    try:
        root = ET.fromstring(raw)
        if "Event" not in root.tag:
            raise ValueError
    except ET.ParseError:
        m = WINLOG_SIMPLE_RE.search(raw)
        if not m:
            return None
        event_id = int(m.group(1))
        computer = m.group(2)
        username = m.group(3)
        return _build_event(event_id, computer, username, {}, raw)
    except ValueError:
        return None

    system = root.find("e:System", NS)
    if system is None:
        return None

    event_id_elem = system.find("e:EventID", NS)
    if event_id_elem is None:
        return None
    event_id = int(event_id_elem.text or 0)

    ts_str = _find(system, "e:TimeCreated", NS)
    if ts_str:
        try:
            timestamp = datetime.fromisoformat(ts_str.rstrip("Z"))
        except ValueError:
            timestamp = datetime.utcnow()
    else:
        timestamp = datetime.utcnow()

    computer = _find(system, "e:Computer", NS) or "unknown"
    channel = _find(system, "e:Channel", NS) or "Security"

    event_data = root.find("e:EventData", NS)
    fields = {}
    if event_data is not None:
        for data in event_data.findall("e:Data", NS):
            name = data.get("Name", "")
            fields[name] = data.text or ""

    username = (
        fields.get("TargetUserName") or
        fields.get("SubjectUserName") or
        fields.get("AccountName")
    )
    source_ip = fields.get("IpAddress") or fields.get("Workstation")
    if source_ip and source_ip in ("-", "::1", "127.0.0.1"):
        source_ip = None

    result = _build_event(event_id, computer, username, fields, raw)
    result["timestamp"] = timestamp
    if source_ip:
        result["source_ip"] = source_ip
    result["extra_fields"]["channel"] = channel
    result["extra_fields"].update(fields)
    return result


def _build_event(event_id: int, computer: str, username: Optional[str], fields: dict, raw: str) -> dict:
    mapping = EVENT_ID_MAP.get(event_id, ("windows_event", "info", None, None))
    event_type, severity, mitre_tech, mitre_tactic = mapping

    msg_parts = [f"Windows Event ID {event_id}: {event_type.replace('_', ' ').title()}"]
    if username and username not in ("-", "SYSTEM"):
        msg_parts.append(f"User: {username}")
    if fields.get("ProcessName"):
        msg_parts.append(f"Process: {fields['ProcessName']}")
    if fields.get("FailureReason"):
        msg_parts.append(f"Reason: {fields['FailureReason']}")

    return {
        "timestamp": datetime.utcnow(),
        "source_ip": None,
        "dest_ip": None,
        "source_port": None,
        "dest_port": None,
        "event_type": event_type,
        "severity": severity,
        "message": " | ".join(msg_parts),
        "raw_log": raw,
        "log_source": computer,
        "log_format": "windows",
        "mitre_technique": mitre_tech,
        "mitre_tactic": mitre_tactic,
        "username": username if username and username not in ("-", "SYSTEM") else None,
        "hostname": computer,
        "extra_fields": {"event_id": event_id},
    }
