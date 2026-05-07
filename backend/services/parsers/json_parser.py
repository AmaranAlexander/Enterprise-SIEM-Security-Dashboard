import json
from datetime import datetime
from typing import Optional

FIELD_ALIASES = {
    "timestamp": ["timestamp", "time", "ts", "@timestamp", "datetime", "event_time"],
    "source_ip": ["source_ip", "src_ip", "src", "sourceIp", "source", "client_ip", "remote_addr"],
    "dest_ip": ["dest_ip", "dst_ip", "dst", "destIp", "destination", "server_ip"],
    "source_port": ["source_port", "src_port", "spt", "sourcePort"],
    "dest_port": ["dest_port", "dst_port", "dpt", "destPort", "port"],
    "event_type": ["event_type", "type", "action", "eventType", "event_name", "category"],
    "severity": ["severity", "level", "priority", "sev"],
    "message": ["message", "msg", "description", "log", "text", "summary"],
    "username": ["username", "user", "user_name", "userId", "account"],
    "hostname": ["hostname", "host", "server", "device"],
}

SEVERITY_NORM = {
    "debug": "info", "trace": "info", "verbose": "info",
    "info": "info", "information": "info", "notice": "low",
    "warn": "low", "warning": "low",
    "error": "high", "err": "high",
    "crit": "critical", "critical": "critical", "fatal": "critical", "emerg": "critical",
    "medium": "medium", "high": "high", "low": "low",
}

EVENT_TYPE_MITRE = {
    "failed_login": ("T1110", "credential-access"),
    "brute_force": ("T1110", "credential-access"),
    "successful_login": (None, None),
    "port_scan": ("T1046", "discovery"),
    "sql_injection": ("T1190", "initial-access"),
    "xss": ("T1190", "initial-access"),
    "malware": ("T1204", "execution"),
    "privilege_escalation": ("T1078", "privilege-escalation"),
    "lateral_movement": ("T1021", "lateral-movement"),
    "data_exfiltration": ("T1041", "exfiltration"),
}


def _get_field(data: dict, aliases: list[str]):
    for alias in aliases:
        if alias in data:
            return data[alias]
    return None


def _parse_timestamp(val) -> datetime:
    if isinstance(val, (int, float)):
        try:
            ts = val / 1000 if val > 1e10 else val
            return datetime.utcfromtimestamp(ts)
        except (ValueError, OSError):
            pass
    if isinstance(val, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
    return datetime.utcnow()


def parse(raw: str) -> Optional[dict]:
    try:
        data = json.loads(raw.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    timestamp = _parse_timestamp(_get_field(data, FIELD_ALIASES["timestamp"]))
    source_ip = _get_field(data, FIELD_ALIASES["source_ip"])
    dest_ip = _get_field(data, FIELD_ALIASES["dest_ip"])
    event_type = str(_get_field(data, FIELD_ALIASES["event_type"]) or "json_event").lower().replace(" ", "_")
    severity_raw = str(_get_field(data, FIELD_ALIASES["severity"]) or "info").lower()
    severity = SEVERITY_NORM.get(severity_raw, "info")
    message = str(_get_field(data, FIELD_ALIASES["message"]) or json.dumps(data))
    username = _get_field(data, FIELD_ALIASES["username"])
    hostname = _get_field(data, FIELD_ALIASES["hostname"])

    src_port = _get_field(data, FIELD_ALIASES["source_port"])
    dst_port = _get_field(data, FIELD_ALIASES["dest_port"])
    try:
        src_port = int(src_port) if src_port else None
        dst_port = int(dst_port) if dst_port else None
    except (ValueError, TypeError):
        src_port = dst_port = None

    mitre_tech, mitre_tactic = EVENT_TYPE_MITRE.get(event_type, (None, None))

    known_fields = {alias for aliases in FIELD_ALIASES.values() for alias in aliases}
    extra = {k: v for k, v in data.items() if k not in known_fields}

    return {
        "timestamp": timestamp,
        "source_ip": str(source_ip) if source_ip else None,
        "dest_ip": str(dest_ip) if dest_ip else None,
        "source_port": src_port,
        "dest_port": dst_port,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "raw_log": raw,
        "log_source": str(hostname) if hostname else "json-source",
        "log_format": "json",
        "mitre_technique": mitre_tech,
        "mitre_tactic": mitre_tactic,
        "username": str(username) if username else None,
        "hostname": str(hostname) if hostname else None,
        "extra_fields": extra,
    }
