import re
from datetime import datetime
from typing import Optional


SEVERITY_MAP = {
    0: "critical", 1: "critical", 2: "critical",  # emerg, alert, crit
    3: "high",                                       # err
    4: "medium",                                     # warning
    5: "low", 6: "low",                             # notice, info
    7: "info",                                       # debug
}

RFC3164_RE = re.compile(
    r"^(?:<(\d+)>)?"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s+"
    r"(.+)$"
)

RFC5424_RE = re.compile(
    r"^<(\d+)>(\d+)\s+"
    r"(\S+)\s+"            # timestamp
    r"(\S+)\s+"            # hostname
    r"(\S+)\s+"            # app-name
    r"(\S+)\s+"            # procid
    r"(\S+)\s+"            # msgid
    r"(-|\[.+?\])\s*"      # structured-data
    r"(.*)$",
    re.DOTALL,
)

IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
USER_RE = re.compile(r"(?:user|for)\s+(\S+)", re.IGNORECASE)
AUTH_FAIL_RE = re.compile(r"(failed|invalid|failure|denied|rejected)", re.IGNORECASE)
AUTH_OK_RE = re.compile(r"(accepted|success|logged in|opened session)", re.IGNORECASE)
PORT_RE = re.compile(r"port\s+(\d+)", re.IGNORECASE)


def _parse_priority(pri: Optional[str]) -> tuple[int, int]:
    if pri is None:
        return 1, 6
    p = int(pri)
    return p // 8, p % 8


def _detect_event_type(message: str, app: str) -> tuple[str, Optional[str], Optional[str]]:
    msg_lower = message.lower()
    app_lower = app.lower()

    if AUTH_FAIL_RE.search(msg_lower) and any(k in msg_lower for k in ("password", "login", "auth", "ssh")):
        return "failed_login", "T1110", "credential-access"
    if AUTH_OK_RE.search(msg_lower) and any(k in msg_lower for k in ("password", "login", "auth", "ssh", "session")):
        return "successful_login", None, None
    if "sudo" in msg_lower:
        return "privilege_escalation", "T1078", "privilege-escalation"
    if any(k in app_lower for k in ("firewall", "iptables", "pf", "ufw")):
        if "block" in msg_lower or "deny" in msg_lower or "drop" in msg_lower:
            return "firewall_block", None, None
        return "firewall_allow", None, None
    if any(k in msg_lower for k in ("scan", "nmap", "masscan")):
        return "port_scan", "T1046", "discovery"
    if "connection" in msg_lower:
        return "network_connection", None, None
    return "system_event", None, None


def parse(raw: str) -> Optional[dict]:
    raw = raw.strip()

    m = RFC5424_RE.match(raw)
    if m:
        pri, version, ts, host, app, pid, msgid, _, msg = m.groups()
        facility, severity_num = _parse_priority(pri)
        try:
            timestamp = datetime.fromisoformat(ts.rstrip("Z"))
        except ValueError:
            timestamp = datetime.utcnow()

        event_type, mitre_tech, mitre_tactic = _detect_event_type(msg, app)
        ips = IP_RE.findall(msg)
        users = USER_RE.findall(msg)
        ports = PORT_RE.findall(msg)

        return {
            "timestamp": timestamp,
            "source_ip": ips[0] if ips else None,
            "dest_ip": ips[1] if len(ips) > 1 else None,
            "dest_port": int(ports[0]) if ports else None,
            "event_type": event_type,
            "severity": SEVERITY_MAP.get(severity_num, "info"),
            "message": msg.strip(),
            "raw_log": raw,
            "log_source": host,
            "log_format": "syslog5424",
            "mitre_technique": mitre_tech,
            "mitre_tactic": mitre_tactic,
            "hostname": host,
            "username": users[0] if users else None,
            "extra_fields": {"app": app, "facility": facility, "pid": pid},
        }

    m = RFC3164_RE.match(raw)
    if m:
        pri, ts_str, host, app, pid, msg = m.groups()
        facility, severity_num = _parse_priority(pri)
        try:
            timestamp = datetime.strptime(ts_str.strip(), "%b %d %H:%M:%S").replace(year=datetime.utcnow().year)
        except ValueError:
            timestamp = datetime.utcnow()

        event_type, mitre_tech, mitre_tactic = _detect_event_type(msg, app)
        ips = IP_RE.findall(msg)
        users = USER_RE.findall(msg)
        ports = PORT_RE.findall(msg)

        return {
            "timestamp": timestamp,
            "source_ip": ips[0] if ips else None,
            "dest_ip": ips[1] if len(ips) > 1 else None,
            "dest_port": int(ports[0]) if ports else None,
            "event_type": event_type,
            "severity": SEVERITY_MAP.get(severity_num, "info"),
            "message": msg.strip(),
            "raw_log": raw,
            "log_source": host,
            "log_format": "syslog3164",
            "mitre_technique": mitre_tech,
            "mitre_tactic": mitre_tactic,
            "hostname": host,
            "username": users[0] if users else None,
            "extra_fields": {"app": app, "pid": pid, "facility": facility},
        }

    return None
