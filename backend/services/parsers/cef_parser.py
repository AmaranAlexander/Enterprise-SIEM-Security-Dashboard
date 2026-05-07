import re
from datetime import datetime
from typing import Optional

CEF_RE = re.compile(
    r"^(?:.*CEF:)(\d+)\|"
    r"([^|]*)\|"   # vendor
    r"([^|]*)\|"   # product
    r"([^|]*)\|"   # version
    r"([^|]*)\|"   # signature id
    r"([^|]*)\|"   # name
    r"([^|]*)\|"   # severity
    r"(.*)$",       # extension
    re.DOTALL,
)

SEVERITY_MAP = {
    "0": "info", "1": "info", "2": "info", "3": "low",
    "4": "low", "5": "medium", "6": "medium", "7": "high",
    "8": "high", "9": "critical", "10": "critical",
    "unknown": "info", "low": "low", "medium": "medium",
    "high": "high", "very-high": "critical",
}

EVENT_TYPE_MAP = {
    "100": "firewall_block", "101": "firewall_allow",
    "200": "ids_alert", "201": "ids_alert",
    "300": "failed_login", "301": "successful_login",
    "400": "malware_detected", "401": "malware_detected",
    "500": "port_scan", "501": "port_scan",
}

MITRE_MAP = {
    "port_scan": ("T1046", "discovery"),
    "ids_alert": ("T1190", "initial-access"),
    "malware_detected": ("T1204", "execution"),
    "failed_login": ("T1110", "credential-access"),
    "firewall_block": (None, None),
}


def _parse_extension(ext: str) -> dict:
    result = {}
    pattern = re.compile(r"(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)")
    for m in pattern.finditer(ext):
        result[m.group(1)] = m.group(2).strip()
    return result


def parse(raw: str) -> Optional[dict]:
    m = CEF_RE.match(raw.strip())
    if not m:
        return None

    _, vendor, product, version, sig_id, name, severity_str, ext_str = m.groups()
    ext = _parse_extension(ext_str)

    severity = SEVERITY_MAP.get(severity_str.strip().lower(), "medium")
    event_type = EVENT_TYPE_MAP.get(sig_id.strip(), "security_event")
    mitre_tech, mitre_tactic = MITRE_MAP.get(event_type, (None, None))

    ts = ext.get("rt") or ext.get("start") or ext.get("end")
    try:
        timestamp = datetime.utcfromtimestamp(int(ts) / 1000) if ts and ts.isdigit() else datetime.utcnow()
    except (ValueError, OSError):
        timestamp = datetime.utcnow()

    src_ip = ext.get("src") or ext.get("sourceAddress")
    dst_ip = ext.get("dst") or ext.get("destinationAddress")
    src_port = ext.get("spt") or ext.get("sourcePort")
    dst_port = ext.get("dpt") or ext.get("destinationPort")

    try:
        src_port = int(src_port) if src_port else None
        dst_port = int(dst_port) if dst_port else None
    except ValueError:
        src_port = dst_port = None

    username = ext.get("suser") or ext.get("duser")
    hostname = ext.get("shost") or ext.get("dhost") or ext.get("deviceHostName")

    msg = ext.get("msg") or name
    device_name = f"{vendor} {product}" if vendor and product else "Unknown"

    return {
        "timestamp": timestamp,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "source_port": src_port,
        "dest_port": dst_port,
        "event_type": event_type,
        "severity": severity,
        "message": msg,
        "raw_log": raw,
        "log_source": device_name,
        "log_format": "cef",
        "mitre_technique": mitre_tech,
        "mitre_tactic": mitre_tactic,
        "username": username,
        "hostname": hostname,
        "extra_fields": {"vendor": vendor, "product": product, "sig_id": sig_id, "name": name, **ext},
    }
