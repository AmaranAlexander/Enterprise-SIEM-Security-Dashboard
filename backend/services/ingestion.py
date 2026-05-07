from typing import Optional
from sqlalchemy.orm import Session
from ..models.event import Event
from ..utils.risk_score import calculate_risk_score
from ..services.parsers import syslog_parser, cef_parser, json_parser, windows_parser


GEO_DB: dict[str, tuple[str, str]] = {
    "185.": ("Russia", "Moscow"),
    "194.": ("Ukraine", "Kyiv"),
    "91.": ("Netherlands", "Amsterdam"),
    "45.33.": ("United States", "Atlanta"),
    "104.21.": ("United States", "San Francisco"),
    "198.51.": ("United States", "Washington DC"),
    "203.": ("China", "Beijing"),
    "218.": ("China", "Shanghai"),
    "58.": ("China", "Guangzhou"),
    "210.": ("Japan", "Tokyo"),
    "49.": ("India", "Mumbai"),
    "41.": ("South Africa", "Johannesburg"),
    "197.": ("Nigeria", "Lagos"),
    "177.": ("Brazil", "São Paulo"),
    "186.": ("Argentina", "Buenos Aires"),
    "10.": ("Internal", "LAN"),
    "192.168.": ("Internal", "LAN"),
    "172.16.": ("Internal", "LAN"),
    "127.": ("Localhost", "Loopback"),
}

KNOWN_THREAT_IPS = {
    "185.220.101.": True,
    "194.165.16.": True,
    "91.108.4.": True,
    "198.51.100.": True,
}


def _geolocate(ip: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if not ip:
        return None, None
    for prefix, (country, city) in GEO_DB.items():
        if ip.startswith(prefix):
            return country, city
    return "Unknown", None


def _is_threat_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    for prefix in KNOWN_THREAT_IPS:
        if ip.startswith(prefix):
            return True
    return False


def _detect_format(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("{") or raw.startswith("["):
        return "json"
    if "CEF:" in raw:
        return "cef"
    if raw.startswith("<EventData") or "<Event " in raw or "EventID=" in raw:
        return "windows"
    return "syslog"


def parse_log(raw: str, force_format: Optional[str] = None) -> Optional[dict]:
    fmt = force_format or _detect_format(raw)

    parsed = None
    if fmt == "json":
        parsed = json_parser.parse(raw)
    elif fmt == "cef":
        parsed = cef_parser.parse(raw)
    elif fmt == "windows":
        parsed = windows_parser.parse(raw)
    else:
        parsed = syslog_parser.parse(raw)
        if parsed is None:
            parsed = json_parser.parse(raw)

    return parsed


def ingest_log(raw: str, db: Session, force_format: Optional[str] = None) -> Optional[Event]:
    parsed = parse_log(raw, force_format)
    if not parsed:
        return None

    country, city = _geolocate(parsed.get("source_ip"))
    if not parsed.get("country"):
        parsed["country"] = country
    if not parsed.get("city"):
        parsed["city"] = city

    is_threat = _is_threat_ip(parsed.get("source_ip"))
    risk = calculate_risk_score(
        severity=parsed.get("severity", "info"),
        event_type=parsed.get("event_type", ""),
        mitre_technique=parsed.get("mitre_technique"),
        is_threat_ip=is_threat,
    )
    parsed["risk_score"] = risk

    extra = parsed.pop("extra_fields", {})
    event = Event(**parsed)
    event.extra_fields = extra

    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def ingest_batch(lines: list[str], db: Session, force_format: Optional[str] = None) -> list[Event]:
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        ev = ingest_log(line, db, force_format)
        if ev:
            events.append(ev)
    return events
