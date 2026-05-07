SEVERITY_BASE = {
    "critical": 85,
    "high": 65,
    "medium": 40,
    "low": 20,
    "info": 5,
}

EVENT_TYPE_BONUS = {
    "failed_login": 10,
    "privilege_escalation": 20,
    "lateral_movement": 25,
    "data_exfiltration": 30,
    "malware_detected": 35,
    "log_cleared": 30,
    "port_scan": 15,
    "sql_injection": 20,
    "ids_alert": 15,
    "account_created": 10,
    "service_install": 15,
}

MITRE_BONUS = {
    "T1110": 5,   # Brute Force
    "T1078": 15,  # Valid Accounts
    "T1021": 20,  # Remote Services
    "T1041": 25,  # Exfiltration Over C2
    "T1070": 20,  # Indicator Removal
    "T1046": 10,  # Network Service Scan
    "T1190": 15,  # Exploit Public-Facing App
    "T1543": 15,  # Create or Modify System Process
    "T1053": 10,  # Scheduled Task
    "T1136": 10,  # Create Account
}


def calculate_risk_score(
    severity: str,
    event_type: str,
    mitre_technique: str | None = None,
    is_threat_ip: bool = False,
) -> float:
    base = SEVERITY_BASE.get(severity, 5)
    bonus = EVENT_TYPE_BONUS.get(event_type, 0)
    mitre_bonus = MITRE_BONUS.get(mitre_technique or "", 0)
    threat_bonus = 15 if is_threat_ip else 0
    return min(100.0, float(base + bonus + mitre_bonus + threat_bonus))
