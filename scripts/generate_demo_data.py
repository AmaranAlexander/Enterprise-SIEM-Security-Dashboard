"""
Demo data generator — creates 7 days of realistic security events covering
7 MITRE ATT&CK scenarios. Run this once to populate the database.
"""
import sys
import os
import random
import json
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.database import SessionLocal, init_db
from backend.models.event import Event
from backend.services.correlation import run_correlation
from backend.utils.risk_score import calculate_risk_score

random.seed(42)

NOW = datetime.utcnow()
SEVEN_DAYS_AGO = NOW - timedelta(days=7)

INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.1.20",
    "10.0.2.5", "10.0.2.6", "10.0.2.100", "192.168.1.50",
    "192.168.1.51", "192.168.1.100",
]

ATTACKER_IPS = [
    ("185.220.101.47", "Russia", "Moscow"),
    ("185.220.101.182", "Russia", "St. Petersburg"),
    ("194.165.16.78", "Ukraine", "Kyiv"),
    ("91.108.4.215", "Netherlands", "Amsterdam"),
    ("203.205.14.88", "China", "Beijing"),
    ("218.92.0.113", "China", "Shanghai"),
    ("45.33.32.156", "United States", "Atlanta"),
    ("197.210.226.100", "Nigeria", "Lagos"),
    ("177.125.90.14", "Brazil", "São Paulo"),
    ("49.207.196.30", "India", "Mumbai"),
]

INTERNAL_USERS = ["jsmith", "mwilson", "alee", "rjones", "bkim", "cdavis", "etaylor", "fmartinez"]
ADMIN_USERS = ["admin", "root", "sysadmin", "administrator"]
SERVICE_ACCOUNTS = ["backup_svc", "monitor_svc", "deploy_svc"]

HOSTNAMES = [
    "web-prod-01", "web-prod-02", "db-server-01", "mail-server",
    "vpn-gateway", "dc-01", "file-server-01", "dev-workstation-03",
    "hr-laptop-12", "finance-ws-07",
]


def rand_time(start: datetime = SEVEN_DAYS_AGO, end: datetime = NOW, business_hours: bool = False) -> datetime:
    delta = end - start
    seconds = int(delta.total_seconds())
    t = start + timedelta(seconds=random.randint(0, seconds))
    if business_hours:
        t = t.replace(hour=random.randint(8, 18), minute=random.randint(0, 59))
    return t


def rand_port() -> int:
    common = [22, 23, 80, 443, 3306, 5432, 6379, 8080, 8443, 3389, 5900, 21, 25, 110, 143]
    return random.choice(common + list(range(1024, 65535, 100)))


def make_event(**kwargs) -> Event:
    severity = kwargs.get("severity", "info")
    event_type = kwargs.get("event_type", "system_event")
    mitre = kwargs.get("mitre_technique")
    is_threat = kwargs.get("_is_threat", False)

    risk = calculate_risk_score(severity, event_type, mitre, is_threat)
    kwargs.pop("_is_threat", None)
    extra = kwargs.pop("extra_fields", {})

    e = Event(risk_score=risk, **kwargs)
    e.extra_fields = extra
    return e


# ── Scenario 1: Brute Force Attack (T1110) ──────────────────────────────────

def gen_brute_force(count: int = 3) -> list[Event]:
    events = []
    for _ in range(count):
        attacker_ip, country, city = random.choice(ATTACKER_IPS[:5])
        target_user = random.choice(INTERNAL_USERS)
        target_host = random.choice(HOSTNAMES[:4])
        attack_start = rand_time()
        fail_count = random.randint(12, 60)

        for i in range(fail_count):
            ts = attack_start + timedelta(seconds=random.randint(i * 5, i * 15))
            events.append(make_event(
                timestamp=ts,
                source_ip=attacker_ip,
                dest_ip=random.choice(INTERNAL_IPS[:4]),
                dest_port=22,
                event_type="failed_login",
                severity="medium",
                message=f"Failed password for {target_user} from {attacker_ip} port {rand_port()} ssh2",
                raw_log=f"<38>Jan 15 {ts.strftime('%H:%M:%S')} {target_host} sshd[{random.randint(1000,9999)}]: Failed password for {target_user} from {attacker_ip} port {rand_port()} ssh2",
                log_source=target_host,
                log_format="syslog3164",
                mitre_technique="T1110",
                mitre_tactic="credential-access",
                username=target_user,
                hostname=target_host,
                country=country,
                city=city,
                _is_threat=True,
            ))

        success_ts = attack_start + timedelta(seconds=fail_count * 12 + random.randint(30, 120))
        events.append(make_event(
            timestamp=success_ts,
            source_ip=attacker_ip,
            dest_ip=random.choice(INTERNAL_IPS[:4]),
            dest_port=22,
            event_type="successful_login",
            severity="high",
            message=f"Accepted password for {target_user} from {attacker_ip} port {rand_port()} ssh2",
            raw_log=f"<38>Jan 15 {success_ts.strftime('%H:%M:%S')} {target_host} sshd[{random.randint(1000,9999)}]: Accepted password for {target_user} from {attacker_ip} port {rand_port()} ssh2",
            log_source=target_host,
            log_format="syslog3164",
            mitre_technique=None,
            mitre_tactic=None,
            username=target_user,
            hostname=target_host,
            country=country,
            city=city,
            _is_threat=True,
        ))
    return events


# ── Scenario 2: Port Scan (T1046) ────────────────────────────────────────────

def gen_port_scan(count: int = 4) -> list[Event]:
    events = []
    for _ in range(count):
        attacker_ip, country, city = random.choice(ATTACKER_IPS[2:])
        target_subnet = random.choice(INTERNAL_IPS)
        scan_start = rand_time()
        num_ports = random.randint(50, 200)

        for i in range(num_ports):
            ts = scan_start + timedelta(milliseconds=random.randint(i * 20, i * 100))
            port = random.randint(1, 65535)
            events.append(make_event(
                timestamp=ts,
                source_ip=attacker_ip,
                dest_ip=target_subnet,
                source_port=random.randint(40000, 65000),
                dest_port=port,
                event_type="port_scan",
                severity="low",
                message=f"Connection attempt from {attacker_ip}:{random.randint(40000,65000)} to {target_subnet}:{port} - BLOCKED",
                log_source="firewall-01",
                log_format="cef",
                mitre_technique="T1046",
                mitre_tactic="discovery",
                hostname="firewall-01",
                country=country,
                city=city,
                _is_threat=True,
            ))
    return events


# ── Scenario 3: SQL Injection (T1190) ───────────────────────────────────────

SQL_PAYLOADS = [
    "' OR 1=1--", "' UNION SELECT * FROM users--", "'; DROP TABLE users--",
    "' OR 'a'='a", "1'; SELECT sleep(5)--", "admin'--",
    "' OR 1=1 LIMIT 1--", "1 AND 1=2 UNION SELECT password FROM users",
]

def gen_sql_injection(count: int = 2) -> list[Event]:
    events = []
    for _ in range(count):
        attacker_ip, country, city = random.choice(ATTACKER_IPS[3:])
        attack_start = rand_time()
        num_attempts = random.randint(20, 80)

        for i in range(num_attempts):
            ts = attack_start + timedelta(seconds=random.randint(i, i * 3))
            payload = random.choice(SQL_PAYLOADS)
            endpoint = random.choice(["/login", "/search", "/api/users", "/admin/query"])
            events.append(make_event(
                timestamp=ts,
                source_ip=attacker_ip,
                dest_ip=random.choice(INTERNAL_IPS[:2]),
                dest_port=443,
                event_type="sql_injection",
                severity=random.choice(["high", "high", "critical"]),
                message=f'SQL injection attempt detected: GET {endpoint}?id={payload} from {attacker_ip}',
                log_source="web-waf-01",
                log_format="json",
                mitre_technique="T1190",
                mitre_tactic="initial-access",
                country=country,
                city=city,
                extra_fields={"endpoint": endpoint, "payload": payload, "method": "GET"},
                _is_threat=True,
            ))
    return events


# ── Scenario 4: Privilege Escalation (T1078) ────────────────────────────────

def gen_privilege_escalation(count: int = 3) -> list[Event]:
    events = []
    for _ in range(count):
        user = random.choice(INTERNAL_USERS)
        host = random.choice(HOSTNAMES[4:])
        ts = rand_time(business_hours=True)

        events.append(make_event(
            timestamp=ts,
            source_ip=random.choice(INTERNAL_IPS),
            dest_ip=None,
            event_type="privilege_escalation",
            severity="critical",
            message=f"sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
            raw_log=f"<85>May 15 {ts.strftime('%H:%M:%S')} {host} sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
            log_source=host,
            log_format="syslog3164",
            mitre_technique="T1078",
            mitre_tactic="privilege-escalation",
            username=user,
            hostname=host,
            country="Internal",
            city="LAN",
        ))

        for _ in range(random.randint(2, 5)):
            ts2 = ts + timedelta(minutes=random.randint(1, 30))
            admin_resource = random.choice(["/etc/shadow", "/etc/passwd", "/root/.ssh/authorized_keys", "/var/log/auth.log"])
            events.append(make_event(
                timestamp=ts2,
                source_ip=random.choice(INTERNAL_IPS),
                event_type="privilege_escalation",
                severity="high",
                message=f"Root access: {user} accessed {admin_resource}",
                log_source=host,
                log_format="syslog3164",
                mitre_technique="T1078",
                mitre_tactic="privilege-escalation",
                username=user,
                hostname=host,
                country="Internal",
                city="LAN",
                extra_fields={"resource": admin_resource, "original_user": user},
            ))
    return events


# ── Scenario 5: Lateral Movement (T1021) ────────────────────────────────────

def gen_lateral_movement(count: int = 2) -> list[Event]:
    events = []
    for _ in range(count):
        source_ip = random.choice(INTERNAL_IPS[:5])
        compromised_user = random.choice(INTERNAL_USERS)
        movement_start = rand_time()
        targets = random.sample(INTERNAL_IPS[3:], k=random.randint(4, 7))

        for i, target_ip in enumerate(targets):
            ts = movement_start + timedelta(minutes=random.randint(i * 5, i * 20))
            target_host = HOSTNAMES[i % len(HOSTNAMES)]
            events.append(make_event(
                timestamp=ts,
                source_ip=source_ip,
                dest_ip=target_ip,
                dest_port=random.choice([22, 3389, 445, 5985]),
                event_type="successful_login",
                severity="high",
                message=f"Accepted publickey for {compromised_user} from {source_ip} to {target_host}",
                log_source=target_host,
                log_format="syslog3164",
                mitre_technique="T1021",
                mitre_tactic="lateral-movement",
                username=compromised_user,
                hostname=target_host,
                country="Internal",
                city="LAN",
                extra_fields={"auth_method": "publickey", "target_host": target_host},
            ))
    return events


# ── Scenario 6: Log Clearing (T1070) ────────────────────────────────────────

def gen_log_clearing(count: int = 2) -> list[Event]:
    events = []
    for _ in range(count):
        host = random.choice(HOSTNAMES[3:7])
        user = random.choice(INTERNAL_USERS + ADMIN_USERS)
        ts = rand_time()

        events.append(make_event(
            timestamp=ts,
            source_ip=random.choice(INTERNAL_IPS),
            event_type="log_cleared",
            severity="critical",
            message=f"Security audit log was cleared. Subject Account: {user} on {host}",
            raw_log=f'<Event><System><EventID>1102</EventID><TimeCreated SystemTime="{ts.isoformat()}"/><Computer>{host}</Computer></System><EventData><Data Name="SubjectUserName">{user}</Data></EventData></Event>',
            log_source=host,
            log_format="windows",
            mitre_technique="T1070",
            mitre_tactic="defense-evasion",
            username=user,
            hostname=host,
            country="Internal",
            city="LAN",
            extra_fields={"event_id": 1102, "channel": "Security"},
        ))
    return events


# ── Scenario 7: Data Exfiltration Indicator (T1041) ──────────────────────────

def gen_data_exfiltration(count: int = 2) -> list[Event]:
    events = []
    for _ in range(count):
        internal_ip = random.choice(INTERNAL_IPS[:4])
        dest_ip, country, city = random.choice(ATTACKER_IPS[5:])
        exfil_start = rand_time()
        num_transfers = random.randint(10, 30)

        for i in range(num_transfers):
            ts = exfil_start + timedelta(minutes=random.randint(i * 2, i * 10))
            mb_transferred = random.randint(50, 500)
            events.append(make_event(
                timestamp=ts,
                source_ip=internal_ip,
                dest_ip=dest_ip,
                source_port=random.randint(40000, 65000),
                dest_port=443,
                event_type="data_exfiltration",
                severity="critical",
                message=f"Large outbound transfer detected: {internal_ip} -> {dest_ip}:{443} ({mb_transferred}MB)",
                log_source="firewall-01",
                log_format="cef",
                mitre_technique="T1041",
                mitre_tactic="exfiltration",
                country=country,
                city=city,
                extra_fields={"bytes_transferred": mb_transferred * 1024 * 1024, "protocol": "HTTPS"},
                _is_threat=True,
            ))
    return events


# ── Background Noise ─────────────────────────────────────────────────────────

def gen_background_noise(count: int = 500) -> list[Event]:
    events = []
    event_configs = [
        ("failed_login", "low", None, None, 0.15),
        ("successful_login", "info", None, None, 0.20),
        ("firewall_block", "low", None, None, 0.15),
        ("firewall_allow", "info", None, None, 0.10),
        ("network_connection", "info", None, None, 0.10),
        ("system_event", "info", None, None, 0.10),
        ("account_created", "medium", "T1136", "persistence", 0.05),
        ("service_install", "high", "T1543", "persistence", 0.05),
        ("scheduled_task", "medium", "T1053", "persistence", 0.05),
        ("kerberos_ticket", "info", None, None, 0.05),
    ]

    for _ in range(count):
        roll = random.random()
        cumulative = 0
        chosen = event_configs[0]
        for cfg in event_configs:
            cumulative += cfg[4]
            if roll <= cumulative:
                chosen = cfg
                break

        event_type, severity, mitre, tactic, _ = chosen

        if random.random() < 0.3:
            src_ip, country, city = random.choice(ATTACKER_IPS)
        else:
            src_ip = random.choice(INTERNAL_IPS)
            country, city = "Internal", "LAN"

        host = random.choice(HOSTNAMES)
        user = random.choice(INTERNAL_USERS + SERVICE_ACCOUNTS) if random.random() < 0.5 else None
        ts = rand_time()

        messages = {
            "failed_login": f"Failed password for {user or 'unknown'} from {src_ip} port {rand_port()}",
            "successful_login": f"Accepted password for {user or 'user'} from {src_ip}",
            "firewall_block": f"Blocked connection from {src_ip}:{rand_port()} to {random.choice(INTERNAL_IPS)}:{rand_port()}",
            "firewall_allow": f"Allowed connection from {src_ip}:{rand_port()} to {random.choice(INTERNAL_IPS)}:{rand_port()}",
            "network_connection": f"New connection: {src_ip} -> {random.choice(INTERNAL_IPS)}:{rand_port()}",
            "system_event": f"System event on {host}: service {'started' if random.random() > 0.5 else 'stopped'}",
            "account_created": f"New user account created: {random.choice(['newuser', 'tempacct', 'svc_new'])} by {user or 'admin'}",
            "service_install": f"New service installed: {'WindowsUpdate' if random.random() > 0.5 else 'SvcHost32'} on {host}",
            "scheduled_task": f"Scheduled task {'created' if random.random() > 0.5 else 'modified'} by {user or 'system'}",
            "kerberos_ticket": f"Kerberos TGT requested for {user or 'user'}@CORP.LOCAL from {src_ip}",
        }

        events.append(make_event(
            timestamp=ts,
            source_ip=src_ip,
            dest_ip=random.choice(INTERNAL_IPS) if random.random() > 0.5 else None,
            dest_port=rand_port() if random.random() > 0.5 else None,
            event_type=event_type,
            severity=severity,
            message=messages[event_type],
            log_source=host,
            log_format=random.choice(["syslog3164", "json", "cef", "windows"]),
            mitre_technique=mitre,
            mitre_tactic=tactic,
            username=user,
            hostname=host,
            country=country,
            city=city,
        ))

    return events


def main():
    print("Initializing database...")
    init_db()

    db = SessionLocal()
    try:
        from sqlalchemy import func
        existing = db.query(func.count(Event.id)).scalar()
        if existing and existing > 0:
            print(f"Database already has {existing} events. Skipping generation.")
            print("Delete siem.db to regenerate demo data.")
            return

        print("Generating realistic security events...")
        all_events = []

        print("  [+] Brute force attacks (T1110)...")
        all_events.extend(gen_brute_force(count=4))

        print("  [+] Port scans (T1046)...")
        all_events.extend(gen_port_scan(count=5))

        print("  [+] SQL injection attacks (T1190)...")
        all_events.extend(gen_sql_injection(count=3))

        print("  [+] Privilege escalation (T1078)...")
        all_events.extend(gen_privilege_escalation(count=4))

        print("  [+] Lateral movement (T1021)...")
        all_events.extend(gen_lateral_movement(count=3))

        print("  [+] Log clearing (T1070)...")
        all_events.extend(gen_log_clearing(count=3))

        print("  [+] Data exfiltration (T1041)...")
        all_events.extend(gen_data_exfiltration(count=2))

        print("  [+] Background noise events...")
        all_events.extend(gen_background_noise(count=600))

        all_events.sort(key=lambda e: e.timestamp)

        print(f"\nInserting {len(all_events)} events into database...")
        for i, event in enumerate(all_events):
            db.add(event)
            if i % 100 == 0:
                db.commit()
                print(f"  {i}/{len(all_events)} events written...", end="\r")
        db.commit()
        print(f"\n[OK] {len(all_events)} events inserted successfully")

        print("\nRunning correlation engine to generate alerts...")
        alerts = run_correlation(db, lookback_minutes=10080)
        print(f"[OK] {len(alerts)} alerts generated")

        print("\n[DONE] Demo data generation complete!")
        print(f"  Events: {len(all_events)}")
        print(f"  Alerts: {len(alerts)}")
        print("\nStart the backend: python -m backend.main")
        print("Start the frontend: cd frontend && npm run dev")

    finally:
        db.close()


if __name__ == "__main__":
    main()
