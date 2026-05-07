"""
Windows Event Log real-time watcher.
Polls Security, System, and Application logs for new events and ships them
to the SIEM API. Requires running as Administrator for the Security log.

Usage:
    py scripts/watch_windows_events.py
    py scripts/watch_windows_events.py --interval 5 --api http://localhost:8000
    py scripts/watch_windows_events.py --channels Security System --dry-run
"""
import sys
import os
import json
import time
import argparse
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

STATE_FILE = Path(__file__).parent.parent / ".watcher_state.json"
API_BASE = "http://localhost:8000"

# Security-relevant event IDs per channel
SECURITY_EVENT_IDS = [
    4624,   # Successful logon
    4625,   # Failed logon
    4634,   # Logoff
    4648,   # Explicit credential logon (RunAs)
    4656,   # Object access attempt
    4663,   # Object accessed
    4672,   # Special privileges assigned to new logon
    4688,   # Process creation
    4697,   # Service installed
    4698,   # Scheduled task created
    4702,   # Scheduled task updated
    4719,   # Audit policy changed
    4720,   # User account created
    4724,   # Password reset
    4725,   # Account disabled
    4726,   # Account deleted
    4732,   # Member added to security group
    4733,   # Member removed from security group
    4740,   # Account locked out
    4768,   # Kerberos TGT requested
    4769,   # Kerberos service ticket requested
    4776,   # Credential validation
    4798,   # User's local group membership enumerated
    4799,   # Security-enabled local group membership enumerated
    1102,   # Audit log cleared
]

SYSTEM_EVENT_IDS = [
    7045,   # New service installed
    7036,   # Service state change
    7040,   # Service start type changed
]

APPLICATION_EVENT_IDS = [
    1000,   # Application crash
    1001,   # Application fault
    1026,   # .NET runtime error
]

CHANNELS = {
    "Security":    SECURITY_EVENT_IDS,
    "System":      SYSTEM_EVENT_IDS,
    "Application": APPLICATION_EVENT_IDS,
}

SEVERITY_MAP = {
    1: "critical",   # Critical
    2: "high",       # Error
    3: "medium",     # Warning
    4: "low",        # Information
    5: "info",       # Verbose
    0: "info",       # LogAlways
}

EVENT_ID_MAP = {
    4624: ("successful_login",       "info"),
    4625: ("failed_login",           "medium"),
    4634: ("system_event",           "info"),
    4648: ("successful_login",       "low"),
    4656: ("system_event",           "low"),
    4663: ("system_event",           "low"),
    4672: ("privilege_escalation",   "medium"),
    4688: ("process_creation",       "low"),
    4697: ("service_install",        "high"),
    4698: ("scheduled_task",         "medium"),
    4702: ("scheduled_task",         "medium"),
    4719: ("audit_policy_change",    "high"),
    4720: ("account_created",        "medium"),
    4724: ("system_event",           "low"),
    4725: ("system_event",           "medium"),
    4726: ("account_deleted",        "medium"),
    4732: ("group_membership_change","medium"),
    4733: ("group_membership_change","low"),
    4740: ("account_lockout",        "high"),
    4768: ("kerberos_ticket",        "info"),
    4769: ("kerberos_ticket",        "info"),
    4776: ("credential_validation",  "info"),
    4798: ("group_enumeration",      "medium"),
    4799: ("group_enumeration",      "medium"),
    1102: ("log_cleared",            "critical"),
    7045: ("service_install",        "high"),
    7036: ("system_event",           "info"),
    7040: ("system_event",           "medium"),
}

MITRE_MAP = {
    4625: ("T1110", "credential-access"),
    4648: ("T1550", "lateral-movement"),
    4672: ("T1078", "privilege-escalation"),
    4688: (None,    None),
    4697: ("T1543", "persistence"),
    4698: ("T1053", "persistence"),
    4702: ("T1053", "persistence"),
    4719: ("T1562", "defense-evasion"),
    4720: ("T1136", "persistence"),
    4732: ("T1098", "persistence"),
    4740: ("T1110", "credential-access"),
    4776: ("T1110", "credential-access"),
    4798: ("T1087", "discovery"),
    4799: ("T1069", "discovery"),
    1102: ("T1070", "defense-evasion"),
    7045: ("T1543", "persistence"),
}

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2))


_WEVTUTIL_BATCH = 20  # wevtutil silently fails above ~23 EventID conditions


def build_xpath_filters(event_ids: list[int], last_record_id: int) -> list[str]:
    """Split into batches to stay within wevtutil's EventID-or-condition limit."""
    filters = []
    for i in range(0, len(event_ids), _WEVTUTIL_BATCH):
        batch = event_ids[i:i + _WEVTUTIL_BATCH]
        id_conditions = " or ".join(f"EventID={eid}" for eid in batch)
        filters.append(f"*[System[({id_conditions}) and EventRecordID > {last_record_id}]]")
    return filters


def build_xpath_time_filters(event_ids: list[int], since: datetime) -> list[str]:
    """Split into batches to stay within wevtutil's EventID-or-condition limit."""
    ts = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    filters = []
    for i in range(0, len(event_ids), _WEVTUTIL_BATCH):
        batch = event_ids[i:i + _WEVTUTIL_BATCH]
        id_conditions = " or ".join(f"EventID={eid}" for eid in batch)
        filters.append(f"*[System[({id_conditions}) and TimeCreated[@SystemTime >= '{ts}']]]")
    return filters


def query_events(channel: str, xpath: str, max_events: int = 200) -> list[str]:
    """Returns a list of raw XML strings, one per event."""
    cmd = [
        "wevtutil", "qe", channel,
        f"/q:{xpath}",
        "/f:XML",
        "/rd:false",          # oldest first so we advance the bookmark correctly
        f"/c:{max_events}",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        )
        if result.returncode != 0:
            if "Access is denied" in result.stderr:
                print(f"  [WARN] Access denied on {channel} log — run as Administrator for Security log")
            else:
                err = result.stderr.strip()
                print(f"  [WARN] wevtutil error on {channel} (exit {result.returncode}): {err[:200]}")
            return []
        raw = result.stdout.strip()
        if not raw:
            return []
        # wevtutil outputs events separated by newlines — each event is a self-contained XML element
        events = []
        current = []
        for line in raw.splitlines():
            if line.startswith("<Event ") and current:
                events.append("\n".join(current))
                current = [line]
            else:
                current.append(line)
        if current:
            events.append("\n".join(current))
        return events
    except subprocess.TimeoutExpired:
        print(f"  [WARN] Timeout querying {channel}")
        return []
    except FileNotFoundError:
        print("  [ERROR] wevtutil not found — must run on Windows")
        return []


def _get(elem, path: str) -> str | None:
    found = elem.find(path, NS)
    return found.text if found is not None else None


def parse_event_xml(raw_xml: str) -> dict | None:
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return None

    system = root.find("e:System", NS)
    if system is None:
        return None

    event_id_elem = system.find("e:EventID", NS)
    if event_id_elem is None:
        return None
    event_id = int(event_id_elem.text or 0)

    record_id_elem = system.find("e:EventRecordID", NS)
    record_id = int(record_id_elem.text or 0) if record_id_elem is not None else 0

    ts_elem = system.find("e:TimeCreated", NS)
    ts_str = ts_elem.get("SystemTime", "") if ts_elem is not None else ""
    try:
        timestamp = datetime.fromisoformat(ts_str.rstrip("Z"))
    except ValueError:
        timestamp = datetime.utcnow()

    computer = _get(system, "e:Computer") or "unknown"
    level_str = _get(system, "e:Level") or "4"
    try:
        level = int(level_str)
    except ValueError:
        level = 4

    # Extract EventData fields
    event_data = root.find("e:EventData", NS)
    fields: dict[str, str] = {}
    if event_data is not None:
        for data in event_data.findall("e:Data", NS):
            name = data.get("Name", "")
            fields[name] = data.text or ""

    username = (
        fields.get("TargetUserName") or
        fields.get("SubjectUserName") or
        fields.get("AccountName") or
        fields.get("NewAccountName")
    )
    if username in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", ""):
        username = None

    source_ip = fields.get("IpAddress") or fields.get("Workstation")
    if source_ip in ("-", "::1", "127.0.0.1", "LOCAL", ""):
        source_ip = None

    dest_port_str = fields.get("IpPort") or fields.get("DestPort")
    try:
        dest_port = int(dest_port_str) if dest_port_str and dest_port_str not in ("-", "") else None
    except ValueError:
        dest_port = None

    event_type, default_severity = EVENT_ID_MAP.get(event_id, ("windows_event", "info"))
    # Windows Security audit events use Level=0 (LogAlways) — not meaningful for severity.
    # Use the event-type default; only apply SEVERITY_MAP for Error/Warning/Critical levels.
    if level in (0, 4):
        severity = default_severity
    else:
        severity = SEVERITY_MAP.get(level, default_severity)
    mitre_technique, mitre_tactic = MITRE_MAP.get(event_id, (None, None))

    # Filter out noisy background logon events that aren't security-relevant
    if event_id == 4624:
        logon_type = fields.get("LogonType", "")
        raw_target = fields.get("TargetUserName", "")
        # Service (5) and Batch (4) logons are normal Windows background activity
        if logon_type in ("4", "5"):
            return None
        # System accounts and anonymous sessions are noise
        noise_accounts = {"", "-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
                          "ANONYMOUS LOGON", "IUSR", "ASPNET"}
        if raw_target.upper() in noise_accounts or raw_target.startswith(("DWM-", "UMFD-", "MSSQL$")):
            return None

    # Build human-readable message
    msg_parts = [f"EventID {event_id}: {event_type.replace('_', ' ').title()}"]
    if username:
        msg_parts.append(f"User: {username}")
    if source_ip:
        msg_parts.append(f"From: {source_ip}")
    if fields.get("ProcessName"):
        msg_parts.append(f"Process: {fields['ProcessName']}")
    if fields.get("ServiceName"):
        msg_parts.append(f"Service: {fields['ServiceName']}")
    if fields.get("FailureReason") and fields["FailureReason"] not in ("-", ""):
        msg_parts.append(f"Reason: {fields['FailureReason']}")
    if fields.get("LogonType") and event_id in (4624, 4625):
        logon_types = {"2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
                       "7": "Unlock", "8": "NetworkCleartext", "10": "RemoteInteractive", "11": "CachedInteractive"}
        lt = logon_types.get(fields["LogonType"], f"Type {fields['LogonType']}")
        msg_parts.append(f"Logon: {lt}")

    return {
        "record_id": record_id,
        "raw": {
            "timestamp": timestamp.isoformat(),
            "source_ip": source_ip,
            "dest_ip": None,
            "dest_port": dest_port,
            "event_type": event_type,
            "severity": severity,
            "message": " | ".join(msg_parts),
            "raw_log": raw_xml[:2000],
            "log_source": computer,
            "log_format": "windows",
            "mitre_technique": mitre_technique,
            "mitre_tactic": mitre_tactic,
            "username": username,
            "hostname": computer,
            "extra_fields": {"event_id": event_id, "level": level, **{k: v for k, v in fields.items() if v and v != "-"}},
        }
    }


def ship_to_api(events: list[dict], api_base: str, dry_run: bool) -> int:
    if not events:
        return 0
    if dry_run:
        for e in events[:3]:
            print(f"    [DRY] {e['timestamp']} | {e['event_type']} | {e.get('source_ip','—')} | {e['message'][:80]}")
        if len(events) > 3:
            print(f"    [DRY] ... and {len(events) - 3} more")
        return len(events)

    try:
        import urllib.request
        payload = json.dumps({
            "lines": [json.dumps(e) for e in events],
            "format": "json",
            "run_correlation": True,
        }).encode()
        req = urllib.request.Request(
            f"{api_base}/api/ingest",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            return result.get("ingested", 0)
    except Exception as e:
        print(f"  [ERROR] Failed to ship events: {e}")
        return 0


def get_latest_record_id(channel: str) -> int:
    """Get the most recent EventRecordID in the channel."""
    cmd = ["wevtutil", "qe", channel, "/c:1", "/rd:true", "/f:XML"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0)
        if not result.stdout.strip():
            return 0
        root = ET.fromstring(result.stdout.strip())
        rid = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventRecordID")
        return int(rid.text or 0) if rid is not None else 0
    except Exception:
        return 0


def run_watcher(channels: list[str], interval: int, api_base: str, dry_run: bool, backfill_minutes: int):
    print(f"\nWindows Event Log Watcher")
    print(f"  Channels:  {', '.join(channels)}")
    print(f"  API:       {api_base}")
    print(f"  Interval:  {interval}s")
    print(f"  Dry run:   {dry_run}")
    if dry_run:
        print("  [DRY RUN MODE — events will be printed, not sent]\n")
    else:
        try:
            import urllib.request
            urllib.request.urlopen(f"{api_base}/api/health", timeout=3)
            print("  [OK] SIEM API reachable\n")
        except Exception:
            print(f"  [ERROR] Cannot reach SIEM API at {api_base}")
            print("          Start the backend first: py -m backend.main\n")
            sys.exit(1)

    state = load_state()

    # ── Backfill pass (time-based) ────────────────────────────────────────────
    if backfill_minutes > 0:
        since = datetime.utcnow() - timedelta(minutes=backfill_minutes)
        print(f"  Backfilling last {backfill_minutes} minutes ({since.strftime('%H:%M')} UTC -> now)...")
        backfill_total = 0
        for channel in channels:
            event_ids = CHANNELS.get(channel, [])
            if not event_ids:
                continue
            raw_events = []
            for xpath in build_xpath_time_filters(event_ids, since):
                raw_events.extend(query_events(channel, xpath, max_events=1000))
            parsed = []
            new_last_id = state.get(channel, 0)
            for raw_xml in raw_events:
                result = parse_event_xml(raw_xml)
                if result:
                    new_last_id = max(new_last_id, result["record_id"])
                    parsed.append(result["raw"])
            if parsed:
                shipped = ship_to_api(parsed, api_base, dry_run)
                backfill_total += shipped
                print(f"    {channel}: backfilled {shipped} events")
                state[channel] = new_last_id
            else:
                print(f"    {channel}: no matching events in that window")
                # Still set the bookmark so ongoing poll starts from now
                state[channel] = max(state.get(channel, 0), get_latest_record_id(channel))
        print(f"  Backfill complete: {backfill_total} events shipped\n")
        save_state(state)

    # ── Bootstrap any channel not yet in state ────────────────────────────────
    for channel in channels:
        if channel not in state:
            last_id = get_latest_record_id(channel)
            state[channel] = last_id
            print(f"  Bootstrap {channel}: watching from RecordID {last_id}")
    save_state(state)

    print(f"\nWatching for new events... (Ctrl+C to stop)")
    print(f"  Polling every {interval}s — trigger events to see them appear\n")

    total_shipped = 0
    tick = 0
    try:
        while True:
            tick += 1
            cycle_events = 0
            for channel in channels:
                event_ids = CHANNELS.get(channel, [])
                if not event_ids:
                    continue
                last_id = state.get(channel, 0)
                raw_events = []
                for xpath in build_xpath_filters(event_ids, last_id):
                    raw_events.extend(query_events(channel, xpath))

                parsed = []
                new_last_id = last_id
                for raw_xml in raw_events:
                    result = parse_event_xml(raw_xml)
                    if result:
                        new_last_id = max(new_last_id, result["record_id"])
                        parsed.append(result["raw"])

                if parsed:
                    shipped = ship_to_api(parsed, api_base, dry_run)
                    cycle_events += shipped
                    total_shipped += shipped
                    now = datetime.now().strftime("%H:%M:%S")
                    print(f"  [{now}] {channel}: +{shipped} events  (session total: {total_shipped})")
                    state[channel] = new_last_id
                    save_state(state)

            # Heartbeat every 6 ticks so user knows it's alive
            if cycle_events == 0 and tick % 6 == 0:
                now = datetime.now().strftime("%H:%M:%S")
                print(f"  [{now}] Listening... (no new events in last {interval * 6}s)")

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n\nStopped. Total events shipped this session: {total_shipped}")
        save_state(state)


def main():
    parser = argparse.ArgumentParser(description="Windows Event Log -> SIEM watcher")
    parser.add_argument("--channels", nargs="+", default=["Security", "System"],
                        choices=list(CHANNELS.keys()), help="Event log channels to watch")
    parser.add_argument("--interval", type=int, default=10, help="Poll interval in seconds (default: 10)")
    parser.add_argument("--api", default=API_BASE, help=f"SIEM API base URL (default: {API_BASE})")
    parser.add_argument("--dry-run", action="store_true", help="Print events instead of shipping to API")
    parser.add_argument("--backfill", type=int, default=0,
                        help="Approximate minutes of history to backfill on first run (default: 0)")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("ERROR: This script only works on Windows.")
        sys.exit(1)

    run_watcher(
        channels=args.channels,
        interval=args.interval,
        api_base=args.api,
        dry_run=args.dry_run,
        backfill_minutes=args.backfill,
    )


if __name__ == "__main__":
    main()
