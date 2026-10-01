"""Single-file Streamlit DNS monitor: capture, analysis, storage, and dashboard."""

import collections
import hashlib
import html
import ipaddress
import json
import math
import os
import queue
import re
import sqlite3
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import pandas as pd
import requests
import streamlit as st

try:
    from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, TCP, UDP, conf, sniff

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


DB_PATH = Path(os.getenv("DNS_MONITOR_DB", str(Path(__file__).with_name("dns_security.db"))))
SUSPICIOUS_TLDS = {
    value.strip().lower().lstrip(".")
    for value in os.getenv("DNS_SUSPICIOUS_TLDS", "xyz,top,click,work,icu,tk,ml,ga,cf,gq,ru").split(",")
    if value.strip()
}
MULTI_LABEL_PUBLIC_SUFFIXES = {
    "ac.uk", "co.in", "co.jp", "co.nz", "co.uk", "com.au", "com.br",
    "com.cn", "com.in", "com.mx", "com.sg", "edu.au", "gov.in", "org.au",
    "org.uk",
}
DNS_TYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 64: "SVCB", 65: "HTTPS",
}
RCODE_MAP = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
_VT_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_VT_LOCK = threading.Lock()


def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = collections.Counter(text.lower())
    length = len(text)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 3)


def parse_domain_components(domain: str) -> dict[str, Any]:
    clean = re.sub(r"^https?://", "", domain.strip().lower()).split("/", 1)[0].rstrip(".")
    labels = [label for label in clean.split(".") if label]
    if len(labels) < 2:
        return {"clean_domain": clean, "subdomain": "", "sld": clean, "tld": "", "labels": labels}
    suffix_pair = ".".join(labels[-2:])
    if len(labels) >= 3 and suffix_pair in MULTI_LABEL_PUBLIC_SUFFIXES:
        sld = labels[-3]
        tld = suffix_pair
        subdomain = ".".join(labels[:-3])
    else:
        sld = labels[-2]
        tld = labels[-1]
        subdomain = ".".join(labels[:-2])
    return {"clean_domain": clean, "subdomain": subdomain, "sld": sld, "tld": tld, "labels": labels}


def _virustotal_reputation(domain: str) -> dict[str, Any]:
    api_key = os.getenv("DNS_VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"available": False, "reason": "VirusTotal lookup is not configured."}

    now = time.monotonic()
    with _VT_LOCK:
        cached = _VT_CACHE.get(domain)
        if cached and now - cached[0] < 3600:
            return cached[1]

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=2.5,
        )
        if response.status_code == 404:
            result = {"available": False, "reason": "VirusTotal has no report for this domain."}
        else:
            response.raise_for_status()
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result = {
                "available": True,
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "source": "VirusTotal",
            }
    except (requests.RequestException, ValueError, TypeError) as error:
        result = {"available": False, "reason": f"VirusTotal lookup failed: {error.__class__.__name__}."}

    with _VT_LOCK:
        _VT_CACHE[domain] = (now, result)
    return result


def analyze_domain(
    domain: str,
    query_frequency: int = 0,
    unique_subdomains: int = 0,
) -> dict[str, Any]:
    components = parse_domain_components(domain)
    clean = components["clean_domain"]
    labels = components["labels"]
    sld = components["sld"]
    subdomain_labels = labels[:-2] if len(labels) > 2 else []
    score = 0
    reasons: list[str] = []
    anomaly_reasons: list[str] = []

    reputation = _virustotal_reputation(clean)
    if reputation.get("available") and reputation.get("malicious", 0) > 0:
        impact = min(100, 70 + 10 * (reputation["malicious"] - 1))
        score += impact
        reasons.append(f"VirusTotal reported {reputation['malicious']} malicious detection(s). (+{impact})")
    elif reputation.get("available"):
        reasons.append("No malicious detections were reported in the available VirusTotal result.")
    else:
        reasons.append(reputation.get("reason", "No external threat-intelligence result is available."))

    tld = components["tld"]
    if tld in SUSPICIOUS_TLDS:
        score += 8
        reasons.append(f"The .{tld} TLD is on the configured elevated-abuse watchlist; this is a weak signal only. (+8)")
    if len(clean) >= 100:
        score += 8
        reasons.append(f"The fully qualified domain name is unusually long ({len(clean)} characters). (+8)")

    longest_subdomain = max(subdomain_labels, key=len, default="")
    longest_entropy = calculate_shannon_entropy(longest_subdomain)
    long_random_label = len(longest_subdomain) >= 25 and longest_entropy >= 3.5
    if len(longest_subdomain) >= 45:
        score += 20
        anomaly_reasons.append(f"Very long subdomain label ({len(longest_subdomain)} characters). (+20)")
    elif len(longest_subdomain) >= 25:
        score += 10
        reasons.append(f"Long subdomain label ({len(longest_subdomain)} characters). (+10)")
    if long_random_label:
        score += 15
        anomaly_reasons.append(f"Long subdomain label has elevated character entropy ({longest_entropy:.2f} bits/character). (+15)")

    depth = len(subdomain_labels)
    if depth >= 5:
        score += 10
        reasons.append(f"Subdomain depth is unusually high ({depth} labels). (+10)")
    if len(sld) >= 10:
        digit_ratio = sum(character.isdigit() for character in sld) / len(sld)
        if digit_ratio >= 0.5:
            score += 8
            reasons.append(f"The registered-name label contains {digit_ratio:.0%} digits; this is a weak signal only. (+8)")
    if query_frequency >= 30:
        score += 20
        anomaly_reasons.append(f"High observed query frequency ({query_frequency} queries in 60 seconds). (+20)")
    if unique_subdomains >= 20:
        score += 25
        anomaly_reasons.append(f"Many distinct subdomains observed under the same parent ({unique_subdomains} in 120 seconds). (+25)")

    anomaly = bool(
        (long_random_label and (query_frequency >= 10 or unique_subdomains >= 10))
        or (query_frequency >= 30 and unique_subdomains >= 20)
    )
    if anomaly:
        reasons.append("Potential DNS Anomaly / Possible DNS Tunneling (heuristic; not proof of tunneling).")
    reasons.extend(anomaly_reasons)

    score = min(100, score)
    try:
        suspicious_at = int(os.getenv("DNS_RISK_SUSPICIOUS_THRESHOLD", "30"))
        high_at = int(os.getenv("DNS_RISK_HIGH_THRESHOLD", "70"))
    except ValueError:
        suspicious_at, high_at = 30, 70
    if not 0 <= suspicious_at < high_at <= 100:
        suspicious_at, high_at = 30, 70
    if score >= high_at:
        classification = "HIGH RISK"
    elif score >= suspicious_at:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"
    if score == 0:
        reasons.append("No elevated domain-structure or behavioral heuristic signals were observed.")

    return {
        "domain": clean,
        "risk_score": score,
        "classification": classification,
        "reasons": reasons,
        "anomaly": anomaly,
        "entropy": calculate_shannon_entropy(sld),
        "subdomain_depth": depth,
        "query_frequency": query_frequency,
        "unique_subdomains": unique_subdomains,
        "threat_intelligence": reputation,
    }


@contextmanager
def get_db_connection() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> int:
    """Create the real-observation schema and discard unprovenanced legacy demo rows once."""
    with get_db_connection() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        legacy_rows = 0
        has_legacy_schema = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'dns_queries'"
        ).fetchone()
        if version == 0 and has_legacy_schema:
            legacy_rows = connection.execute("SELECT COUNT(*) FROM dns_queries").fetchone()[0]
            for table in ("alerts", "threat_intel", "blocked_domains", "dns_queries"):
                connection.execute(f"DROP TABLE IF EXISTS {table}")

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                query_type TEXT NOT NULL,
                response TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_reasons TEXT NOT NULL,
                is_anomaly INTEGER NOT NULL DEFAULT 0,
                observation_source TEXT NOT NULL,
                event_key TEXT NOT NULL UNIQUE
            );
            CREATE INDEX IF NOT EXISTS idx_dns_queries_timestamp ON dns_queries(timestamp);
            CREATE INDEX IF NOT EXISTS idx_dns_queries_domain ON dns_queries(domain);
            CREATE INDEX IF NOT EXISTS idx_dns_queries_status ON dns_queries(status);
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_id INTEGER NOT NULL UNIQUE REFERENCES dns_queries(id) ON DELETE CASCADE,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL
            );
            PRAGMA user_version = 1;
            """
        )
    return legacy_rows


def record_observation(
    *,
    timestamp: str,
    source_ip: str,
    destination_ip: str,
    domain: str,
    query_type: str,
    risk_score: int,
    status: str,
    reasons: list[str],
    anomaly: bool,
    event_key: str,
) -> int | None:
    with get_db_connection() as connection:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO dns_queries (
                timestamp, source_ip, destination_ip, domain, query_type, response,
                status, risk_score, risk_reasons, is_anomaly, observation_source, event_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp, source_ip, destination_ip, domain, query_type,
                "Awaiting matching DNS response", status, risk_score,
                json.dumps(reasons), int(anomaly), "local_packet_capture", event_key,
            ),
        )
        if cursor.rowcount == 0:
            return None
        query_id = int(cursor.lastrowid)
        if status in ("SUSPICIOUS", "HIGH RISK") or anomaly:
            severity = "HIGH" if status == "HIGH RISK" else "MEDIUM"
            title = "Potential DNS Anomaly / Possible DNS Tunneling" if anomaly else f"{status.title()} DNS domain observed"
            connection.execute(
                """INSERT OR IGNORE INTO alerts (query_id, timestamp, severity, title, description)
                   VALUES (?, ?, ?, ?, ?)""",
                (query_id, timestamp, severity, title, "; ".join(reasons)),
            )
        return query_id


def complete_response(event_key: str, response: str) -> None:
    with get_db_connection() as connection:
        connection.execute("UPDATE dns_queries SET response = ? WHERE event_key = ?", (response, event_key))


def get_dashboard_stats() -> dict[str, int]:
    with get_db_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM dns_queries").fetchone()[0]
        domains = connection.execute(
            """SELECT domain, status FROM dns_queries q
               WHERE id = (SELECT MAX(id) FROM dns_queries WHERE domain = q.domain)"""
        ).fetchall()
        counts = {"SAFE": 0, "SUSPICIOUS": 0, "HIGH RISK": 0}
        for row in domains:
            if row["status"] in counts:
                counts[row["status"]] += 1
        return {
            "total_queries": total,
            "unique_domains": len(domains),
            "safe_domains": counts["SAFE"],
            "suspicious_domains": counts["SUSPICIOUS"],
            "high_risk_domains": counts["HIGH RISK"],
        }


def get_queries(
    status: str = "All",
    recent_only: bool = False,
    limit: int = 100,
    search: str = "",
    anomalies_only: bool = False,
    domain_filter: str | None = None,
) -> list[dict[str, Any]]:
    conditions = []
    parameters: list[Any] = []
    if status != "All":
        conditions.append("status = ?")
        parameters.append(status)
    if recent_only:
        conditions.append("timestamp >= strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now', '-5 minutes')")
    if search.strip():
        conditions.append("(domain LIKE ? OR source_ip LIKE ? OR query_type LIKE ?)")
        search_term = f"%{search.strip()}%"
        parameters.extend((search_term, search_term, search_term))
    if anomalies_only:
        conditions.append("is_anomaly = 1")
    if domain_filter is not None:
        conditions.append("domain = ?")
        parameters.append(domain_filter)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    with get_db_connection() as connection:
        rows = connection.execute(
            f"SELECT * FROM dns_queries {where} ORDER BY id DESC LIMIT ?",
            (*parameters, max(1, min(limit, 1000))),
        ).fetchall()
    items = [dict(row) for row in rows]
    for item in items:
        item["risk_reasons"] = "; ".join(json.loads(item["risk_reasons"]))
    return items


def get_domain_names() -> list[str]:
    with get_db_connection() as connection:
        rows = connection.execute("SELECT DISTINCT domain FROM dns_queries ORDER BY domain").fetchall()
    return [row["domain"] for row in rows]


def get_domain_profile(domain: str) -> dict[str, Any] | None:
    with get_db_connection() as connection:
        aggregate = connection.execute(
            """SELECT COUNT(*) AS query_count, MIN(timestamp) AS first_observed,
                      MAX(timestamp) AS last_observed,
                      SUM(CASE WHEN julianday(timestamp) >= julianday('now', '-60 seconds') THEN 1 ELSE 0 END) AS queries_last_minute
               FROM dns_queries WHERE domain = ?""",
            (domain,),
        ).fetchone()
        if not aggregate or not aggregate["query_count"]:
            return None
        latest = connection.execute(
            "SELECT * FROM dns_queries WHERE domain = ? ORDER BY id DESC LIMIT 1", (domain,)
        ).fetchone()
        query_types = connection.execute(
            "SELECT DISTINCT query_type FROM dns_queries WHERE domain = ? ORDER BY query_type", (domain,)
        ).fetchall()
    profile = dict(aggregate)
    profile.update(dict(latest))
    profile["query_types"] = [row["query_type"] for row in query_types]
    profile["risk_reasons"] = json.loads(profile["risk_reasons"])
    return profile


def get_alerts(limit: int = 100) -> list[dict[str, Any]]:
    with get_db_connection() as connection:
        rows = connection.execute(
            """SELECT a.*, q.domain, q.risk_score, q.risk_reasons, q.query_type,
                      q.source_ip, q.destination_ip
               FROM alerts a JOIN dns_queries q ON q.id = a.query_id
               ORDER BY a.id DESC LIMIT ?""",
            (max(1, min(limit, 1000)),),
        ).fetchall()
    alerts = [dict(row) for row in rows]
    for alert in alerts:
        alert["risk_reasons"] = json.loads(alert["risk_reasons"])
    return alerts


def clear_observations() -> int:
    with get_db_connection() as connection:
        count = connection.execute("SELECT COUNT(*) FROM dns_queries").fetchone()[0]
        connection.execute("DELETE FROM alerts")
        connection.execute("DELETE FROM dns_queries")
    return count


class DnsRealtimeMonitor:
    def __init__(self, interface: str | None = None):
        configured_interface = interface or os.getenv("DNS_CAPTURE_INTERFACE")
        if configured_interface:
            self.interface = configured_interface
        elif HAS_SCAPY:
            try:
                self.interface = conf.route.route("0.0.0.0")[0]
            except Exception:
                self.interface = conf.iface
        else:
            self.interface = None
        self.is_running = False
        self.last_error: str | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._packet_queue: queue.Queue[Any] = queue.Queue(maxsize=5000)
        self.dropped_packet_count = 0
        self._pending: dict[tuple[Any, ...], tuple[str, float]] = {}
        self._recent_packets: dict[tuple[Any, ...], float] = {}
        self._domain_times: dict[str, deque[float]] = defaultdict(deque)
        self._parent_domains: dict[str, deque[tuple[str, float]]] = defaultdict(deque)

    def start(self) -> None:
        with self._lock:
            if self.is_running:
                return
            if not HAS_SCAPY:
                self.last_error = "Scapy is not installed. Install project requirements, then retry capture."
                return
            self.last_error = None
            self._stop_event.clear()
            self.is_running = True
            threading.Thread(target=self._processing_loop, daemon=True, name="DNS-packet-analysis").start()
            self._thread = threading.Thread(target=self._capture_loop, daemon=True, name="DNS-packet-capture")
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            self.is_running = False

    def _enqueue_packet(self, packet: Any) -> None:
        try:
            self._packet_queue.put_nowait(packet)
        except queue.Full:
            self.dropped_packet_count += 1

    def _processing_loop(self) -> None:
        while not self._stop_event.is_set() or not self._packet_queue.empty():
            try:
                packet = self._packet_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self._handle_packet(packet)
            except Exception as error:
                self.last_error = f"DNS packet processing failed: {error}"
            finally:
                self._packet_queue.task_done()

    def _capture_loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                sniff(
                    iface=self.interface,
                    filter="udp port 53 or tcp port 53",
                    prn=self._enqueue_packet,
                    store=False,
                    timeout=1,
                )
        except Exception as error:
            self.last_error = f"Packet capture failed: {error}. On Windows, install Npcap and run the app with capture permissions."
        finally:
            self.is_running = False
            self._stop_event.set()

    def _handle_packet(self, packet: Any) -> None:
        if not HAS_SCAPY or not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return
        dns = packet[DNS]
        question = packet[DNSQR]
        qname = question.qname.decode("ascii", errors="ignore").rstrip(".").lower()
        if not qname or not self._is_domain_name(qname):
            return
        source_ip, destination_ip = self._addresses(packet)
        if not source_ip or not destination_ip:
            return
        transport = packet[UDP] if packet.haslayer(UDP) else packet[TCP] if packet.haslayer(TCP) else None
        if transport is None:
            return
        query_type = DNS_TYPE_MAP.get(int(question.qtype), f"TYPE{int(question.qtype)}")
        dns_id = int(dns.id)
        if int(dns.qr) == 0:
            self._record_query(packet, qname, query_type, source_ip, destination_ip, transport, dns_id)
        else:
            self._record_response(packet, qname, source_ip, destination_ip, transport, dns_id, dns)

    @staticmethod
    def _is_domain_name(value: str) -> bool:
        if len(value) > 253:
            return False
        try:
            ipaddress.ip_address(value)
            return False
        except ValueError:
            return all(label and len(label) <= 63 for label in value.split("."))

    @staticmethod
    def _addresses(packet: Any) -> tuple[str | None, str | None]:
        if packet.haslayer(IP):
            return packet[IP].src, packet[IP].dst
        if packet.haslayer(IPv6):
            return packet[IPv6].src, packet[IPv6].dst
        return None, None

    def _record_query(
        self,
        packet: Any,
        domain: str,
        query_type: str,
        source_ip: str,
        destination_ip: str,
        transport: Any,
        dns_id: int,
    ) -> None:
        now = float(packet.time)
        packet_key = (source_ip, destination_ip, domain, query_type, dns_id)
        with self._lock:
            self._expire_tracking(now)
            if now - self._recent_packets.get(packet_key, 0.0) < 0.75:
                return
            self._recent_packets[packet_key] = now
            domain_times = self._domain_times[domain]
            domain_times.append(now)
            while domain_times and now - domain_times[0] > 60:
                domain_times.popleft()
            components = parse_domain_components(domain)
            parent = f"{components['sld']}.{components['tld']}" if components["tld"] else components["sld"]
            parent_events = self._parent_domains[parent]
            parent_events.append((domain, now))
            while parent_events and now - parent_events[0][1] > 120:
                parent_events.popleft()
            unique_subdomains = len({name for name, _ in parent_events if name != parent})
            frequency = len(domain_times)

        analysis = analyze_domain(domain, frequency, unique_subdomains)
        event_time = datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="milliseconds")
        event_key = hashlib.sha256(
            f"{event_time}|{source_ip}|{destination_ip}|{dns_id}|{domain}|{query_type}".encode()
        ).hexdigest()
        query_id = record_observation(
            timestamp=event_time,
            source_ip=source_ip,
            destination_ip=destination_ip,
            domain=domain,
            query_type=query_type,
            risk_score=analysis["risk_score"],
            status=analysis["classification"],
            reasons=analysis["reasons"],
            anomaly=analysis["anomaly"],
            event_key=event_key,
        )
        if query_id is not None:
            source_port = int(transport.sport)
            destination_port = int(transport.dport)
            pending_key = (dns_id, source_ip, source_port, destination_ip, destination_port, domain)
            with self._lock:
                self._pending[pending_key] = (event_key, now)

    def _record_response(
        self,
        packet: Any,
        domain: str,
        source_ip: str,
        destination_ip: str,
        transport: Any,
        dns_id: int,
        dns: Any,
    ) -> None:
        response_key = (
            dns_id, destination_ip, int(transport.dport), source_ip, int(transport.sport), domain,
        )
        with self._lock:
            pending = self._pending.pop(response_key, None)
        if not pending:
            return
        event_key, _ = pending
        rcode = int(dns.rcode)
        records = [
            answer.rdata.decode("utf-8", errors="replace")
            if isinstance(answer.rdata, bytes)
            else str(answer.rdata)
            for answer in (dns.an or [])
            if isinstance(answer, DNSRR)
        ]
        response = RCODE_MAP.get(rcode, f"RCODE{rcode}")
        if records:
            response = f"{response}: {', '.join(records)}"
        complete_response(event_key, response)

    def _expire_tracking(self, now: float) -> None:
        self._recent_packets = {
            key: timestamp for key, timestamp in self._recent_packets.items() if now - timestamp <= 2
        }
        self._pending = {
            key: pending for key, pending in self._pending.items() if now - pending[1] <= 10
        }

    def clear_session_tracking(self) -> None:
        with self._lock:
            self._pending.clear()
            self._recent_packets.clear()
            self._domain_times.clear()
            self._parent_domains.clear()


@st.cache_resource
def get_global_monitor() -> DnsRealtimeMonitor:
    return DnsRealtimeMonitor()


def format_timestamp(value: str | None) -> str:
    if not value:
        return "--"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone().strftime("%b %d, %H:%M:%S")
    except ValueError:
        return value


def time_since(value: str | None) -> str:
    if not value:
        return "Awaiting first event"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        seconds = max(0, int((datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds()))
    except ValueError:
        return "Time unavailable"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    return f"{seconds // 3600}h ago"


def render_empty_state(title: str, message: str) -> None:
    st.markdown(
        f"""<div class="empty-state"><div class="empty-mark">&#9675;</div>
        <strong>{html.escape(title)}</strong><span>{html.escape(message)}</span></div>""",
        unsafe_allow_html=True,
    )


def event_table(events: list[dict[str, Any]], limit: int | None = None) -> None:
    if limit is not None:
        events = events[:limit]
    if not events:
        render_empty_state("No DNS events yet", "The monitoring engine is active. Browse websites to observe real DNS activity.")
        return
    frame = pd.DataFrame(events)
    frame["Time"] = frame["timestamp"].map(format_timestamp)
    frame["Risk score"] = frame["risk_score"].map(lambda score: f"{score}/100")
    frame.rename(
        columns={
            "domain": "Domain",
            "query_type": "Type",
            "status": "Status",
            "risk_reasons": "Detection reason",
            "source_ip": "Source",
            "destination_ip": "Resolver",
            "response": "Response",
            "observation_source": "Source type",
        },
        inplace=True,
    )
    preferred = ["Time", "Domain", "Type", "Status", "Risk score", "Detection reason"]
    st.dataframe(
        frame[[column for column in preferred if column in frame.columns]],
        hide_index=True,
        width="stretch",
        column_config={
            "Time": st.column_config.TextColumn(width="small"),
            "Domain": st.column_config.TextColumn(width="medium"),
            "Type": st.column_config.TextColumn(width="small"),
            "Status": st.column_config.TextColumn(width="small"),
            "Risk score": st.column_config.TextColumn(width="small"),
            "Detection reason": st.column_config.TextColumn(width="large"),
        },
    )


def latest_domain_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    latest = []
    for event in events:
        if event["domain"] not in seen:
            latest.append(event)
            seen.add(event["domain"])
    return latest


def render_alert_list(alerts: list[dict[str, Any]], limit: int = 5) -> None:
    if not alerts:
        render_empty_state("No security alerts", "Alerts appear only when captured DNS activity triggers a detection rule.")
        return
    for alert in alerts[:limit]:
        severity = "high" if alert["severity"] == "HIGH" else "medium"
        reasons = "<br>".join(html.escape(reason) for reason in alert["risk_reasons"])
        st.markdown(
            f"""<div class="alert-row alert-{severity}">
              <div class="alert-heading"><span class="severity-pill {severity}">{html.escape(alert['severity'])}</span>
              <span class="muted">{html.escape(format_timestamp(alert['timestamp']))}</span></div>
              <strong>{html.escape(alert['title'])}</strong>
              <div class="alert-domain">{html.escape(alert['domain'])} <span>{alert['risk_score']}/100</span></div>
              <div class="alert-reasons">{reasons}</div>
            </div>""",
            unsafe_allow_html=True,
        )


def render_dashboard(monitor: DnsRealtimeMonitor) -> None:
    @st.fragment(run_every="2s")
    def live_overview() -> None:
        stats = get_dashboard_stats()
        events = get_queries(limit=1000)
        last_event = events[0] if events else None
        sensor_class = "online" if monitor.is_running and not monitor.last_error else "offline"
        sensor_label = "LIVE MONITORING" if sensor_class == "online" else "SENSOR OFFLINE"
        header_left, header_right = st.columns([2.2, 1])
        with header_left:
            st.markdown("## Security Operations Center")
            st.caption("Host DNS telemetry, domain risk and behavioral anomaly monitoring")
        with header_right:
            st.markdown(
                f"""<div class="live-panel"><span class="live-dot {sensor_class}"></span>
                <strong>{sensor_label}</strong><span class="live-meta">Last event: {time_since(last_event['timestamp'] if last_event else None)}</span>
                <span class="live-meta">Updated {datetime.now().astimezone().strftime('%H:%M:%S')}</span></div>""",
                unsafe_allow_html=True,
            )

        metric_cols = st.columns(4)
        metric_cols[0].metric("DNS queries", f"{stats['total_queries']:,}", help="Captured query packets, after retransmission deduplication")
        metric_cols[1].metric("Safe domains", f"{stats['safe_domains']:,}")
        metric_cols[2].metric("Suspicious", f"{stats['suspicious_domains']:,}")
        metric_cols[3].metric("High risk", f"{stats['high_risk_domains']:,}")

        st.markdown('<div class="section-label">LIVE TELEMETRY</div>', unsafe_allow_html=True)
        chart_col, risk_col = st.columns([1.7, 1])
        with chart_col:
            with st.container(border=True):
                st.markdown("### Real-time DNS activity")
                st.caption("Captured queries per observed minute")
                if events:
                    frame = pd.DataFrame(events)
                    times = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce").dropna()
                    if not times.empty:
                        series = times.dt.floor("min").value_counts().sort_index().rename("Queries")
                        st.line_chart(series, height=260, width="stretch")
                    else:
                        render_empty_state("Activity timeline unavailable", "Captured timestamps could not be parsed.")
                else:
                    render_empty_state("No DNS activity detected yet", "Start browsing to begin real-time monitoring.")
        with risk_col:
            with st.container(border=True):
                st.markdown("### Risk distribution")
                st.caption("Latest observed classification per domain")
                risk_data = pd.DataFrame(
                    {"Domains": [stats["safe_domains"], stats["suspicious_domains"], stats["high_risk_domains"]]},
                    index=["Low risk", "Suspicious", "High risk"],
                )
                if risk_data["Domains"].sum():
                    st.bar_chart(risk_data, height=260, color="#4cc9b0")
                else:
                    render_empty_state("No risk data", "Classifications appear after DNS queries are observed.")

        st.markdown('<div class="section-label">OBSERVED EVENTS</div>', unsafe_allow_html=True)
        with st.container(border=True):
            query_col, action_col = st.columns([4, 1])
            query_col.markdown("### Recent DNS queries")
            if action_col.button("Open live monitor", icon=":material/open_in_new:", width="stretch"):
                st.session_state.active_view = "Live DNS Monitor"
                st.rerun()
            event_table(events, limit=12)

        flagged = [event for event in latest_domain_events(events) if event["status"] != "SAFE"]
        alerts = get_alerts(limit=8)
        anomalies = get_queries(anomalies_only=True, limit=8)
        st.markdown('<div class="section-label">THREAT REVIEW</div>', unsafe_allow_html=True)
        overview_col, alerts_col, anomaly_col = st.columns([1.05, 1.2, 1.2])
        with overview_col:
            with st.container(border=True):
                st.markdown("### Threat overview")
                st.metric("Flagged domains", len(flagged))
                if flagged:
                    event_table(flagged, limit=4)
                else:
                    render_empty_state("No detections", "No observed domain currently exceeds the low-risk band.")
        with alerts_col:
            with st.container(border=True):
                st.markdown("### Recent alerts")
                render_alert_list(alerts, limit=3)
        with anomaly_col:
            with st.container(border=True):
                st.markdown("### DNS anomaly detection")
                if anomalies:
                    st.caption("Potential DNS Anomaly is heuristic evidence, not confirmation of tunneling.")
                    event_table(anomalies, limit=3)
                else:
                    render_empty_state("No potential anomalies", "Behavioral indicators are evaluated from captured queries.")
        if monitor.last_error:
            st.error(monitor.last_error)

    live_overview()


def render_domain_analysis() -> None:
    st.markdown("## Domain analysis")
    st.caption("Investigate a domain that has been observed by this sensor.")
    domains = get_domain_names()
    if not domains:
        render_empty_state("No observed domains", "Browse websites while monitoring is active. Only captured domains can be analyzed here.")
        return
    selected_domain = st.selectbox("Observed domain", domains, key="domain_analysis_selection")
    profile = get_domain_profile(selected_domain)
    if not profile:
        render_empty_state("Domain record unavailable", "This domain has no stored observations.")
        return

    components = parse_domain_components(selected_domain)
    metrics = st.columns(4)
    metrics[0].metric("Classification", profile["status"])
    metrics[1].metric("Risk score", f"{profile['risk_score']}/100")
    metrics[2].metric("Observed queries", f"{profile['query_count']:,}")
    metrics[3].metric("Last minute", f"{profile['queries_last_minute'] or 0:,}")
    first_col, last_col, types_col = st.columns(3)
    first_col.metric("First observed", format_timestamp(profile["first_observed"]))
    last_col.metric("Last observed", format_timestamp(profile["last_observed"]))
    types_col.metric("Query types", ", ".join(profile["query_types"]) or "--")

    structure_col, reputation_col = st.columns(2)
    with structure_col:
        with st.container(border=True):
            st.markdown("### Domain characteristics")
            st.write(f"**Registered name:** `{components['sld']}`")
            st.write(f"**Suffix:** `{components['tld'] or 'none'}`")
            st.write(f"**Subdomain depth:** {len([part for part in components['subdomain'].split('.') if part])}")
            st.write(f"**Name length:** {len(components['clean_domain'])} characters")
            st.write(f"**Name-label entropy:** {calculate_shannon_entropy(components['sld'])} bits/character")
            st.write(f"**Resolver:** `{profile['destination_ip']}`")
    with reputation_col:
        with st.container(border=True):
            st.markdown("### Threat intelligence")
            intel_reasons = [reason for reason in profile["risk_reasons"] if "VirusTotal" in reason]
            if intel_reasons:
                for reason in intel_reasons:
                    st.write(reason)
            else:
                st.info("No threat-intelligence result was recorded with this observation.")
            st.caption("Unavailable reputation is not treated as a clean reputation.")

    with st.container(border=True):
        st.markdown("### Detection reasons")
        if profile["risk_reasons"]:
            for reason in profile["risk_reasons"]:
                st.markdown(f"- {html.escape(reason)}")
        else:
            st.write("No detection reasons were stored for the latest observation.")
    st.markdown("### Query history")
    event_table(get_queries(limit=1000, domain_filter=selected_domain), limit=100)


def render_threat_detection() -> None:
    st.markdown("## Threat detection")
    st.caption("Latest observed classification for each domain. Unusual appearance alone is not treated as malicious.")
    events = latest_domain_events(get_queries(limit=1000))
    flagged = [event for event in events if event["status"] != "SAFE"]
    if not flagged:
        render_empty_state("No flagged domains", "Threat detections will appear when real DNS observations trigger scoring rules.")
        return
    minimum_score = st.slider("Minimum risk score", min_value=0, max_value=100, value=0)
    filtered = [event for event in flagged if event["risk_score"] >= minimum_score]
    event_table(filtered)


def render_anomalies() -> None:
    st.markdown("## DNS anomaly detection")
    st.caption("Heuristic behavior findings from real captured queries. These indicators do not confirm tunneling or compromise.")
    anomalies = get_queries(anomalies_only=True, limit=500)
    if not anomalies:
        render_empty_state("No potential DNS anomalies", "Long/high-entropy labels and abnormal query patterns are evaluated as traffic is observed.")
        return
    st.warning("Potential DNS Anomaly / Possible DNS Tunneling is a heuristic label, not a confirmed attack.")
    event_table(anomalies)


def render_live_monitor() -> None:
    st.markdown("## Live DNS monitor")
    st.caption("Packet-level observations from the selected local network interface.")
    filter_col, search_col, recent_col = st.columns([1, 1.5, 1])
    status = filter_col.selectbox("Classification", ["All", "SAFE", "SUSPICIOUS", "HIGH RISK"])
    search = search_col.text_input("Search domain, source, or type", key="live_search")
    recent = recent_col.checkbox("Last 5 minutes", key="live_recent")
    events = get_queries(status=status, recent_only=recent, limit=1000, search=search)
    if events:
        event_table(events)
        frame = pd.DataFrame(events)
        export = frame.to_csv(index=False)
        st.download_button("Export observed events (CSV)", export, "dns_observations.csv", "text/csv", icon=":material/download:")
    else:
        render_empty_state("No matching DNS events", "Adjust filters or browse websites to observe new DNS activity.")


def render_alerts() -> None:
    st.markdown("## Security alerts")
    alerts = get_alerts(limit=500)
    if not alerts:
        render_empty_state("No security alerts", "Alerts are created only from observed DNS events that trigger detections.")
        return
    severity = st.multiselect("Severity", ["HIGH", "MEDIUM"], default=["HIGH", "MEDIUM"])
    render_alert_list([alert for alert in alerts if alert["severity"] in severity], limit=500)


def render_logs() -> None:
    st.markdown("## DNS logs")
    search_col, status_col, recent_col = st.columns([2, 1, 1])
    search = search_col.text_input("Search logs", key="logs_search", placeholder="Domain, address, query type")
    status = status_col.selectbox("Status", ["All", "SAFE", "SUSPICIOUS", "HIGH RISK"], key="logs_status")
    recent = recent_col.checkbox("Recently observed", key="logs_recent")
    events = get_queries(status=status, recent_only=recent, limit=1000, search=search)
    event_table(events)


def render_settings(monitor: DnsRealtimeMonitor) -> None:
    st.markdown("## Settings")
    st.caption("Sensor configuration and local data controls")
    settings_col, sensor_col = st.columns(2)
    with settings_col:
        with st.container(border=True):
            st.markdown("### Risk thresholds")
            st.code(
                f"SAFE < {os.getenv('DNS_RISK_SUSPICIOUS_THRESHOLD', '30')}\n"
                f"SUSPICIOUS < {os.getenv('DNS_RISK_HIGH_THRESHOLD', '70')}\n"
                "DNS_VIRUSTOTAL_API_KEY=<optional>"
            )
            st.caption("Set thresholds and optional threat-intelligence configuration in the environment before starting the app.")
    with sensor_col:
        with st.container(border=True):
            st.markdown("### Capture interface")
            st.write(f"`{monitor.interface or 'system default'}`")
            st.caption("Captures visible UDP/TCP port 53 traffic. DoH, DoT, VPN routes and cached answers may not be observable.")
            if monitor.last_error:
                st.error(monitor.last_error)

    with st.container(border=True):
        st.markdown("### Local observation database")
        st.write(f"Database path: `{DB_PATH}`")
        st.warning("Clearing permanently deletes captured DNS events and their alerts.")
        confirm_clear = st.checkbox("Confirm deletion of captured records", key="confirm_clear_records")
        if st.button("Clear captured data", type="primary", disabled=not confirm_clear, icon=":material/delete:"):
            deleted = clear_observations()
            monitor.clear_session_tracking()
            st.success(f"Removed {deleted} captured DNS events and their alerts.")
            st.rerun()


def run_dashboard() -> None:
    st.set_page_config(
        page_title="DNS Security Monitor",
        page_icon="DNS",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    legacy_rows_cleared = init_db()
    monitor = get_global_monitor()
    if not st.session_state.get("capture_initialized"):
        monitor.start()
        st.session_state.capture_initialized = True

    st.markdown(
        """
        <style>
          @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
          :root { color-scheme: dark; --canvas: #0b1115; --panel: #111b21; --panel-raised: #152229;
            --border: #26353d; --text: #e5edf0; --muted: #91a3aa; --teal: #55d6be;
            --amber: #e7b866; --red: #ef7777; --blue: #79aef2; }
          .stApp { background: radial-gradient(ellipse at 82% 0%, rgba(42, 102, 103, .14), transparent 42%),
            linear-gradient(145deg, #0b1115 0%, #0d151a 55%, #10191e 100%); color: var(--text); }
          .stApp::before { content: ''; position: fixed; inset: 0; z-index: 0; pointer-events: none; opacity: .13;
            background-image: linear-gradient(rgba(112, 158, 165, .08) 1px, transparent 1px),
              linear-gradient(90deg, rgba(112, 158, 165, .08) 1px, transparent 1px);
            background-size: 44px 44px; mask-image: linear-gradient(to bottom, black, transparent 62%); }
          .block-container { position: relative; z-index: 1; max-width: 1640px; padding-top: 1.35rem; padding-bottom: 3rem; }
          [data-testid="stSidebar"] { background: linear-gradient(180deg, #101a20, #0e171c); border-right: 1px solid var(--border); }
          [data-testid="stSidebar"] > div:first-child { padding-top: 1.3rem; }
          [data-testid="stHeader"] { background: rgba(11, 17, 21, .72); }
          h1, h2, h3 { color: var(--text); letter-spacing: 0; }
          p, label, [data-testid="stCaptionContainer"] { color: var(--muted); }
          code, .stCode { font-family: 'IBM Plex Mono', Consolas, monospace; }
          div[data-testid="stMetric"] { background: linear-gradient(145deg, rgba(22, 34, 41, .96), rgba(17, 27, 33, .96));
            border: 1px solid var(--border); border-radius: 8px; padding: 16px 18px; box-shadow: 0 8px 22px rgba(0,0,0,.16); }
          div[data-testid="stMetricLabel"] { color: var(--muted); font-size: .76rem; }
          div[data-testid="stMetricValue"] { color: var(--text); font-weight: 650; }
          [data-testid="stVerticalBlockBorderWrapper"] { background: rgba(17, 27, 33, .88); border-color: var(--border); border-radius: 8px; }
          div[data-testid="stButton"] > button { border-radius: 6px; transition: border-color .16s ease, background .16s ease; }
          div[data-testid="stButton"] > button:hover { border-color: #4e7278; color: var(--text); }
          div[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 7px; overflow: hidden; }
          .brand-block { padding: 0 0 1.25rem; border-bottom: 1px solid var(--border); margin-bottom: 1.2rem; }
          .brand-line { display: flex; align-items: center; gap: 10px; color: var(--text); font-weight: 700; font-size: 1rem; }
          .brand-icon { width: 32px; height: 32px; display: grid; place-items: center; color: #10221f; background: var(--teal); border-radius: 7px; font-weight: 800; }
          .brand-sub { color: var(--muted); font-size: .67rem; margin: 5px 0 0 42px; letter-spacing: .08em; }
          .section-label { color: #80969e; font-size: .68rem; font-weight: 700; letter-spacing: .12em; margin: 1.1rem 0 .5rem; }
          .live-panel { display: flex; flex-direction: column; align-items: flex-end; gap: 5px; border: 1px solid var(--border);
            border-radius: 8px; background: rgba(17, 27, 33, .86); padding: 12px 15px; }
          .live-panel strong { color: var(--teal); font: 600 .75rem 'IBM Plex Mono', Consolas, monospace; letter-spacing: .06em; }
          .live-panel strong:has(+ .live-meta) { line-height: 1.3; }
          .live-dot { width: 8px; height: 8px; border-radius: 50%; position: relative; display: inline-block; margin-right: 7px; }
          .live-dot.online { background: var(--teal); box-shadow: 0 0 9px rgba(85,214,190,.45); }
          .live-dot.offline { background: var(--red); }
          .live-meta { color: var(--muted); font-size: .72rem; }
          .empty-state { min-height: 145px; display: flex; flex-direction: column; align-items: center; justify-content: center;
            gap: 8px; text-align: center; padding: 22px; border: 1px dashed #34464f; border-radius: 7px; color: var(--muted); background: rgba(11,17,21,.28); }
          .empty-state strong { color: #d5e0e3; font-size: .9rem; }
          .empty-state span { font-size: .78rem; max-width: 420px; }
          .empty-mark { color: #65818a; font-size: 1.5rem; }
          .alert-row { border: 1px solid var(--border); border-left-width: 3px; border-radius: 6px; padding: 12px; margin: 9px 0; background: rgba(11,17,21,.35); }
          .alert-high { border-left-color: var(--red); }
          .alert-medium { border-left-color: var(--amber); }
          .alert-heading { display: flex; justify-content: space-between; gap: 8px; align-items: center; margin-bottom: 8px; }
          .severity-pill { border-radius: 4px; padding: 3px 7px; font: 600 .65rem 'IBM Plex Mono', Consolas, monospace; }
          .severity-pill.high { background: rgba(239,119,119,.13); color: var(--red); }
          .severity-pill.medium { background: rgba(231,184,102,.13); color: var(--amber); }
          .alert-row strong { display: block; color: var(--text); font-size: .82rem; }
          .alert-domain { color: #b9c9cd; font: .72rem 'IBM Plex Mono', Consolas, monospace; margin-top: 7px; overflow-wrap: anywhere; }
          .alert-domain span { float: right; color: var(--amber); }
          .alert-reasons { color: var(--muted); font-size: .72rem; line-height: 1.55; margin-top: 7px; }
          .muted { color: var(--muted); font-size: .7rem; }
          @media (max-width: 760px) { .live-panel { align-items: flex-start; margin: 8px 0 14px; }
            .block-container { padding-left: 1rem; padding-right: 1rem; } }
          @media (prefers-reduced-motion: reduce) { *, *::before, *::after { transition: none !important; } }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if legacy_rows_cleared:
        st.info(f"Removed {legacy_rows_cleared} unprovenanced legacy records. The event log now contains captured observations only.")

    with st.sidebar:
        st.markdown(
            '<div class="brand-block"><div class="brand-line"><span class="brand-icon">D</span> DNS / SENTINEL</div>'
            '<div class="brand-sub">LOCAL RESOLVER TELEMETRY</div></div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="section-label">OPERATIONS</div>', unsafe_allow_html=True)
        pages = [
            "Dashboard", "Live DNS Monitor", "Domain Analysis", "Threat Detection",
            "DNS Anomalies", "Alerts", "Logs", "Settings",
        ]
        if "active_view" not in st.session_state:
            st.session_state.active_view = "Dashboard"
        page = st.radio("Navigation", pages, key="active_view", label_visibility="collapsed")
        st.divider()
        st.markdown('<div class="section-label">SENSOR</div>', unsafe_allow_html=True)
        if monitor.is_running and not monitor.last_error:
            st.success("Capture active")
            capture_button = "Pause packet capture"
        elif monitor.last_error:
            st.error("Capture unavailable")
            st.caption(monitor.last_error)
            capture_button = "Retry packet capture"
        else:
            st.warning("Capture paused")
            capture_button = "Start packet capture"
        if st.button(capture_button, width="stretch"):
            if monitor.is_running:
                monitor.stop()
            else:
                monitor.start()
            st.rerun()
        st.caption(f"Interface: `{monitor.interface or 'system default'}`")

    @st.fragment(run_every="2s")
    def top_status() -> None:
        latest = get_queries(limit=1)
        is_online = monitor.is_running and not monitor.last_error
        label = "LIVE MONITORING" if is_online else "SENSOR OFFLINE"
        status_class = "online" if is_online else "offline"
        left, right = st.columns([2, 1])
        with left:
            st.markdown("# DNS Security Operations")
            st.caption("Real-time host telemetry and defensive domain analysis")
        with right:
            st.markdown(
                f"""<div class="live-panel"><div><span class="live-dot {status_class}"></span>
                <strong>{label}</strong></div><span class="live-meta">Last event: {time_since(latest[0]['timestamp'] if latest else None)}</span>
                <span class="live-meta">Refreshed {datetime.now().astimezone().strftime('%H:%M:%S')}</span></div>""",
                unsafe_allow_html=True,
            )
    top_status()

    if page == "Dashboard":
        render_dashboard(monitor)
    elif page == "Live DNS Monitor":
        @st.fragment(run_every="2s")
        def live_monitor_view() -> None:
            render_live_monitor()
        live_monitor_view()
    elif page == "Domain Analysis":
        render_domain_analysis()
    elif page == "Threat Detection":
        render_threat_detection()
    elif page == "DNS Anomalies":
        @st.fragment(run_every="2s")
        def anomaly_view() -> None:
            render_anomalies()
        anomaly_view()
    elif page == "Alerts":
        @st.fragment(run_every="2s")
        def alerts_view() -> None:
            render_alerts()
        alerts_view()
    elif page == "Logs":
        @st.fragment(run_every="2s")
        def logs_view() -> None:
            render_logs()
        logs_view()
    else:
        render_settings(monitor)


if __name__ == "__main__":
    run_dashboard()
