"""Small authenticated bridge for forwarding local DNS sensor events to Streamlit Cloud.

Deploy this file as a separate web service (e.g. Render) with a persistent disk if you
want the event history to survive restarts. Set DNS_BRIDGE_TOKEN to a long random secret.
"""
import os, sqlite3, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

TOKEN = os.getenv("DNS_BRIDGE_TOKEN", "")
DB_PATH = Path(os.getenv("DNS_BRIDGE_DB", "data/dns_bridge.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
app = FastAPI(title="DNS Sensor Bridge", docs_url=None, redoc_url=None)

class Event(BaseModel):
    timestamp: str
    source_ip: str = "unknown"
    destination_ip: str = "unknown"
    domain: str = Field(min_length=1, max_length=253)
    query_type: str = "A"
    risk_score: int = Field(ge=0, le=100)
    status: str = "SAFE"
    reasons: list[str] = []
    anomaly: bool = False
    event_key: str = Field(min_length=32, max_length=128)
    response: str = "Awaiting matching DNS response"
    sensor_id: str = Field(default="local-sensor", max_length=128)

class Heartbeat(BaseModel):
    sensor_id: str = Field(default="local-sensor", max_length=128)
    hostname: str = Field(default="local-sensor", max_length=128)

def init_db() -> None:
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL, domain TEXT NOT NULL,
            query_type TEXT NOT NULL, risk_score INTEGER NOT NULL, status TEXT NOT NULL,
            reasons TEXT NOT NULL, anomaly INTEGER NOT NULL, event_key TEXT NOT NULL UNIQUE,
            response TEXT NOT NULL, sensor_id TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS heartbeats (
            sensor_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, last_seen REAL NOT NULL)""")
init_db()

def authorize(authorization: str | None) -> None:
    if not TOKEN:
        raise HTTPException(status_code=503, detail="DNS_BRIDGE_TOKEN is not configured on the server")
    if not authorization or authorization != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

@app.post("/heartbeat")
def heartbeat(body: Heartbeat, authorization: str | None = Header(default=None)) -> dict[str, bool]:
    authorize(authorization)
    with sqlite3.connect(DB_PATH) as db:
        db.execute("INSERT INTO heartbeats(sensor_id, hostname, last_seen) VALUES(?,?,?) "
                   "ON CONFLICT(sensor_id) DO UPDATE SET hostname=excluded.hostname,last_seen=excluded.last_seen",
                   (body.sensor_id, body.hostname, time.time()))
    return {"ok": True}

@app.get("/status")
def status(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    authorize(authorization)
    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute("SELECT sensor_id, hostname, last_seen FROM heartbeats ORDER BY last_seen DESC").fetchall()
    now = time.time()
    sensors = [{"sensor_id": r[0], "hostname": r[1], "last_seen": datetime.fromtimestamp(r[2], timezone.utc).isoformat(), "online": now-r[2] < 35} for r in rows]
    return {"online": any(s["online"] for s in sensors), "sensors": sensors}

@app.post("/events")
def create_event(body: Event, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    authorize(authorization)
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""INSERT INTO events(timestamp,source_ip,destination_ip,domain,query_type,risk_score,status,reasons,anomaly,event_key,response,sensor_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(event_key) DO UPDATE SET response=excluded.response""",
            (body.timestamp, body.source_ip, body.destination_ip, body.domain, body.query_type,
             body.risk_score, body.status, "\n".join(body.reasons), int(body.anomaly), body.event_key, body.response, body.sensor_id))
    return {"ok": True, "event_key": body.event_key}

@app.get("/events")
def get_events(limit: int = Query(default=500, ge=1, le=1000), authorization: str | None = Header(default=None)) -> dict[str, Any]:
    authorize(authorization)
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM (SELECT * FROM events ORDER BY id DESC LIMIT ?) ORDER BY id ASC", (limit,)).fetchall()
    events=[]
    for row in rows:
        item=dict(row); item["reasons"]=[x for x in item["reasons"].split("\n") if x]; item["anomaly"]=bool(item["anomaly"]); events.append(item)
    return {"events": events}

@app.post("/events/{event_key}/response")
def update_response(event_key: str, payload: dict[str, str], authorization: str | None = Header(default=None)) -> dict[str, bool]:
    authorize(authorization)
    response = payload.get("response", "")[:2000]
    with sqlite3.connect(DB_PATH) as db:
        db.execute("UPDATE events SET response=? WHERE event_key=?", (response, event_key))
    return {"ok": True}
