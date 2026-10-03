import sqlite3
import uuid
import json
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))
import os
from contextlib import closing

DB_PATH = os.path.join(os.path.dirname(__file__), "incidents.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(get_db()) as conn:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    ticket_id TEXT UNIQUE,
                    customer TEXT,
                    target_host_or_url TEXT,
                    category TEXT,
                    issue TEXT,
                    priority TEXT,
                    status TEXT,
                    support_level TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    diagnostic_results TEXT,
                    troubleshooting_recommendation TEXT,
                    resolution_notes TEXT,
                    escalation_reason TEXT
                )
            """)

def generate_ticket_id():
    return f"INC-{datetime.now(IST).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

def create_incident(customer, target_host_or_url, category, issue, priority):
    ticket_id = generate_ticket_id()
    now = datetime.now(IST).isoformat()
    with closing(get_db()) as conn:
        with conn:
            conn.execute("""
                INSERT INTO incidents (
                    id, ticket_id, customer, target_host_or_url, category, issue, priority, status, support_level, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Open', 'L1', ?, ?)
            """, (uuid.uuid4().hex, ticket_id, customer, target_host_or_url, category, issue, priority, now, now))
    return get_incident(ticket_id)

def get_incident(ticket_id):
    with closing(get_db()) as conn:
        row = conn.execute("SELECT * FROM incidents WHERE ticket_id = ?", (ticket_id,)).fetchone()
        return dict(row) if row else None

def list_incidents():
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

def update_incident_status(ticket_id, status, support_level=None, resolution_notes=None, escalation_reason=None):
    now = datetime.now(IST).isoformat()
    updates = ["status = ?", "updated_at = ?"]
    params = [status, now]

    if support_level is not None:
        updates.append("support_level = ?")
        params.append(support_level)
    if resolution_notes is not None:
        updates.append("resolution_notes = ?")
        params.append(resolution_notes)
    if escalation_reason is not None:
        updates.append("escalation_reason = ?")
        params.append(escalation_reason)

    params.append(ticket_id)
    query = f"UPDATE incidents SET {', '.join(updates)} WHERE ticket_id = ?"

    with closing(get_db()) as conn:
        with conn:
            conn.execute(query, params)
    return get_incident(ticket_id)

def attach_diagnostics(ticket_id, results, recommendation):
    now = datetime.now(IST).isoformat()
    with closing(get_db()) as conn:
        with conn:
            conn.execute("""
                UPDATE incidents
                SET diagnostic_results = ?, troubleshooting_recommendation = ?, updated_at = ?
                WHERE ticket_id = ?
            """, (json.dumps(results), json.dumps(recommendation), now, ticket_id))
    return get_incident(ticket_id)
