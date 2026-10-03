import pytest
import sqlite3
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app import app
from core import incident_store as incidents

@pytest.fixture
def client(tmp_path):
    app.config["TESTING"] = True
    test_db = tmp_path / "test_incidents.db"
    incidents.DB_PATH = str(test_db)
    incidents.init_db()
    with app.test_client() as client:
        yield client
    # The database file can be safely deleted or ignored since it's in tmp_path
    if os.path.exists(str(test_db)):
        os.remove(str(test_db))

def test_incident_creation(client):
    r = client.post("/api/incidents", json={
        "customer": "Test Corp",
        "target_host_or_url": "example.com",
        "category": "DNS",
        "issue": "Cannot resolve internal domain",
        "priority": "High"
    })
    assert r.status_code == 200
    data = r.get_json()
    assert "ticket_id" in data
    assert data["customer"] == "Test Corp"
    assert data["target_host_or_url"] == "example.com"
    assert data["status"] == "Open"

def test_list_incidents(client):
    client.post("/api/incidents", json={"customer": "A", "target_host_or_url": "example.com", "issue": "A"})
    client.post("/api/incidents", json={"customer": "B", "target_host_or_url": "example.com", "issue": "B"})
    r = client.get("/api/incidents")
    assert r.status_code == 200
    assert len(r.get_json()) == 2

def test_missing_fields(client):
    r = client.post("/api/incidents", json={"customer": "Test Corp", "issue": "A"})
    assert r.status_code == 400

def test_escalation(client):
    r = client.post("/api/incidents", json={"customer": "A", "target_host_or_url": "example.com", "issue": "A"})
    ticket_id = r.get_json()["ticket_id"]

    r2 = client.post(f"/api/incidents/{ticket_id}/status", json={
        "status": "Escalated",
        "support_level": "L2",
        "escalation_reason": "Needs deeper investigation"
    })
    assert r2.status_code == 200
    data = r2.get_json()
    assert data["status"] == "Escalated"
    assert data["support_level"] == "L2"
    assert data["escalation_reason"] == "Needs deeper investigation"

def test_resolution(client):
    r = client.post("/api/incidents", json={"customer": "A", "target_host_or_url": "example.com", "issue": "A"})
    ticket_id = r.get_json()["ticket_id"]

    r2 = client.post(f"/api/incidents/{ticket_id}/status", json={
        "status": "Resolved",
        "resolution_notes": "Fixed DNS entry."
    })
    assert r2.status_code == 200
    data = r2.get_json()
    assert data["status"] == "Resolved"
    assert data["resolution_notes"] == "Fixed DNS entry."

def test_unknown_ticket(client):
    r = client.get("/api/incidents/UNKNOWN-123")
    assert r.status_code == 404

def test_attach_diagnostics(client):
    r = client.post("/api/incidents", json={"customer": "A", "target_host_or_url": "example.com", "issue": "A"})
    ticket_id = r.get_json()["ticket_id"]

    r2 = client.post(f"/api/incidents/{ticket_id}/diagnostics", json={
        "results": {"ping": {"reachable": False}}
    })
    assert r2.status_code == 200
    data = r2.get_json()
    assert data["diagnostic_results"] is not None
    assert data["troubleshooting_recommendation"] is not None

def test_unsafe_target_rejection(client):
    r = client.post("/api/incidents", json={
        "customer": "Test Corp",
        "target_host_or_url": "127.0.0.1",
        "category": "Other",
        "issue": "Bad target",
        "priority": "Low"
    })
    assert r.status_code == 403

def test_invalid_status(client):
    r = client.post("/api/incidents", json={"customer": "A", "target_host_or_url": "example.com", "issue": "A"})
    ticket_id = r.get_json()["ticket_id"]

    r2 = client.post(f"/api/incidents/{ticket_id}/status", json={
        "status": "FakeStatus",
        "support_level": "L2"
    })
    assert r2.status_code == 400
    assert "error" in r2.get_json()
