import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from security.target_security import is_safe_target
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_safe_targets():
    assert is_safe_target("google.com") is True
    assert is_safe_target("8.8.8.8") is True
    assert is_safe_target("https://example.com") is True

def test_unsafe_targets():
    assert is_safe_target("localhost") is False
    assert is_safe_target("127.0.0.1") is False
    assert is_safe_target("10.0.0.1") is False
    assert is_safe_target("192.168.1.1") is False
    assert is_safe_target("http://169.254.169.254/latest/meta-data") is False
    assert is_safe_target("224.0.0.1") is False  # Multicast
    assert is_safe_target("240.0.0.1") is False  # Reserved

def test_api_rejection(client):
    r = client.post("/api/ping", json={"host": "127.0.0.1"})
    assert r.status_code == 403
    assert "Invalid or restricted target address" in r.get_json()["error"]
