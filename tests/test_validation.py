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
    assert is_safe_target("google.com")[0] is True
    assert is_safe_target("8.8.8.8")[0] is True
    assert is_safe_target("https://example.com")[0] is True

def test_unsafe_targets():
    assert is_safe_target("localhost")[0] is False
    assert is_safe_target("127.0.0.1")[0] is False
    assert is_safe_target("10.0.0.1")[0] is False
    assert is_safe_target("192.168.1.1")[0] is False
    assert is_safe_target("http://169.254.169.254/latest/meta-data")[0] is False
    assert is_safe_target("224.0.0.1")[0] is False  # Multicast
    assert is_safe_target("240.0.0.1")[0] is False  # Reserved

def test_api_rejection(client, monkeypatch):
    class MockPing:
        called = False
        @classmethod
        def mock_ping_icmp(cls, *args, **kwargs):
            cls.called = True

    monkeypatch.setattr("app.ping_icmp", MockPing.mock_ping_icmp)
    unsafe_targets = [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "240.0.0.1"
    ]
    for target in unsafe_targets:
        r = client.post("/api/ping", json={"host": target})
        assert r.status_code == 403
        assert "Invalid or restricted target address" in r.get_json()["error"]

        # Verify diagnostic work was not started
        assert not MockPing.called
