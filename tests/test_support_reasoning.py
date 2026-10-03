import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.support_reasoning import analyze_diagnostics

def test_dns_failure():
    rec = analyze_diagnostics({"dns": {"resolvable": False}})
    assert "DNS resolution failure" in rec["likely_cause"]

def test_ping_failure():
    rec = analyze_diagnostics({"ping": {"reachable": False}, "dns": {"resolvable": True}})
    assert "ICMP/TCP ping failure to a resolved host" in rec["likely_cause"]

def test_http_failure():
    rec = analyze_diagnostics({"http": {"reachable": False}})
    assert "destination web service may be unavailable" in rec["likely_cause"]

def test_http_4xx():
    rec = analyze_diagnostics({"http": {"reachable": True, "status_code": 404}})
    assert "Client-side error" in rec["likely_cause"]

def test_ssl_failure():
    rec = analyze_diagnostics({"http": {"reachable": True, "status_code": 200, "ssl": {"valid": False}}})
    assert "TLS/SSL certificate validation failed" in rec["likely_cause"]

def test_all_clear():
    rec = analyze_diagnostics({"http": {"reachable": True, "status_code": 200, "ssl": {"valid": True}}, "dns": {"resolvable": True}, "ping": {"reachable": True}})
    assert "No clear diagnostic indication of failure" in rec["likely_cause"]
