"""
app.py — Flask web dashboard for NetSupport – IT Support Incident Management Platform.

Provides a REST API and modern web interface for running
network diagnostics without the command line.

Deployable on Render, Fly.io (free tier) or locally.
"""

import os
import json
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, jsonify, Response

IST = timezone(timedelta(hours=5, minutes=30))

from diagnostics import (
    ping_icmp, ping_tcp, resolve_domain,
    scan_ports, scan_common, scan_port_group,
    check_endpoint, bulk_check, traceroute
)
from reports import generate_markdown_report, generate_json_report
from security.target_security import is_safe_target
from core import incident_store
from core import support_reasoning

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

# Initialize the database
incident_store.init_db()


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ── Web Routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    """Health check endpoint for platform uptime monitoring."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(IST).isoformat(),
        "service": "netsupport",
        "version": "1.0.0",
        "commit": os.environ.get("RENDER_GIT_COMMIT", "unknown")
    })


# ── API Routes ────────────────────────────────────────────────────────────────

@app.route("/api/ping", methods=["POST"])
def api_ping():
    data = request.get_json(silent=True) or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "host is required"}), 400
    is_safe, resolved_ip = is_safe_target(host)
    if not is_safe:
        return jsonify({"error": "Invalid or restricted target address."}), 403

    count   = min(int(data.get("count", 4)), 8)
    timeout = min(int(data.get("timeout", 3)), 10)

    try:
        result = ping_icmp(resolved_ip or host, count=count, timeout=timeout)
    except Exception:
        result = ping_tcp(resolved_ip or host, timeout=timeout)

    return jsonify({
        "host":              result.host,
        "reachable":         result.reachable,
        "method":            result.method,
        "latency_ms":        result.latency_ms,
        "packet_loss_pct":   result.packet_loss_pct,
        "packets_sent":      result.packets_sent,
        "packets_received":  result.packets_received,
        "error":             result.error,
    })


@app.route("/api/dns", methods=["POST"])
def api_dns():
    data   = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    is_safe, _ = is_safe_target(domain)
    if not is_safe:
        return jsonify({"error": "Invalid or restricted target address."}), 403

    result = resolve_domain(domain)
    return jsonify({
        "domain":           result.domain,
        "resolvable":       result.resolvable,
        "resolution_ms":    result.resolution_ms,
        "ipv4_addresses":   result.ipv4_addresses,
        "ipv6_addresses":   result.ipv6_addresses,
        "mx_records":       result.mx_records,
        "nameservers":      result.nameservers,
        "cname":            result.cname,
        "error":            result.error,
    })


@app.route("/api/ports", methods=["POST"])
def api_ports():
    data = request.get_json(silent=True) or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "host is required"}), 400
    is_safe, resolved_ip = is_safe_target(host)
    if not is_safe:
        return jsonify({"error": "Invalid or restricted target address."}), 403

    ports   = data.get("ports")
    group   = data.get("group")
    timeout = min(float(data.get("timeout", 2)), 5)

    try:
        target_ip = resolved_ip or host
        if ports:
            ports = [int(p) for p in ports[:50]]  # cap at 50
            results = scan_ports(target_ip, ports, timeout=timeout)
        elif group:
            results = scan_port_group(target_ip, group, timeout=timeout)
        else:
            results = scan_common(target_ip)

        return jsonify([{
            "port":       r.port,
            "service":    r.service,
            "state":      r.state,
            "latency_ms": r.latency_ms,
            "banner":     r.banner,
        } for r in results])

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/http", methods=["POST"])
def api_http():
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    is_safe, _ = is_safe_target(url)
    if not is_safe:
        return jsonify({"error": "Invalid or restricted target address."}), 403

    timeout = min(int(data.get("timeout", 10)), 15)
    result  = check_endpoint(url, timeout=timeout)

    ssl_data = None
    if result.ssl_info:
        ssl = result.ssl_info
        ssl_data = {
            "valid":              ssl.valid,
            "subject":            ssl.subject,
            "issuer":             ssl.issuer,
            "expires":            ssl.expires,
            "days_until_expiry":  ssl.days_until_expiry,
            "error":              ssl.error,
        }

    return jsonify({
        "url":                  result.url,
        "reachable":            result.reachable,
        "status_code":          result.status_code,
        "status_text":          result.status_text,
        "status_category":      result.status_category,
        "response_ms":          result.response_ms,
        "content_type":         result.content_type,
        "server_header":        result.server_header,
        "final_url":            result.final_url,
        "ssl":                  ssl_data,
        "error":                result.error,
    })


@app.route("/api/traceroute", methods=["POST"])
def api_traceroute():
    data = request.get_json(silent=True) or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "host is required"}), 400
    is_safe, resolved_ip = is_safe_target(host)
    if not is_safe:
        return jsonify({"error": "Invalid or restricted target address."}), 403

    max_hops = min(int(data.get("max_hops", 20)), 30)
    timeout  = min(int(data.get("timeout", 3)), 5)

    result = traceroute(resolved_ip or host, max_hops=max_hops, timeout=timeout)
    return jsonify({
        "destination":    result.destination,
        "destination_ip": result.destination_ip,
        "reached":        result.reached,
        "total_hops":     result.total_hops,
        "error":          result.error,
        "hops": [{
            "number":      h.number,
            "ip":          h.ip,
            "hostname":    h.hostname,
            "latency_ms":  h.latency_ms,
            "avg_latency": h.avg_latency_ms,
            "timed_out":   h.timed_out,
        } for h in result.hops],
    })


@app.route("/api/full-scan", methods=["POST"])
def api_full_scan():
    """Run all diagnostics against a host and return a combined report."""
    data = request.get_json(silent=True) or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "host is required"}), 400
    is_safe, resolved_ip = is_safe_target(host)
    if not is_safe:
        return jsonify({"error": "Invalid or restricted target address."}), 403

    timeout = min(int(data.get("timeout", 5)), 10)
    report  = {"target": host, "timestamp": datetime.now(IST).isoformat()}

    # Ping
    try:
        p = ping_icmp(resolved_ip or host, count=3, timeout=timeout)
        report["ping"] = {
            "reachable": p.reachable,
            "method":    p.method,
            "latency_ms": p.latency_ms,
            "packet_loss_pct": p.packet_loss_pct,
        }
    except Exception as e:
        report["ping"] = {"error": str(e)}

    # DNS
    try:
        d = resolve_domain(host)
        report["dns"] = {
            "resolvable":     d.resolvable,
            "resolution_ms":  d.resolution_ms,
            "ipv4_addresses": d.ipv4_addresses,
        }
    except Exception as e:
        report["dns"] = {"error": str(e)}

    # Common ports
    try:
        pr = scan_common(resolved_ip or host)
        report["ports"] = [{
            "port":    r.port,
            "service": r.service,
            "state":   r.state,
        } for r in pr if r.state == "open"]
    except Exception as e:
        report["ports"] = {"error": str(e)}

    # HTTP
    try:
        hr = check_endpoint(f"https://{host}", timeout=timeout)
        report["http"] = {
            "url":         hr.url,
            "status_code": hr.status_code,
            "status_text": hr.status_text,
            "response_ms": hr.response_ms,
            "reachable":   hr.reachable,
        }
    except Exception as e:
        report["http"] = {"error": str(e)}

    return jsonify(report)


@app.route("/api/report/markdown", methods=["POST"])
def api_report_markdown():
    """Generate a Markdown incident report from provided diagnostic data."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "unknown")
    report = generate_markdown_report(
        target=target,
        analyst=data.get("analyst", "Salwyn Christopher"),
        ticket_id=data.get("ticket_id")
    )
    return Response(report, mimetype="text/markdown",
                    headers={"Content-Disposition": f"attachment; filename=report_{target}.md"})


# ── Incident Management Routes ────────────────────────────────────────────────

@app.route("/api/incidents", methods=["GET"])
def api_list_incidents():
    return jsonify(incident_store.list_incidents())

@app.route("/api/incidents", methods=["POST"])
def api_create_incident():
    data = request.get_json(silent=True) or {}
    customer = data.get("customer", "").strip()
    target_host_or_url = data.get("target_host_or_url", "").strip()
    category = data.get("category", "Other").strip()
    issue = data.get("issue", "").strip()
    priority = data.get("priority", "Medium").strip()

    if not customer or not issue or not target_host_or_url:
        return jsonify({"error": "customer, target, and issue are required"}), 400

    is_safe, _ = is_safe_target(target_host_or_url)
    if not is_safe:
        return jsonify({"error": "Invalid or restricted target address."}), 403

    incident = incident_store.create_incident(customer, target_host_or_url, category, issue, priority)
    return jsonify(incident)

@app.route("/api/incidents/<ticket_id>", methods=["GET"])
def api_get_incident(ticket_id):
    incident = incident_store.get_incident(ticket_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify(incident)

@app.route("/api/incidents/<ticket_id>/status", methods=["POST"])
def api_update_incident_status(ticket_id):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    support_level = data.get("support_level")
    resolution_notes = data.get("resolution_notes")
    escalation_reason = data.get("escalation_reason")

    if not status:
        return jsonify({"error": "status is required"}), 400

    valid_statuses = ['Open', 'Investigating', 'Diagnosed', 'Escalated', 'Resolved']
    if status not in valid_statuses:
        return jsonify({"error": "invalid status"}), 400

    incident = incident_store.update_incident_status(ticket_id, status, support_level, resolution_notes, escalation_reason)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify(incident)

@app.route("/api/incidents/<ticket_id>/diagnostics", methods=["POST"])
def api_attach_diagnostics(ticket_id):
    data = request.get_json(silent=True) or {}
    results = data.get("results")
    if not results:
        return jsonify({"error": "results are required"}), 400

    recommendation = support_reasoning.analyze_diagnostics(results)
    incident = incident_store.attach_diagnostics(ticket_id, results, recommendation)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify(incident)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "production") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
