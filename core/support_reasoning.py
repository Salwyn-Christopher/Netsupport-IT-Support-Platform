def analyze_diagnostics(results):
    ping = results.get("ping", {})
    dns = results.get("dns", {})
    http = results.get("http", {})
    ports = results.get("ports", [])

    # 1. DNS Failure
    if dns and dns.get("resolvable") is False:
        return {
            "likely_cause": "DNS resolution failure.",
            "recommended_action": "Verify DNS configuration, DNS server availability, and local network connectivity.",
            "customer_summary": "We identified a DNS resolution issue that may be preventing the requested service from being reached."
        }

    # 2. Ping Failure but DNS passes
    if ping and ping.get("reachable") is False and dns and dns.get("resolvable") is True:
        return {
            "likely_cause": "ICMP/TCP ping failure to a resolved host. Host may be offline or blocking ICMP.",
            "recommended_action": "Verify if the destination host is powered on, connected to the network, and whether ICMP traffic is permitted through intermediate firewalls.",
            "customer_summary": "The destination server's name resolves correctly, but it is not responding to our basic network reachability checks. This could be due to a firewall rule or the server being offline."
        }

    # 3. HTTP Failure
    if http and (http.get("reachable") is False or (http.get("status_code") and http.get("status_code") >= 500)):
        return {
            "likely_cause": "The destination web service may be unavailable or blocked.",
            "recommended_action": "Verify service availability on the destination server, firewall/proxy rules, and destination connectivity.",
            "customer_summary": "We can reach the server, but the web service itself appears to be unavailable or returning an error."
        }

    # 4. HTTP 4xx Client Error
    if http and http.get("status_code") and 400 <= http.get("status_code") < 500:
        return {
            "likely_cause": "Client-side error accessing the web resource (e.g., Not Found, Forbidden).",
            "recommended_action": "Verify the URL path, required permissions, and authentication requirements for the requested resource.",
            "customer_summary": "The server was reached successfully, but the specific page or resource could not be accessed."
        }

    # 5. SSL/TLS Issue
    ssl_info = http.get("ssl") if http else None
    if ssl_info and not ssl_info.get("valid", True):
        return {
            "likely_cause": "TLS/SSL certificate validation failed.",
            "recommended_action": "Check the certificate expiration date, hostname mismatch, or trust chain configuration on the destination server.",
            "customer_summary": "We established a connection, but there is an issue with the website's security certificate which may prevent secure access."
        }

    # 6. All clear
    return {
        "likely_cause": "No clear diagnostic indication of failure.",
        "recommended_action": "If the issue persists, perform deeper application-level tracing or check client-side configuration.",
        "customer_summary": "Our automated diagnostics did not find any obvious network or service availability issues from our vantage point."
    }
