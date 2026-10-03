# Salwyn-Christopher / netsupport-it-support-platform

# NetSupport
### IT Support & Network Diagnostics Platform

**Python • Flask • SQLite • Networking • REST API • Pytest**

`[Incident Management]` `[Diagnostics]` `[L1/L2 Workflow]` `[Security Validation]` `[Automated Tests]`

---

Support engineers need to collect network evidence, investigate incidents, document findings, escalate difficult cases, and record resolution.

NetSupport combines network diagnostics with incident management and L1/L2 support workflow to streamline this exact process.

## My Contributions

- incident management architecture
- SQLite persistence
- ticket lifecycle
- L1/L2 workflow
- escalation
- resolution tracking
- diagnostic evidence
- rule-based support reasoning
- target security validation
- API integration
- UI/UX redesign
- Quick Target workflow
- automated testing
- deployment configuration
- documentation

## Upstream Attribution

NetSupport incorporates/adapts networking functionality from the MIT-licensed Network Diagnostic Toolkit by Sandrine Uwineza. See [PROVENANCE.md](PROVENANCE.md) for details.

## Architecture

                NetSupport UI
                     |
                Flask API
          ___________|____________
         |           |            |
     Incidents   Diagnostics   Support Reasoning
         |           |            |
      SQLite      Network      Rule-based analysis
                     |
             Target Security
                 Validation

## Core Features

- Network diagnostics
- DNS checks
- Ping/latency
- TCP port checks
- HTTP/HTTPS
- TLS
- Traceroute
- Incident management
- L1/L2 escalation
- Diagnostic evidence
- Rule-based troubleshooting
- Target validation
- API
- Automated testing

## License

This project contains upstream MIT-licensed material. See the `LICENSE` file for the original copyright and permission notice.
