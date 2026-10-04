# NetSupport
## IT Support & Network Diagnostics Platform

1. Overview
2. Key Capabilities
3. Incident Management
4. Network Diagnostics
5. Support Reasoning
6. Security Validation
7. Architecture
8. Technology Stack
9. API Overview
10. Screenshots / Demo
11. Local Setup
12. Testing
13. Deployment
14. Known Hosting Limitations

---

## 1. Overview
NetSupport is a streamlined platform combining network diagnostics with incident management and L1/L2 support workflows. It enables support engineers to investigate network issues, collect diagnostic evidence, escalate difficult cases, and document resolutions.

## 2. Key Capabilities
- **Unified Interface:** Run diagnostics and manage incidents from a single dashboard.
- **Automated Evidence Collection:** Diagnostic results are automatically attached to support tickets.
- **Rule-Based Analysis:** Translates raw networking data into actionable support insights.
- **Target Security:** Strict SSRF protections and target sanitization.

## 3. Incident Management
The platform features a complete ticket lifecycle:
- Create, open, investigate, diagnose, escalate, and resolve incidents.
- Track L1/L2 workflow progression.
- Persist incident data via SQLite.

## 4. Network Diagnostics
Integrated networking tools for real-time investigation:
- DNS resolution checks
- Ping and latency measurements
- TCP port scanning
- HTTP/HTTPS endpoint validation
- Traceroute

## 5. Support Reasoning
A deterministic, rule-based reasoning module interprets diagnostic output (e.g., DNS failures, port closures) to recommend troubleshooting steps without relying on external AI APIs.

## 6. Security Validation
Strict validation prevents Server-Side Request Forgery (SSRF) and localized path traversal. Network calls are only permitted against safe targets, actively blocking loopback (127.0.0.1, ::1) and internal IP ranges before execution.

## 7. Architecture
```text
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
```

## 8. Technology Stack
- **Backend:** Python, Flask
- **Persistence:** SQLite
- **Network Core:** dnspython, subprocess-based diagnostics
- **API:** REST
- **Testing:** Pytest

## 9. API Overview
- `GET /api/incidents`: List all incidents.
- `POST /api/incidents`: Create a new incident.
- `GET /api/incidents/<id>`: Retrieve incident details.
- `POST /api/incidents/<id>/status`: Update status and notes.
- `POST /api/ping`, `/api/dns`, `/api/ports`, `/api/http`: Execute network diagnostics.

## 10. Screenshots / Demo
*Screenshots and live demo link will be added once deployed.*

## 11. Local Setup
```bash
# Clone repository
git clone https://github.com/Salwyn-Christopher/Netsupport-IT-Support-Platform.git
cd Netsupport-IT-Support-Platform

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Start application
python app.py
```
Access the application at `http://127.0.0.1:5000`.

## 12. Testing
The project includes a comprehensive Pytest suite covering diagnostics, reasoning, incidents, and validation.
```bash
python -m pytest tests/ -v
python -m pytest tests/ --cov=.
```

## 13. Deployment
The application is configured for deployment on Render using Gunicorn.
- **Procfile:** `web: gunicorn app:app`
- **Configuration:** `render.yaml`
- **Dependencies:** `requirements.txt`

## 14. Known Hosting Limitations
**Render Free Tier Deployment:** The application stores incidents dynamically in a local SQLite database (`core/incidents.db`). Because Render's Free tier utilizes ephemeral filesystems, the database will be reset and incident data will be wiped out whenever the application sleeps or is redeployed. This stateless behavior is by design for this portfolio demonstration. For durable persistence, migrate to PostgreSQL.
