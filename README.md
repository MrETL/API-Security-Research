# API Security Risk Analysis — OWASP crAPI

| Field | Details |
|-------|---------|
| Tester | Dilnessa Aemro |
| Date | April 2026 |
| Target | OWASP crAPI — https://crapi.apisec.ai |
| Methodology | OWASP API Security Top 10 (2023) |

---

## About This Project

This repository contains a hands-on security assessment of **OWASP crAPI** (Completely Ridiculous API) — an intentionally vulnerable REST API built by OWASP for security education. The assessment follows real-world penetration testing methodology, covering reconnaissance, exploitation, and remediation.

crAPI simulates an automotive marketplace with user authentication, vehicle management, workshop services, and a community forum — each module containing deliberate vulnerabilities aligned with the OWASP API Top 10.

**Official Resources:**
- OWASP Project: https://owasp.org/www-project-crapi/
- GitHub: https://github.com/OWASP/crAPI
- Hosted Instance: https://crapi.apisec.ai

---

## Repository Structure

```
FUTURE_CS_03/
├── README.md
└── report/
    ├── API_SECURITY_ASSESSMENT_REPORT.md   # Full assessment report
    └── API_SECURITY_ASSESSMENT_REPORT.pdf  # Professional PDF version
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| curl | HTTP request crafting and endpoint testing |
| jq | JSON response parsing |
| Browser DevTools | Traffic interception and request inspection |
| JWT.io | Token decoding and payload analysis |

---

## Vulnerabilities Confirmed

| # | Vulnerability | OWASP Category | Severity |
|---|--------------|----------------|----------|
| 1 | BOLA — Broken Object Level Authorization | API1:2023 | CRITICAL |
| 2 | Broken Authentication (OTP brute force + MailHog) | API2:2023 | CRITICAL |
| 3 | JWT Tampering (HS256, no expiry) | API2:2023 | HIGH |
| 4 | Mass Assignment | API3:2023 | HIGH |
| 5 | Excessive Data Exposure | API3:2023 | MEDIUM |
| 6 | Missing Rate Limiting | API6:2023 | MEDIUM |

All six vulnerabilities were confirmed through direct exploitation during testing.

---

## Analysis Approach

1. **Reconnaissance** — Mapped the full API surface, discovered hidden endpoints and an exposed MailHog mail server on port 8025
2. **Authentication Analysis** — Decoded JWT tokens, identified missing expiration claims and weak HS256 signing
3. **Authorization Testing** — Tested BOLA across mechanic records, service reports, and vehicle location endpoints
4. **Input Validation** — Tested mass assignment by injecting internal fields into write endpoints
5. **Response Analysis** — Audited API responses for excessive data exposure
6. **Rate Limiting** — Sent 50 consecutive failed login attempts to confirm absence of throttling

---

## Scope and Ethics

All testing was conducted exclusively against OWASP crAPI — an intentionally vulnerable platform designed for security education. No real users, systems, or data were involved at any point.

---

**Prepared By:** Dilnessa Aemro
**Program:** 
**Date:** April 2026
