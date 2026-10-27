# Web Security Configuration Auditor

A Python tool that passively audits a web target's HTTP security posture and
produces a report mapped to the **OWASP Top 10 (2021)** with remediation steps.
Standard library only, so there are no dependencies to install.

> **Authorized use only.** Run it against systems you own or have written
> permission to test (e.g. a local OWASP Juice Shop container).

## What it checks

| Area | Checks | OWASP category |
|---|---|---|
| Response headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | A05 Security Misconfiguration |
| Info disclosure | `Server`, `X-Powered-By`, framework version headers | A05 |
| Cookies | `Secure`, `HttpOnly`, `SameSite` flags | A02, A05, A01 |
| CORS | Reflected origin with credentials, wildcard origin | A01 Broken Access Control |
| Transport | TLS version, certificate validity/expiry, HTTP->HTTPS redirect | A02 Cryptographic Failures |

## Usage

```bash
python3 audit.py https://your-site.example
python3 audit.py http://localhost:3000 -o report.md
python3 audit.py http://localhost:3000 --format json -o report.json
```

See `sample_report.md` for output from a deliberately misconfigured local
test server (1 High, 2 Medium, 6 Low findings).

## Design notes

- Passive only: one GET per check, no payloads, no brute forcing.
- Redirects are not followed, so the tool can inspect the redirect itself.
- Findings are sorted by severity, each with an explanation and a concrete fix.

## Ideas to extend it (these make the project stronger)

1. **Add a test suite** (`pytest`) that runs the auditor against a local mock server.
2. **Run it against OWASP Juice Shop** in Docker and write up the findings.
3. **Add a CI workflow** that fails the build if any High finding appears.
4. **Add a CVSS-style score** and sort the report by it.
5. **Scan multiple URLs** from a file, with a combined summary.
6. **Add a banner-to-CVE lookup** for versions found in leaky headers.

## Resume bullets (pick 2-3, adjust to what you actually built)

- Built a Python web security auditor that checks HTTP headers, cookie flags,
  CORS policy, and TLS configuration, mapping each finding to OWASP Top 10
  categories with prioritized remediation guidance.
- Validated the tool against intentionally vulnerable targets (OWASP Juice
  Shop, a custom misconfigured server) and produced Markdown/JSON reports
  suitable for engineering and compliance review.
- Automated recurring configuration checks by integrating the scanner into
  a CI pipeline, failing builds on high-severity findings.

## Skills demonstrated

HTTP/HTTPS and TLS fundamentals, common web attack classes and mitigations,
OWASP Top 10, Python scripting, secure reporting and remediation writing.
