#!/usr/bin/env python3
"""
Web Security Configuration Auditor
----------------------------------
Passive checks of a web target's HTTP security posture. Maps findings to
OWASP Top 10 (2021) categories and produces a Markdown or JSON report with
remediation guidance.

ONLY run this against systems you own or have explicit written permission
to test (e.g. a local OWASP Juice Shop container, your own site).

Usage:
    python3 audit.py https://example.com
    python3 audit.py http://localhost:3000 --format json -o report.json
"""
import argparse
import datetime as dt
import http.client
import json
import socket
import ssl
import sys
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
TIMEOUT = 8


@dataclass
class Finding:
    title: str
    severity: str
    owasp: str
    detail: str
    remediation: str


# (header, severity, why it matters, how to fix)
SECURITY_HEADERS = [
    ("Content-Security-Policy", "Medium",
     "No CSP means the browser has no policy limiting where scripts load from, "
     "which increases the impact of XSS.",
     "Add a restrictive policy, e.g. Content-Security-Policy: default-src 'self'; "
     "then tighten per-resource directives."),
    ("Strict-Transport-Security", "Medium",
     "Without HSTS, browsers may connect over plain HTTP, enabling SSL-stripping.",
     "Send Strict-Transport-Security: max-age=31536000; includeSubDomains "
     "(HTTPS responses only)."),
    ("X-Content-Type-Options", "Low",
     "Missing nosniff lets browsers MIME-sniff responses, enabling content-type confusion.",
     "Send X-Content-Type-Options: nosniff."),
    ("X-Frame-Options", "Low",
     "Page can be framed by other sites, enabling clickjacking "
     "(unless CSP frame-ancestors is set).",
     "Send X-Frame-Options: DENY (or SAMEORIGIN), or use CSP frame-ancestors."),
    ("Referrer-Policy", "Low",
     "Full URLs (possibly containing tokens or IDs) may leak to third parties via Referer.",
     "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter)."),
    ("Permissions-Policy", "Info",
     "Browser features (camera, geolocation, etc.) are not explicitly restricted.",
     "Send a Permissions-Policy header disabling unused features."),
]

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def request(scheme, host, port, path="/", method="GET", headers=None):
    """Single request, no redirect following. Returns (status, [(k, v), ...])."""
    if scheme == "https":
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    try:
        conn.request(method, path, headers=headers or {"User-Agent": "sec-auditor/1.0"})
        resp = conn.getresponse()
        resp.read(1024)
        return resp.status, resp.getheaders()
    finally:
        conn.close()


def hmap(headers):
    return {k.lower(): v for k, v in headers}


def check_headers(headers, scheme):
    findings = []
    h = hmap(headers)
    for name, sev, why, fix in SECURITY_HEADERS:
        if name == "Strict-Transport-Security" and scheme != "https":
            continue
        if name.lower() not in h:
            findings.append(Finding(f"Missing header: {name}", sev,
                                    "A05:2021 Security Misconfiguration", why, fix))
    for name in LEAKY_HEADERS:
        if name.lower() in h:
            findings.append(Finding(
                f"Information disclosure: {name}: {h[name.lower()]}", "Low",
                "A05:2021 Security Misconfiguration",
                "Version/technology details help attackers pick known exploits.",
                f"Remove or genericize the {name} header in server/framework config."))
    return findings


def check_cookies(headers, scheme):
    findings = []
    for k, v in headers:
        if k.lower() != "set-cookie":
            continue
        name = v.split("=", 1)[0]
        attrs = [a.strip().lower() for a in v.split(";")[1:]]
        if scheme == "https" and "secure" not in attrs:
            findings.append(Finding(
                f"Cookie '{name}' missing Secure flag", "Medium",
                "A02:2021 Cryptographic Failures",
                "Cookie may be sent over unencrypted HTTP and intercepted.",
                "Add the Secure attribute to the cookie."))
        if "httponly" not in attrs:
            findings.append(Finding(
                f"Cookie '{name}' missing HttpOnly flag", "Medium",
                "A05:2021 Security Misconfiguration",
                "JavaScript can read the cookie, so an XSS bug can steal the session.",
                "Add the HttpOnly attribute to session cookies."))
        if not any(a.startswith("samesite") for a in attrs):
            findings.append(Finding(
                f"Cookie '{name}' missing SameSite attribute", "Low",
                "A01:2021 Broken Access Control",
                "Cookie is sent on cross-site requests, which aids CSRF.",
                "Set SameSite=Lax (or Strict) and use anti-CSRF tokens on state changes."))
    return findings


def check_cors(scheme, host, port):
    findings = []
    try:
        _, hdrs = request(scheme, host, port, headers={
            "User-Agent": "sec-auditor/1.0", "Origin": "https://evil.example"})
    except Exception:
        return findings
    h = hmap(hdrs)
    acao = h.get("access-control-allow-origin")
    creds = h.get("access-control-allow-credentials", "").lower() == "true"
    if acao == "https://evil.example" and creds:
        findings.append(Finding(
            "CORS reflects arbitrary Origin with credentials allowed", "High",
            "A01:2021 Broken Access Control",
            "Any website can make authenticated cross-origin requests and read responses.",
            "Validate Origin against an explicit allowlist; never reflect it blindly "
            "when credentials are enabled."))
    elif acao == "*":
        findings.append(Finding(
            "CORS allows any origin (*)", "Low",
            "A05:2021 Security Misconfiguration",
            "Fine for public static content, risky for anything user-specific.",
            "Restrict Access-Control-Allow-Origin to trusted origins."))
    return findings


def check_https_redirect(host, port_http=80):
    try:
        status, hdrs = request("http", host, port_http)
    except Exception:
        return [Finding("Port 80 not reachable", "Info", "A02:2021 Cryptographic Failures",
                        "Could not test HTTP->HTTPS redirect.", "None required if intentional.")]
    loc = hmap(hdrs).get("location", "")
    if status in (301, 302, 307, 308) and loc.startswith("https://"):
        return []
    return [Finding("HTTP does not redirect to HTTPS", "Medium",
                    "A02:2021 Cryptographic Failures",
                    "Users who type the bare hostname may stay on unencrypted HTTP.",
                    "Return a 301 redirect from HTTP to HTTPS and enable HSTS.")]


def check_tls(host, port):
    findings = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                version = s.version()
                cert = s.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return [Finding("TLS certificate failed validation", "High",
                        "A02:2021 Cryptographic Failures", str(e),
                        "Install a valid, trusted certificate that matches the hostname.")]
    except Exception as e:
        return [Finding("TLS connection failed", "Info",
                        "A02:2021 Cryptographic Failures", str(e), "Verify HTTPS is enabled.")]
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(Finding(f"Weak TLS version negotiated: {version}", "High",
                                "A02:2021 Cryptographic Failures",
                                "Deprecated protocols have known weaknesses.",
                                "Disable anything below TLS 1.2; prefer TLS 1.3."))
    not_after = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    days = (not_after - dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)).days
    if days < 0:
        findings.append(Finding("TLS certificate expired", "High",
                                "A02:2021 Cryptographic Failures",
                                f"Expired {-days} days ago.", "Renew the certificate."))
    elif days < 30:
        findings.append(Finding(f"TLS certificate expires in {days} days", "Medium",
                                "A02:2021 Cryptographic Failures",
                                "Expiry will cause outages and browser warnings.",
                                "Renew now and automate renewal (e.g. ACME/Let's Encrypt)."))
    findings.append(Finding(f"TLS negotiated {version}; cert valid {days} more days", "Info",
                            "A02:2021 Cryptographic Failures", "Informational.", "None."))
    return findings


def audit(url):
    u = urlparse(url)
    scheme = u.scheme or "https"
    host = u.hostname
    port = u.port or (443 if scheme == "https" else 80)
    status, headers = request(scheme, host, port, u.path or "/")
    findings = []
    findings += check_headers(headers, scheme)
    findings += check_cookies(headers, scheme)
    findings += check_cors(scheme, host, port)
    if scheme == "https":
        findings += check_tls(host, port)
        findings += check_https_redirect(host)
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return {"target": url, "status": status,
            "scanned_at": dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat() + "Z", "findings": findings}


def to_markdown(r):
    counts = {}
    for f in r["findings"]:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines = [f"# Web Security Audit: {r['target']}", "",
             f"- Scanned: {r['scanned_at']}", f"- HTTP status: {r['status']}",
             "- Summary: " + ", ".join(f"{k}: {v}" for k, v in
                                       sorted(counts.items(), key=lambda x: SEVERITY_ORDER[x[0]])),
             "", "## Findings", ""]
    for i, f in enumerate(r["findings"], 1):
        lines += [f"### {i}. [{f.severity}] {f.title}", f"**OWASP:** {f.owasp}  ",
                  f"**Detail:** {f.detail}  ", f"**Remediation:** {f.remediation}", ""]
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="Passive web security configuration auditor")
    p.add_argument("url")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("-o", "--output")
    a = p.parse_args()
    print("[!] Only scan systems you own or are authorized to test.", file=sys.stderr)
    try:
        r = audit(a.url)
    except Exception as e:
        sys.exit(f"Scan failed: {e}")
    out = (json.dumps({**r, "findings": [asdict(f) for f in r["findings"]]}, indent=2)
           if a.format == "json" else to_markdown(r))
    if a.output:
        with open(a.output, "w") as fh:
            fh.write(out)
        print(f"Report written to {a.output}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
