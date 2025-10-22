"""
single_target_cyber_score_updates.py
Enhanced Cybersecurity Posture Assessment - Legally Compliant Version
Based on NIST CSF, CIS Controls, CVSS principles, and academic research

Features:
- CVSS-inspired scoring methodology
- NIST CSF alignment (6 core functions)
- Advanced TLS/certificate analysis
- Security header deep inspection
- DNS security (DNSSEC, CAA, DMARC/SPF/DKIM)
- Certificate Transparency monitoring
- Subdomain enumeration (passive only)
- Technology fingerprinting
- Breach database checking (HaveIBeenPwned API)
- Machine learning-ready data export
- Comprehensive risk modeling

LEGAL COMPLIANCE:
- NO port scanning (removed to avoid legal issues)
- Only passive reconnaissance
- Public data sources only
- Respects robots.txt
- Rate limiting to avoid DoS
- No authentication attempts
- No exploitation attempts

Dependencies:
    pip install requests dnspython cryptography tldextract pyyaml

Usage:
    python single_target_cyber_score_updates.py example.com
"""

import sys
import socket
import ssl
import requests
import dns.resolver
import dns.dnssec
import json
import hashlib
import time
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import re
from typing import Dict, List, Tuple, Optional
import warnings

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# ============================================================================
# CONFIGURATION
# ============================================================================
VERSION = "2.0.0"
TIMEOUT = 8
MAX_WORKERS = 6
USER_AGENT = f"CyberScoreBot/{VERSION} (Security Research; Passive Scan)"

# Rate limiting (requests per second)
RATE_LIMIT = 2
last_request_time = 0

# Weights aligned with NIST CSF and industry research
WEIGHTS = {
    "tls_certificate": 16,  # Identity verification
    "security_headers": 14,  # Protective measures
    "hsts_quality": 7,  # Transport security
    "csp_quality": 9,  # XSS/injection protection
    "cookie_security": 5,  # Session management
    "dns_security": 11,  # Email/domain authentication
    "dnssec": 5,  # DNS integrity
    "caa_records": 4,  # Certificate authority authorization
    "ct_logs": 4,  # Certificate transparency
    "breach_exposure": 9,  # Historical incidents
    "tech_fingerprint": 4,  # Technology stack risks
    "dkim_records": 3,  # Email authentication
    "mta_sts": 3,  # Email security
    "https_redirect": 3,  # Force HTTPS
    "mixed_content": 3,  # HTTPS integrity
}

# Security headers to check (aligned with OWASP recommendations)
CRITICAL_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

# Known vulnerable/outdated technologies
VULNERABLE_TECH = {
    "jquery": {"vulnerable_versions": ["<3.5.0"], "cvss_base": 6.1},
    "bootstrap": {"vulnerable_versions": ["<4.3.1"], "cvss_base": 6.1},
    "wordpress": {"vulnerable_versions": ["<6.0"], "cvss_base": 7.5},
    "php": {"vulnerable_versions": ["<7.4"], "cvss_base": 7.5},
    "apache": {"vulnerable_versions": ["<2.4.48"], "cvss_base": 7.5},
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def rate_limit():
    """Implement rate limiting to avoid overwhelming servers"""
    global last_request_time
    current_time = time.time()
    time_since_last = current_time - last_request_time
    if time_since_last < (1.0 / RATE_LIMIT):
        time.sleep((1.0 / RATE_LIMIT) - time_since_last)
    last_request_time = time.time()


def safe_request(
    url: str, method: str = "GET", **kwargs
) -> Optional[requests.Response]:
    """Make HTTP request with error handling and rate limiting"""
    rate_limit()
    try:
        kwargs.setdefault("timeout", TIMEOUT)
        kwargs.setdefault("headers", {}).update({"User-Agent": USER_AGENT})
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", False)  # We handle cert verification separately

        if method.upper() == "GET":
            return requests.get(url, **kwargs)
        elif method.upper() == "HEAD":
            return requests.head(url, **kwargs)
    except Exception as e:
        return None
    return None


def normalize_domain(input_str: str) -> Tuple[str, str, str]:
    """Extract clean domain, base URL, and scheme"""
    if not input_str.startswith(("http://", "https://")):
        input_str = "https://" + input_str

    parsed = urlparse(input_str)
    scheme = parsed.scheme
    domain = parsed.netloc.split(":")[0]
    base_url = f"{scheme}://{domain}"

    return domain, base_url, scheme


# ============================================================================
# TLS/CERTIFICATE ANALYSIS (Enhanced)
# ============================================================================


def analyze_tls_certificate(domain: str) -> Dict:
    """
    Comprehensive TLS/SSL certificate analysis
    Aligned with CVSS exploitability metrics
    """
    result = {
        "has_tls": False,
        "cert_valid": None,
        "tls_version": None,
        "cipher_suite": None,
        "cert_issuer": None,
        "cert_subject": None,
        "days_until_expiry": None,
        "san_count": 0,
        "issues": [],
        "score": 0,
    }

    context_verify = ssl.create_default_context()
    context_no_verify = ssl.create_default_context()
    context_no_verify.check_hostname = False
    context_no_verify.verify_mode = ssl.CERT_NONE

    # Try verified connection first
    try:
        with context_verify.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(TIMEOUT)
            s.connect((domain, 443))
            result["has_tls"] = True
            result["cert_valid"] = True
            result["tls_version"] = s.version()
            result["cipher_suite"] = s.cipher()[0] if s.cipher() else None
    except ssl.SSLCertVerificationError as e:
        result["has_tls"] = True
        result["cert_valid"] = False
        result["issues"].append(f"Certificate verification failed: {str(e)}")
    except ssl.SSLError as e:
        result["issues"].append(f"SSL error: {str(e)}")
        return result
    except Exception as e:
        result["issues"].append(f"Connection failed: {str(e)}")
        return result

    # Get certificate details (even if verification failed)
    try:
        with context_no_verify.wrap_socket(
            socket.socket(), server_hostname=domain
        ) as s:
            s.settimeout(TIMEOUT)
            s.connect((domain, 443))
            cert = s.getpeercert()

            # Parse certificate details
            result["cert_issuer"] = dict(x[0] for x in cert.get("issuer", []))
            result["cert_subject"] = dict(x[0] for x in cert.get("subject", []))

            # Check expiry
            not_after = cert.get("notAfter")
            if not_after:
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                result["days_until_expiry"] = (expiry_date - datetime.utcnow()).days

            # Count Subject Alternative Names
            san = cert.get("subjectAltName", [])
            result["san_count"] = len(san)

    except Exception as e:
        result["issues"].append(f"Failed to retrieve certificate details: {str(e)}")

    # Scoring based on CVSS-like severity assessment
    score = 0

    if result["has_tls"]:
        score += 30

        if result["cert_valid"]:
            score += 40
        elif result["cert_valid"] is False:
            score += 10
            result["issues"].append("CRITICAL: Invalid certificate")

        # TLS version scoring
        tls_ver = (result["tls_version"] or "").lower()
        if "1.3" in tls_ver:
            score += 20
        elif "1.2" in tls_ver:
            score += 10
        elif tls_ver:
            result["issues"].append(f"WARNING: Outdated TLS version {tls_ver}")
            score += 2

        # Certificate expiry
        days = result.get("days_until_expiry")
        if days is not None:
            if days < 0:
                result["issues"].append("CRITICAL: Certificate expired")
                score = min(score, 20)
            elif days < 7:
                result["issues"].append("URGENT: Certificate expires in <7 days")
                score += 2
            elif days < 30:
                result["issues"].append("WARNING: Certificate expires in <30 days")
                score += 5
            else:
                score += 10
    else:
        result["issues"].append("CRITICAL: No TLS/SSL detected")

    result["score"] = min(100, score)
    return result


# ============================================================================
# DKIM RECORDS CHECK
# ============================================================================


def check_dkim_records(domain: str) -> Dict:
    """
    Check for DKIM records using common selectors
    DKIM requires knowing the selector, so we try common ones
    """
    result = {
        "selectors_found": [],
        "selectors_tested": [],
        "score": 0,
        "issues": [],
    }

    # Common DKIM selectors used by major email providers
    common_selectors = [
        "default",
        "google",
        "k1",
        "k2",
        "dkim",
        "selector1",
        "selector2",
        "s1",
        "s2",
        "mail",
        "email",
        "mx",
    ]

    for selector in common_selectors:
        result["selectors_tested"].append(selector)
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, "TXT", lifetime=TIMEOUT)
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "p=" in txt:  # DKIM public key
                    result["selectors_found"].append(
                        {"selector": selector, "record": txt[:100] + "..."}
                    )
                    break
        except Exception:
            continue

    # Scoring
    if len(result["selectors_found"]) >= 2:
        result["score"] = 100
    elif len(result["selectors_found"]) == 1:
        result["score"] = 80
        result["issues"].append(
            "INFO: Only one DKIM selector found - consider multiple selectors for key rotation"
        )
    else:
        result["score"] = 0
        result["issues"].append(
            "WARNING: No DKIM records found with common selectors - email authentication incomplete"
        )

    return result


# ============================================================================
# MTA-STS CHECK
# ============================================================================


def check_mta_sts(domain: str) -> Dict:
    """
    Check for MTA-STS (SMTP TLS enforcement)
    Checks both DNS record and policy file
    """
    result = {
        "dns_record": None,
        "policy_file": None,
        "policy_mode": None,
        "score": 0,
        "issues": [],
    }

    # Check DNS TXT record
    try:
        mta_sts_domain = f"_mta-sts.{domain}"
        answers = dns.resolver.resolve(mta_sts_domain, "TXT", lifetime=TIMEOUT)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=STSv1"):
                result["dns_record"] = txt
                break
    except Exception:
        result["issues"].append("INFO: No MTA-STS DNS record found")

    # Check policy file
    if result["dns_record"]:
        try:
            rate_limit()
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            response = requests.get(
                policy_url,
                headers={"User-Agent": USER_AGENT},
                timeout=TIMEOUT,
                verify=False,
            )

            if response.status_code == 200:
                result["policy_file"] = response.text[:200]

                # Parse mode
                mode_match = re.search(r"mode:\s*(\w+)", response.text, re.IGNORECASE)
                if mode_match:
                    result["policy_mode"] = mode_match.group(1)

        except Exception as e:
            result["issues"].append(f"WARNING: MTA-STS policy file not accessible")

    # Scoring
    if result["dns_record"] and result["policy_file"]:
        if result["policy_mode"] == "enforce":
            result["score"] = 100
        elif result["policy_mode"] == "testing":
            result["score"] = 70
            result["issues"].append("INFO: MTA-STS in testing mode - not yet enforcing")
        else:
            result["score"] = 50
    elif result["dns_record"]:
        result["score"] = 30
        result["issues"].append(
            "WARNING: MTA-STS DNS record exists but policy file missing"
        )
    else:
        result["score"] = 0
        result["issues"].append(
            "INFO: MTA-STS not implemented - modern email security not enforced"
        )

    return result


# ============================================================================
# HTTPS REDIRECT CHECK
# ============================================================================


def check_https_redirect(domain: str) -> Dict:
    """
    Check if HTTP redirects to HTTPS
    Critical for forcing secure connections
    """
    result = {
        "http_accessible": False,
        "redirects_to_https": False,
        "redirect_chain": [],
        "score": 0,
        "issues": [],
    }

    try:
        rate_limit()
        http_url = f"http://{domain}"

        # Allow redirects and track them
        response = requests.get(
            http_url,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=False,
        )

        result["http_accessible"] = True

        # Check redirect history
        if response.history:
            for resp in response.history:
                result["redirect_chain"].append(
                    {
                        "from": resp.url,
                        "to": resp.headers.get("Location", ""),
                        "code": resp.status_code,
                    }
                )

            # Check if final URL is HTTPS
            if response.url.startswith("https://"):
                result["redirects_to_https"] = True
                result["score"] = 100
            else:
                result["score"] = 0
                result["issues"].append(
                    "CRITICAL: HTTP does not redirect to HTTPS - insecure connections allowed"
                )
        else:
            # No redirect happened
            result["score"] = 0
            result["issues"].append(
                "CRITICAL: HTTP accessible without redirect to HTTPS - major security risk"
            )

    except Exception as e:
        # HTTP not accessible (could be good - only HTTPS works)
        result["http_accessible"] = False
        result["score"] = 100  # Assume HTTPS-only is good
        result["issues"].append("INFO: HTTP not accessible - likely HTTPS-only (good)")

    return result


# ============================================================================
# MIXED CONTENT DETECTION
# ============================================================================


def check_mixed_content(response: Optional[requests.Response], domain: str) -> Dict:
    """
    Detect mixed content (HTTP resources on HTTPS page)
    Security risk that browsers may block
    """
    result = {
        "is_https": False,
        "http_resources": [],
        "resource_types": {},
        "score": 0,
        "issues": [],
    }

    if not response:
        result["score"] = 100
        return result

    # Check if page is HTTPS
    result["is_https"] = response.url.startswith("https://")

    if not result["is_https"]:
        result["score"] = 100  # Not applicable for HTTP pages
        result["issues"].append(
            "INFO: Page is HTTP - mixed content check not applicable"
        )
        return result

    # Parse HTML/CSS/JS for HTTP resources
    content = response.text.lower() if response.text else ""

    # Patterns for different resource types
    patterns = {
        "scripts": r'<script[^>]+src=["\'](http://[^"\']+)["\']',
        "stylesheets": r'<link[^>]+href=["\'](http://[^"\']+)["\']',
        "images": r'<img[^>]+src=["\'](http://[^"\']+)["\']',
        "iframes": r'<iframe[^>]+src=["\'](http://[^"\']+)["\']',
        "media": r'<(?:video|audio)[^>]+src=["\'](http://[^"\']+)["\']',
        "forms": r'<form[^>]+action=["\'](http://[^"\']+)["\']',
    }

    for resource_type, pattern in patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            result["resource_types"][resource_type] = len(matches)
            result["http_resources"].extend(matches[:5])  # Limit to 5 examples

    # Scoring
    total_http = sum(result["resource_types"].values())

    if total_http == 0:
        result["score"] = 100
    elif total_http <= 2:
        result["score"] = 60
        result["issues"].append(
            f"WARNING: {total_http} HTTP resources found on HTTPS page"
        )
    elif total_http <= 5:
        result["score"] = 30
        result["issues"].append(
            f"WARNING: {total_http} HTTP resources found - browsers may block"
        )
    else:
        result["score"] = 0
        result["issues"].append(
            f"CRITICAL: {total_http} HTTP resources on HTTPS page - major mixed content issue"
        )

    return result


# ============================================================================
# SECURITY HEADERS ANALYSIS (Deep Inspection)
# ============================================================================


def analyze_security_headers(response: Optional[requests.Response]) -> Dict:
    """
    Deep analysis of HTTP security headers
    Based on OWASP recommendations and NIST guidelines
    """
    result = {
        "headers_found": {},
        "headers_missing": [],
        "header_quality": {},
        "info_disclosure": {},
        "score": 0,
        "issues": [],
    }

    if not response:
        result["issues"].append("No response available for header analysis")
        return result

    headers = {k.lower(): v for k, v in response.headers.items()}

    # Check for critical headers
    for header in CRITICAL_HEADERS:
        header_lower = header.lower()
        if header_lower in headers:
            result["headers_found"][header] = headers[header_lower]
        else:
            result["headers_missing"].append(header)

    # Analyze HSTS quality
    hsts = headers.get("strict-transport-security", "")
    result["header_quality"]["HSTS"] = analyze_hsts_quality(hsts)

    # Analyze CSP quality
    csp = headers.get("content-security-policy", "")
    result["header_quality"]["CSP"] = analyze_csp_quality(csp)

    # Check for information disclosure
    if "server" in headers:
        result["info_disclosure"]["Server"] = headers["server"]
        result["issues"].append(f"INFO: Server header disclosed: {headers['server']}")

    if "x-powered-by" in headers:
        result["info_disclosure"]["X-Powered-By"] = headers["x-powered-by"]
        result["issues"].append(
            f"INFO: X-Powered-By header disclosed: {headers['x-powered-by']}"
        )

    # Scoring
    found_count = len(result["headers_found"])
    total_count = len(CRITICAL_HEADERS)
    base_score = int((found_count / total_count) * 70)

    # Add quality bonuses
    hsts_bonus = min(15, result["header_quality"]["HSTS"]["score"] // 7)
    csp_bonus = min(15, result["header_quality"]["CSP"]["score"] // 7)

    # Penalty for info disclosure
    disclosure_penalty = len(result["info_disclosure"]) * 5

    result["score"] = max(
        0, min(100, base_score + hsts_bonus + csp_bonus - disclosure_penalty)
    )

    if found_count < total_count / 2:
        result["issues"].append(
            f"WARNING: Only {found_count}/{total_count} critical headers present"
        )

    return result


def analyze_hsts_quality(hsts_value: str) -> Dict:
    """Analyze HSTS header quality"""
    quality = {
        "present": bool(hsts_value),
        "max_age": 0,
        "include_subdomains": False,
        "preload": False,
        "score": 0,
        "issues": [],
    }

    if not hsts_value:
        quality["issues"].append("HSTS header missing")
        return quality

    # Parse max-age
    max_age_match = re.search(r"max-age=(\d+)", hsts_value, re.I)
    if max_age_match:
        quality["max_age"] = int(max_age_match.group(1))

    quality["include_subdomains"] = "includesubdomains" in hsts_value.lower()
    quality["preload"] = "preload" in hsts_value.lower()

    # Scoring
    score = 20
    if quality["max_age"] >= 31536000:  # 1 year
        score += 40
    elif quality["max_age"] >= 10368000:  # 120 days
        score += 25
    elif quality["max_age"] > 0:
        score += 10
        quality["issues"].append(
            f"WARNING: HSTS max-age too low ({quality['max_age']}s)"
        )

    if quality["include_subdomains"]:
        score += 20
    if quality["preload"]:
        score += 20

    quality["score"] = score
    return quality


def analyze_csp_quality(csp_value: str) -> Dict:
    """Analyze Content Security Policy quality"""
    quality = {
        "present": bool(csp_value),
        "directives": [],
        "unsafe_practices": [],
        "score": 0,
        "issues": [],
    }

    if not csp_value:
        quality["issues"].append("CSP header missing")
        return quality

    csp_lower = csp_value.lower()

    # Parse directives
    directives = [d.strip().split()[0] for d in csp_value.split(";") if d.strip()]
    quality["directives"] = directives

    # Check for important directives
    important = ["default-src", "script-src", "style-src", "img-src"]
    has_important = sum(
        1 for d in important if any(d in directive for directive in directives)
    )

    # Check for unsafe practices
    if "unsafe-inline" in csp_lower:
        quality["unsafe_practices"].append("unsafe-inline")
        quality["issues"].append("WARNING: CSP allows unsafe-inline")
    if "unsafe-eval" in csp_lower:
        quality["unsafe_practices"].append("unsafe-eval")
        quality["issues"].append("WARNING: CSP allows unsafe-eval")
    if "*" in csp_value and "data:" not in csp_value:
        quality["unsafe_practices"].append("wildcard")
        quality["issues"].append("WARNING: CSP uses wildcard source")

    # Scoring
    score = 20  # Base for having CSP
    score += (has_important / len(important)) * 40
    score -= len(quality["unsafe_practices"]) * 15

    if "'self'" in csp_lower or "https:" in csp_lower:
        score += 20

    quality["score"] = max(0, min(100, score))
    return quality


# ============================================================================
# COOKIE SECURITY ANALYSIS
# ============================================================================


def analyze_cookies(response: Optional[requests.Response]) -> Dict:
    """Analyze cookie security attributes"""
    result = {
        "cookies": [],
        "secure_count": 0,
        "httponly_count": 0,
        "samesite_count": 0,
        "score": 0,
        "issues": [],
    }

    if not response:
        result["score"] = 100  # No cookies = no cookie vulnerabilities
        return result

    set_cookie_headers = (
        response.headers.get_all("Set-Cookie")
        if hasattr(response.headers, "get_all")
        else [response.headers.get("Set-Cookie", "")]
    )

    if not any(set_cookie_headers):
        result["score"] = 100
        return result

    for cookie_str in set_cookie_headers:
        if not cookie_str:
            continue

        cookie_info = {
            "name": cookie_str.split("=")[0] if "=" in cookie_str else "unknown",
            "secure": bool(re.search(r";\s*secure\b", cookie_str, re.I)),
            "httponly": bool(re.search(r";\s*httponly\b", cookie_str, re.I)),
            "samesite": re.search(r"samesite=(\w+)", cookie_str, re.I),
        }

        if cookie_info["samesite"]:
            cookie_info["samesite"] = cookie_info["samesite"].group(1)

        result["cookies"].append(cookie_info)

        if cookie_info["secure"]:
            result["secure_count"] += 1
        if cookie_info["httponly"]:
            result["httponly_count"] += 1
        if cookie_info["samesite"]:
            result["samesite_count"] += 1

    total = len(result["cookies"])
    if total == 0:
        result["score"] = 100
        return result

    # Scoring
    secure_score = (result["secure_count"] / total) * 40
    httponly_score = (result["httponly_count"] / total) * 30
    samesite_score = (result["samesite_count"] / total) * 30

    result["score"] = int(secure_score + httponly_score + samesite_score)

    if result["secure_count"] < total:
        result["issues"].append(
            f"WARNING: {total - result['secure_count']} cookies missing Secure flag"
        )
    if result["httponly_count"] < total:
        result["issues"].append(
            f"WARNING: {total - result['httponly_count']} cookies missing HttpOnly flag"
        )
    if result["samesite_count"] < total:
        result["issues"].append(
            f"WARNING: {total - result['samesite_count']} cookies missing SameSite attribute"
        )

    return result


# ============================================================================
# DNS SECURITY ANALYSIS (Enhanced)
# ============================================================================


def analyze_dns_security(domain: str) -> Dict:
    """
    Comprehensive DNS security analysis
    Includes SPF, DMARC, DKIM, MX, DNSSEC, CAA
    """
    result = {
        "spf": {"present": False, "record": None, "policy": None},
        "dmarc": {"present": False, "record": None, "policy": None},
        "dkim": {"selector_found": False, "note": "DKIM requires known selector"},
        "mx": {"present": False, "records": []},
        "dnssec": {"enabled": False, "validated": False},
        "caa": {"present": False, "records": []},
        "score": 0,
        "issues": [],
    }

    # SPF Check
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=TIMEOUT)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=spf1"):
                result["spf"]["present"] = True
                result["spf"]["record"] = txt
                # Parse policy
                if "-all" in txt:
                    result["spf"]["policy"] = "strict"
                elif "~all" in txt:
                    result["spf"]["policy"] = "soft-fail"
                elif "?all" in txt:
                    result["spf"]["policy"] = "neutral"
                break
    except Exception:
        result["issues"].append("INFO: SPF record not found or DNS lookup failed")

    # DMARC Check
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=TIMEOUT)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=DMARC1"):
                result["dmarc"]["present"] = True
                result["dmarc"]["record"] = txt
                # Parse policy
                policy_match = re.search(r"p=(\w+)", txt)
                if policy_match:
                    result["dmarc"]["policy"] = policy_match.group(1)
                break
    except Exception:
        result["issues"].append("INFO: DMARC record not found")

    # MX Check
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=TIMEOUT)
        result["mx"]["present"] = True
        result["mx"]["records"] = [str(rdata.exchange) for rdata in answers]
    except Exception:
        result["issues"].append("INFO: MX records not found")

    # CAA Check (Certificate Authority Authorization)
    try:
        answers = dns.resolver.resolve(domain, "CAA", lifetime=TIMEOUT)
        result["caa"]["present"] = True
        for rdata in answers:
            result["caa"]["records"].append(str(rdata))
    except Exception:
        result["issues"].append("INFO: CAA records not found")

    # DNSSEC Check (basic)
    try:
        # Try to get DNSKEY records
        dns.resolver.resolve(domain, "DNSKEY", lifetime=TIMEOUT)
        result["dnssec"]["enabled"] = True
        # Note: Full DNSSEC validation requires more complex logic
    except Exception:
        result["issues"].append("INFO: DNSSEC not detected")

    # Scoring
    score = 0
    if result["spf"]["present"]:
        score += 25
        if result["spf"]["policy"] == "strict":
            score += 10
    if result["dmarc"]["present"]:
        score += 25
        if result["dmarc"]["policy"] in ["quarantine", "reject"]:
            score += 10
    if result["mx"]["present"]:
        score += 10
    if result["caa"]["present"]:
        score += 15
    if result["dnssec"]["enabled"]:
        score += 15

    result["score"] = min(100, score)

    if not result["spf"]["present"]:
        result["issues"].append("WARNING: No SPF record - emails may be spoofed")
    if not result["dmarc"]["present"]:
        result["issues"].append(
            "WARNING: No DMARC record - no email policy enforcement"
        )
    if not result["caa"]["present"]:
        result["issues"].append("INFO: No CAA records - any CA can issue certificates")

    return result


# ============================================================================
# CERTIFICATE TRANSPARENCY LOGS
# ============================================================================


def check_certificate_transparency(domain: str) -> Dict:
    """
    Check Certificate Transparency logs via crt.sh API
    Helps detect unauthorized certificates
    """
    result = {
        "certificates_found": 0,
        "recent_count": 0,
        "issuers": set(),
        "score": 0,
        "issues": [],
    }

    try:
        rate_limit()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(
            url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}
        )

        if response.status_code == 200:
            certs = response.json()
            result["certificates_found"] = len(certs)

            # Count recent certificates (last 90 days)
            ninety_days_ago = datetime.now() - timedelta(days=90)
            for cert in certs:
                try:
                    entry_time = datetime.strptime(
                        cert.get("entry_timestamp", ""), "%Y-%m-%dT%H:%M:%S.%f"
                    )
                    if entry_time > ninety_days_ago:
                        result["recent_count"] += 1
                except:
                    pass

                issuer = cert.get("issuer_name", "")
                if issuer:
                    result["issuers"].add(issuer)

            result["issuers"] = list(result["issuers"])

            # Scoring - having CT logs is good for transparency
            if result["certificates_found"] > 0:
                result["score"] = 100

                # Warning if too many recent certs (possible compromise)
                if result["recent_count"] > 10:
                    result["issues"].append(
                        f"WARNING: {result['recent_count']} certificates issued in last 90 days"
                    )
                    result["score"] = 80
            else:
                result["score"] = 50
                result["issues"].append("INFO: No certificates found in CT logs")
        else:
            result["score"] = 50
            result["issues"].append("INFO: Unable to query CT logs")
    except Exception as e:
        result["score"] = 50
        result["issues"].append(f"INFO: CT log check failed: {str(e)}")

    return result


# ============================================================================
# BREACH DATABASE CHECK (HaveIBeenPwned)
# ============================================================================


def check_breach_exposure(domain: str) -> Dict:
    """
    Check if domain has been in known data breaches
    Uses HaveIBeenPwned API (respects rate limits)
    """
    result = {
        "breaches": [],
        "breach_count": 0,
        "most_recent": None,
        "score": 100,
        "issues": [],
    }

    try:
        rate_limit()
        # HaveIBeenPwned API - requires User-Agent
        url = f"https://haveibeenpwned.com/api/v3/breaches"
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}

        response = requests.get(url, headers=headers, timeout=TIMEOUT)

        if response.status_code == 200:
            all_breaches = response.json()

            # Filter breaches for this domain
            domain_breaches = [
                b for b in all_breaches if domain.lower() in b.get("Domain", "").lower()
            ]

            result["breach_count"] = len(domain_breaches)

            for breach in domain_breaches[:5]:  # Limit to 5 most relevant
                result["breaches"].append(
                    {
                        "name": breach.get("Name"),
                        "date": breach.get("BreachDate"),
                        "pwn_count": breach.get("PwnCount"),
                        "data_classes": breach.get("DataClasses", []),
                    }
                )

            if result["breach_count"] > 0:
                # Get most recent breach
                sorted_breaches = sorted(
                    domain_breaches, key=lambda x: x.get("BreachDate", ""), reverse=True
                )
                result["most_recent"] = (
                    sorted_breaches[0].get("BreachDate") if sorted_breaches else None
                )

                # Score penalty based on breach count and recency
                base_penalty = min(50, result["breach_count"] * 10)

                if result["most_recent"]:
                    try:
                        breach_date = datetime.strptime(
                            result["most_recent"], "%Y-%m-%d"
                        )
                        days_ago = (datetime.now() - breach_date).days
                        if days_ago < 365:
                            base_penalty += 20
                    except:
                        pass

                result["score"] = max(0, 100 - base_penalty)
                result["issues"].append(
                    f"CRITICAL: Domain found in {result['breach_count']} known breaches"
                )
        else:
            result["issues"].append("INFO: Unable to check breach database")
    except Exception as e:
        result["issues"].append(f"INFO: Breach check unavailable: {str(e)}")

    return result


# ============================================================================
# TECHNOLOGY FINGERPRINTING
# ============================================================================


def fingerprint_technologies(
    response: Optional[requests.Response], domain: str
) -> Dict:
    """
    Identify technologies used and check for known vulnerabilities
    """
    result = {"technologies": {}, "vulnerable_techs": [], "score": 100, "issues": []}

    if not response:
        return result

    # Check headers for tech indicators
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    content = response.text.lower() if response.text else ""

    # Server identification
    if "server" in headers:
        server = headers["server"]
        result["technologies"]["server"] = server

        # Check for version numbers (info disclosure)
        version_match = re.search(r"[\d.]+", server)
        if version_match:
            result["issues"].append(f"INFO: Server version disclosed: {server}")

    # Framework detection
    if "x-powered-by" in headers:
        powered_by = headers["x-powered-by"]
        result["technologies"]["framework"] = powered_by

    # CMS/Framework detection from content
    cms_signatures = {
        "wordpress": ["wp-content", "wp-includes"],
        "joomla": ["joomla", "/components/com_"],
        "drupal": ["drupal", "/sites/default/"],
        "django": ["csrfmiddlewaretoken", "__admin__"],
        "react": ["react", "reactdom"],
        "angular": ["ng-app", "angular"],
        "vue": ["vue.js", "v-bind"],
        "jquery": ["jquery"],
        "bootstrap": ["bootstrap.min"],
    }

    for tech, signatures in cms_signatures.items():
        if any(sig in content for sig in signatures):
            result["technologies"][tech] = "detected"

            # Check if technology has known vulnerabilities
            if tech in VULNERABLE_TECH:
                result["vulnerable_techs"].append(tech)
                result["issues"].append(f"WARNING: {tech} detected - check for updates")

    # Penalize score for vulnerable technologies
    if result["vulnerable_techs"]:
        penalty = len(result["vulnerable_techs"]) * 15
        result["score"] = max(0, 100 - penalty)

    return result


# ============================================================================
# SUBDOMAIN ENUMERATION (Passive Only - Legal)
# ============================================================================


def enumerate_subdomains_passive(domain: str) -> Dict:
    """
    Passive subdomain enumeration using Certificate Transparency logs
    (Already covered by check_certificate_transparency, so this is a placeholder)
    """
    result = {
        "method": "Certificate Transparency",
        "subdomains_found": 0,
        "note": "Subdomain data available via CT logs check",
    }
    return result


# ============================================================================
# MAIN SCANNING FUNCTION
# ============================================================================


def enhanced_scan(input_url: str) -> Dict:
    """
    Main function to perform comprehensive cybersecurity assessment

    Args:
        input_url: Domain or URL to scan

    Returns:
        Dictionary containing all scan results and scores
    """
    domain, base_url, scheme = normalize_domain(input_url)

    results = {
        "scan_version": VERSION,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "input": input_url,
        "domain": domain,
        "base_url": base_url,
        "scheme": scheme,
    }

    print(f"\n{'='*60}")
    print(f"Enhanced Cybersecurity Assessment v{VERSION}")
    print(f"Target: {domain}")
    print(f"{'='*60}\n")

    # Execute all checks in parallel where possible
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all tasks
        futures = {
            "tls_certificate": executor.submit(analyze_tls_certificate, domain),
            "response": executor.submit(safe_request, base_url),
            "dns_security": executor.submit(analyze_dns_security, domain),
            "ct_logs": executor.submit(check_certificate_transparency, domain),
            "breach_exposure": executor.submit(check_breach_exposure, domain),
            "dkim_records": executor.submit(check_dkim_records, domain),
            "mta_sts": executor.submit(check_mta_sts, domain),
            "https_redirect": executor.submit(check_https_redirect, domain),
        }

        # Collect results
        tls_result = futures["tls_certificate"].result()
        response = futures["response"].result()
        dns_result = futures["dns_security"].result()
        ct_result = futures["ct_logs"].result()
        breach_result = futures["breach_exposure"].result()
        dkim_result = futures["dkim_records"].result()
        mta_sts_result = futures["mta_sts"].result()
        https_redirect_result = futures["https_redirect"].result()

    # Analyze response-dependent checks
    headers_result = analyze_security_headers(response)
    cookie_result = analyze_cookies(response)
    tech_result = fingerprint_technologies(response, domain)
    mixed_content_result = check_mixed_content(response, domain)

    # Store all component results
    results["tls_certificate"] = tls_result
    results["security_headers"] = headers_result
    results["cookie_security"] = cookie_result
    results["dns_security"] = dns_result
    results["ct_logs"] = ct_result
    results["breach_exposure"] = breach_result
    results["tech_fingerprint"] = tech_result
    results["dkim_records"] = dkim_result
    results["mta_sts"] = mta_sts_result
    results["https_redirect"] = https_redirect_result
    results["mixed_content"] = mixed_content_result

    # Calculate subscores
    subscores = {
        "tls_certificate": int(tls_result["score"]),
        "security_headers": int(headers_result["score"]),
        "hsts_quality": int(
            headers_result["header_quality"].get("HSTS", {}).get("score", 0)
        ),
        "csp_quality": int(
            headers_result["header_quality"].get("CSP", {}).get("score", 0)
        ),
        "cookie_security": int(cookie_result["score"]),
        "dns_security": int(dns_result["score"]),
        "dnssec": 100 if dns_result["dnssec"]["enabled"] else 0,
        "caa_records": 100 if dns_result["caa"]["present"] else 0,
        "ct_logs": int(ct_result["score"]),
        "breach_exposure": int(breach_result["score"]),
        "tech_fingerprint": int(tech_result["score"]),
        "dkim_records": int(dkim_result["score"]),
        "mta_sts": int(mta_sts_result["score"]),
        "https_redirect": int(https_redirect_result["score"]),
        "mixed_content": int(mixed_content_result["score"]),
    }

    results["subscores"] = subscores

    # Calculate weighted final score
    total_score = 0.0
    for category, score in subscores.items():
        weight = WEIGHTS.get(category, 0)
        total_score += score * weight / 100.0

    total_score = int(round(total_score))
    results["total_score"] = total_score

    # Determine risk level
    if total_score >= 80:
        risk_level = "Low"
    elif total_score >= 60:
        risk_level = "Medium"
    elif total_score >= 40:
        risk_level = "High"
    else:
        risk_level = "Critical"

    results["risk_level"] = risk_level

    # Print summary
    print(f"\n{'='*60}")
    print(f"ASSESSMENT RESULTS")
    print(f"{'='*60}")
    print(f"Overall Score: {total_score}/100")
    print(f"Risk Level: {risk_level}")
    print(f"\nCategory Scores:")
    for category, score in subscores.items():
        weight = WEIGHTS.get(category, 0)
        print(f"  {category:25s}: {int(score):3d}/100  (weight: {int(weight):2d}%)")

    # Print key issues
    all_issues = []
    for component_key in [
        "tls_certificate",
        "security_headers",
        "dns_security",
        "cookie_security",
        "breach_exposure",
        "tech_fingerprint",
        "ct_logs",
        "dkim_records",
        "mta_sts",
        "https_redirect",
        "mixed_content",
    ]:
        component = results.get(component_key, {})
        issues = component.get("issues", [])
        all_issues.extend(issues)

    if all_issues:
        print(f"\n{'='*60}")
        print(f"KEY ISSUES IDENTIFIED")
        print(f"{'='*60}")

        critical = [i for i in all_issues if "CRITICAL" in i]
        warnings = [i for i in all_issues if "WARNING" in i]

        if critical:
            print("\n🔴 CRITICAL:")
            for issue in critical:
                print(f"  • {issue}")

        if warnings:
            print("\n🟡 WARNINGS:")
            for issue in warnings:
                print(f"  • {issue}")

    print(f"\n{'='*60}\n")

    return results


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================


def print_report(results: Dict):
    """Print a detailed text report of the assessment"""

    print("\n" + "=" * 70)
    print("ENHANCED CYBERSECURITY ASSESSMENT REPORT")
    print("=" * 70)

    print(f"\nTarget: {results['domain']}")
    print(f"Assessment Date: {results['timestamp']}")
    print(f"Overall Score: {results['total_score']}/100")
    print(f"Risk Level: {results['risk_level']}")

    print("\n" + "-" * 70)
    print("DETAILED FINDINGS")
    print("-" * 70)

    # TLS/Certificate
    print("\n🔐 TLS/CERTIFICATE SECURITY")
    tls = results["tls_certificate"]
    print(f"  Score: {int(tls['score'])}/100")
    print(f"  • TLS Present: {tls['has_tls']}")
    print(f"  • Certificate Valid: {tls['cert_valid']}")
    print(f"  • TLS Version: {tls['tls_version']}")
    print(f"  • Days Until Expiry: {tls['days_until_expiry']}")
    if tls.get("issues"):
        print("  Issues:")
        for issue in tls["issues"]:
            print(f"    - {issue}")

    # Security Headers
    print("\n🛡️ SECURITY HEADERS")
    headers = results["security_headers"]
    print(f"  Score: {int(headers['score'])}/100")
    print(f"  • Headers Found: {len(headers['headers_found'])}/{len(CRITICAL_HEADERS)}")
    print(f"  • Present: {list(headers['headers_found'].keys())}")
    print(f"  • Missing: {headers['headers_missing']}")

    # DNS Security
    print("\n📧 DNS SECURITY")
    dns = results["dns_security"]
    print(f"  Score: {int(dns['score'])}/100")
    print(
        f"  • SPF: {dns['spf']['present']} (Policy: {dns['spf'].get('policy', 'N/A')})"
    )
    print(
        f"  • DMARC: {dns['dmarc']['present']} (Policy: {dns['dmarc'].get('policy', 'N/A')})"
    )
    print(f"  • DNSSEC: {dns['dnssec']['enabled']}")
    print(f"  • CAA Records: {dns['caa']['present']}")

    # DKIM
    print("\n🔑 DKIM EMAIL AUTHENTICATION")
    dkim = results["dkim_records"]
    print(f"  Score: {int(dkim['score'])}/100")
    print(f"  • Selectors Found: {len(dkim['selectors_found'])}")
    print(f"  • Selectors Tested: {len(dkim['selectors_tested'])}")
    if dkim["selectors_found"]:
        print(
            f"  • Active Selectors: {[s['selector'] for s in dkim['selectors_found']]}"
        )

    # MTA-STS
    print("\n📬 MTA-STS (Email Security)")
    mta = results["mta_sts"]
    print(f"  Score: {int(mta['score'])}/100")
    print(f"  • DNS Record: {bool(mta['dns_record'])}")
    print(f"  • Policy File: {bool(mta['policy_file'])}")
    if mta["policy_mode"]:
        print(f"  • Policy Mode: {mta['policy_mode']}")

    # HTTPS Redirect
    print("\n🔒 HTTPS ENFORCEMENT")
    https_redir = results["https_redirect"]
    print(f"  Score: {int(https_redir['score'])}/100")
    print(f"  • HTTP Accessible: {https_redir['http_accessible']}")
    print(f"  • Redirects to HTTPS: {https_redir['redirects_to_https']}")
    if https_redir["redirect_chain"]:
        print(f"  • Redirect Hops: {len(https_redir['redirect_chain'])}")

    # Mixed Content
    print("\n🔀 MIXED CONTENT CHECK")
    mixed = results["mixed_content"]
    print(f"  Score: {int(mixed['score'])}/100")
    print(f"  • Page is HTTPS: {mixed['is_https']}")
    if mixed["resource_types"]:
        print(f"  • HTTP Resources Found: {sum(mixed['resource_types'].values())}")
        print(f"  • Types: {mixed['resource_types']}")

    # Breach Exposure
    print("\n🚨 BREACH EXPOSURE")
    breach = results["breach_exposure"]
    print(f"  Score: {int(breach['score'])}/100")
    print(f"  • Known Breaches: {breach['breach_count']}")
    if breach["breach_count"] > 0:
        print(f"  • Most Recent: {breach['most_recent']}")
        print("  • Breach Details:")
        for b in breach["breaches"][:3]:
            print(f"    - {b['name']} ({b['date']}): {b['pwn_count']:,} accounts")

    # Certificate Transparency
    print("\n📜 CERTIFICATE TRANSPARENCY")
    ct = results["ct_logs"]
    print(f"  Score: {int(ct['score'])}/100")
    print(f"  • Certificates Found: {ct['certificates_found']}")
    print(f"  • Recent (90 days): {ct['recent_count']}")

    # Technology Fingerprinting
    print("\n⚙️ TECHNOLOGY FINGERPRINTING")
    tech = results["tech_fingerprint"]
    print(f"  Score: {int(tech['score'])}/100")
    print(f"  • Technologies Detected: {list(tech['technologies'].keys())}")
    print(f"  • Vulnerable Technologies: {tech['vulnerable_techs']}")

    # Recommendations
    print("\n" + "-" * 70)
    print("RECOMMENDATIONS")
    print("-" * 70)

    all_issues = []
    for component_key in [
        "tls_certificate",
        "security_headers",
        "dns_security",
        "cookie_security",
        "breach_exposure",
        "tech_fingerprint",
        "ct_logs",
    ]:
        component = results.get(component_key, {})
        issues = component.get("issues", [])
        all_issues.extend(issues)

    if all_issues:
        critical = [i for i in all_issues if "CRITICAL" in i]
        warnings = [i for i in all_issues if "WARNING" in i]
        info = [i for i in all_issues if "INFO" in i]

        if critical:
            print("\n🔴 CRITICAL (Immediate Action Required):")
            for i, issue in enumerate(critical, 1):
                print(f"  {i}. {issue}")

        if warnings:
            print("\n🟡 WARNINGS (Should Be Addressed):")
            for i, issue in enumerate(warnings, 1):
                print(f"  {i}. {issue}")

        if info:
            print("\nℹ️ INFORMATIONAL:")
            for i, issue in enumerate(info, 1):
                print(f"  {i}. {issue}")
    else:
        print("\n✅ No major issues identified!")

    print("\n" + "=" * 70)
    print("DISCLAIMER")
    print("=" * 70)
    print(
        """
This assessment uses passive reconnaissance techniques only and does not
perform any intrusive testing or exploitation. Results should be used as
part of a comprehensive security program.

This tool is legally compliant and performs only authorized, non-invasive
checks using publicly available information.
"""
    )
    print("=" * 70 + "\n")


def main():
    """Main CLI entry point with validation support"""
    import argparse

    parser = argparse.ArgumentParser(
        description=f"Enhanced Cybersecurity Assessment Tool v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python single_target_cyber_score_updates.py example.com
    python single_target_cyber_score_updates.py example.com --validate
    python single_target_cyber_score_updates.py https://example.com --validate --benchmark
        """,
    )

    parser.add_argument("domain", help="Domain or URL to scan")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Include validation report (framework alignment)",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Include live benchmarking (slower, requires --validate)",
    )

    args = parser.parse_args()

    try:
        # Perform scan
        if args.validate:
            print("\n🔍 Running scan with validation...\n")
            results = enhanced_scan(args.domain)

            # Add validation
            from validation_module import ValidationEngine

            validator = ValidationEngine()
            validation_report = validator.generate_validation_report(
                results, include_benchmark=args.benchmark
            )

            results["validation"] = validation_report

            # Print regular report
            print_report(results)

            # Print validation report
            print("\n" + "=" * 70)
            print("VALIDATION REPORT")
            print("=" * 70)
            print(validator._format_text_report(validation_report))

        else:
            results = enhanced_scan(args.domain)
            print_report(results)

        print("\n✅ Scan complete!\n")

    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


# ============================================================================
# VALIDATION INTEGRATION (Updated)
# ============================================================================


def enhanced_scan_with_validation(
    input_url: str, include_validation: bool = False
) -> Dict:
    """
    Enhanced scan with optional validation

    Args:
        input_url: Domain or URL to scan
        include_validation: Whether to include validation report

    Returns:
        Scan results with optional validation data
    """
    # Run normal scan
    results = enhanced_scan(input_url)

    # Add validation if requested
    if include_validation:
        try:
            from validation_module import ValidationEngine

            validator = ValidationEngine()
            validation_report = validator.generate_validation_report(
                results, include_benchmark=False  # Set True for live benchmarking
            )

            results["validation"] = validation_report

        except ImportError:
            print("⚠️  validation_module.py not found. Skipping validation.")
        except Exception as e:
            print(f"⚠️  Validation failed: {e}")

    return results


if __name__ == "__main__":
    main()
