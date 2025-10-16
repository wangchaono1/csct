Summary of the Model

This is a passive reconnaissance-based cybersecurity scoring tool that evaluates a target website/company through non-invasive checks. It assigns a score from 0-100 and classifies risk as Low/Medium/High/Critical.

Key Components Evaluated (10 categories):
TLS/SSL (20% weight) - Certificate presence, CA verification, TLS version, expiration
Security Headers (18%) - Presence of 6 key headers (HSTS, CSP, X-Frame-Options, etc.)
HSTS Configuration (8%) - Strict-Transport-Security strength
Content Security Policy (12%) - CSP implementation quality
Mixed Content (8%) - HTTP resources on HTTPS pages
Cookie Security (6%) - Secure and HttpOnly flags
DNS/Email Security (10%) - SPF and DMARC records
MX Records (4%) - Mail server presence
Well-known Files (6%) - security.txt, robots.txt presence
Port Exposure (8%) - Open common ports (21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443)

Scoring Logic:
Each category receives a 0-100 subscore
Final score = weighted sum of subscores
Risk thresholds: ≥80 Low, 60-79 Medium, 40-59 High, <40 Critical
