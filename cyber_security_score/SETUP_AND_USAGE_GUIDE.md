# Enhanced Cybersecurity Scoring System - Setup & Usage Guide

## 📋 Overview

This enhanced cybersecurity assessment platform provides:
- **Legally-compliant passive security reconnaissance**
- **NIST CSF & CVSS v4.0 aligned scoring**
- **11 comprehensive security categories**
- **Both CLI and Web interface options**

---

## 🚀 Quick Start

### 1. Installation

```bash
# Install required dependencies
pip install requests dnspython cryptography streamlit matplotlib numpy

# Optional: For better DNS resolution
pip install dnspython[DOH]
```

### 2. File Structure

Ensure you have these files in the same directory:
```
your_project/
├── single_target_cyber_score_updates.py  # Enhanced scoring engine
└── cyber_security_web_en_v2.py           # Streamlit web interface
```

---

## 💻 Usage Options

### Option 1: Command Line Interface (CLI)

Run a quick assessment from the terminal:

```bash
# Basic usage
python single_target_cyber_score_updates.py example.com

# With HTTPS
python single_target_cyber_score_updates.py https://example.com
```

**Output:**
- Console report with color-coded findings
- JSON file with complete results
- Actionable recommendations

**Example Output:**
```
============================================================
Enhanced Cybersecurity Assessment v2.0.0
Target: example.com
============================================================

ASSESSMENT RESULTS
============================================================
Overall Score: 78/100
Risk Level: Medium

Category Scores:
  tls_certificate          :  85/100  (weight: 18%)
  security_headers         :  70/100  (weight: 16%)
  hsts_quality             :  60/100  (weight:  8%)
  csp_quality              :  40/100  (weight: 10%)
  ...
```

---

### Option 2: Web Application (Streamlit)

Launch an interactive web interface:

```bash
# Start the Streamlit app
streamlit run cyber_security_web_en_v2.py
```

**The web app will open in your browser at:** `http://localhost:8501`

**Features:**
- 🎨 Modern, professional UI
- 📊 Interactive radar charts
- 📥 Export results (JSON/TXT)
- 🔍 Expandable detailed findings
- 💡 Actionable recommendations
- 📱 Mobile-friendly responsive design

---

## 🔒 Optional: Password Protection

To add password protection to the web app:

**Method 1: Environment Variable**
```bash
# Set password in terminal
export PASSWORD="your_secure_password"
streamlit run cyber_security_web_en_v2.py
```

**Method 2: Streamlit Secrets**
Create `.streamlit/secrets.toml`:
```toml
PASSWORD = "your_secure_password"
```

Then uncomment the password protection section in `cyber_security_web_en_v2.py` (lines 12-19).

---

## 📊 Understanding the Scores

### Overall Score Ranges
| Score | Risk Level | Meaning |
|-------|------------|---------|
| 80-100 | 🟢 Low | Strong security posture |
| 60-79 | 🟡 Medium | Moderate security, improvements recommended |
| 40-59 | 🟠 High | Significant vulnerabilities present |
| 0-39 | 🔴 Critical | Severe security issues require immediate action |

### Scoring Categories & Weights

| Category | Weight | What It Measures |
|----------|--------|------------------|
| TLS Certificate | 18% | SSL/TLS configuration, certificate validity |
| Security Headers | 16% | HTTP security headers (OWASP recommended) |
| DNS Security | 12% | SPF, DMARC, DKIM email authentication |
| CSP Quality | 10% | Content Security Policy effectiveness |
| Breach Exposure | 10% | Historical data breach involvement |
| HSTS Quality | 8% | HTTP Strict Transport Security config |
| Cookie Security | 6% | Secure, HttpOnly, SameSite attributes |
| DNSSEC | 6% | DNS integrity verification |
| Tech Fingerprint | 5% | Known vulnerable technologies |
| CT Logs | 5% | Certificate Transparency monitoring |
| CAA Records | 4% | Certificate Authority Authorization |

---

## 🎯 What the Tool Checks

### ✅ Included (Legal & Passive)
- ✓ TLS/SSL certificate analysis
- ✓ HTTP security headers inspection
- ✓ DNS records (SPF, DMARC, DNSSEC, CAA)
- ✓ Certificate Transparency logs
- ✓ Historical breach data (HaveIBeenPwned)
- ✓ Technology fingerprinting
- ✓ Cookie security attributes
- ✓ Content Security Policy analysis
- ✓ HSTS configuration review

### ❌ NOT Included (Legal Compliance)
- ✗ Port scanning (removed for legal compliance)
- ✗ Vulnerability exploitation
- ✗ Password attacks
- ✗ Network intrusion
- ✗ Unauthorized access attempts

---

## 🛠️ Troubleshooting

### Issue: Import Error
```
ImportError: cannot import name 'enhanced_scan'
```
**Solution:** Ensure `single_target_cyber_score_updates.py` is in the same directory and contains the `enhanced_scan()` function.

### Issue: DNS Lookup Failures
```
DNS lookup failed
```
**Solution:** 
- Check internet connection
- Try different DNS server
- Some domains may block DNS queries

### Issue: Certificate Transparency Check Slow
**Solution:** This is normal - CT logs can take 10-15 seconds to query. The tool uses rate limiting to be respectful.

### Issue: Rate Limiting Errors
**Solution:** The tool already implements rate limiting (2 req/sec). If you still hit limits, increase the delay in the code:
```python
RATE_LIMIT = 1  # Change from 2 to 1 request per second
```

---

## 📤 Exporting Results

### From CLI
Automatically saves to:
```
security_assessment_<domain>_<timestamp>.json
```

### From Web App
Two export options:
1. **📄 JSON Report** - Complete machine-readable results
2. **📝 Text Summary** - Human-readable summary report

---

## 🔧 Customization

### Adjust Scoring Weights

Edit `WEIGHTS` dictionary in `single_target_cyber_score_updates.py`:

```python
WEIGHTS = {
    "tls_certificate": 18,      # Increase if TLS is critical
    "security_headers": 16,      # Adjust as needed
    "breach_exposure": 10,       # Increase for high-risk orgs
    # ... modify others
}
```

**Important:** Weights should sum to 100.

### Add Custom Checks

Add new check functions following this pattern:

```python
def check_custom_feature(domain: str) -> Dict:
    """Your custom security check"""
    result = {
        "score": 0,
        "issues": [],
        "data": {}
    }
    
    # Your check logic here
    
    return result
```

Then add to `enhanced_scan()` function and `WEIGHTS` dictionary.

---

## ⚠️ Important Disclaimers

### Legal Compliance
- ✅ This tool uses **ONLY** passive reconnaissance
- ✅ No unauthorized access or exploitation
- ✅ Complies with CFAA and similar laws
- ✅ Safe for use on any domain you have permission to assess

### Limitations
- 📌 **Point-in-time assessment** - Security posture changes constantly
- 📌 **External view only** - Cannot see internal controls/firewall rules
- 📌 **Not a penetration test** - Does not detect actual exploitable vulnerabilities
- 📌 **False negatives possible** - Good score ≠ completely secure

### Recommendations
1. **Use as part of a comprehensive security program**
2. **Perform regular assessments** (weekly/monthly)
3. **Combine with vulnerability scanning** (Nessus, Qualys, etc.)
4. **Consider professional penetration testing** for critical systems
5. **Implement security monitoring** and incident response

---

## 📚 Additional Resources

### Standards Referenced
- **NIST Cybersecurity Framework (CSF) 2.0**
- **Common Vulnerability Scoring System (CVSS) v4.0**
- **CIS Controls v8**
- **OWASP Security Headers**

### Learn More
- NIST CSF: https://www.nist.gov/cyberframework
- CVSS: https://www.first.org/cvss/
- OWASP: https://owasp.org/
- HaveIBeenPwned API: https://haveibeenpwned.com/API/v3

---

## 🤝 Support

### Getting Help
1. Check this guide first
2. Review error messages carefully
3. Ensure all dependencies are installed
4. Verify network connectivity

### Reporting Issues
When reporting issues, include:
- Target domain (if not sensitive)
- Full error message
- Python version (`python --version`)
- Operating system

---

## 📝 Version History

### v2.0.0 (Current)
- ✨ Complete rewrite with CVSS/NIST alignment
- ✨ 11 comprehensive security categories
- ✨ Enhanced DNS security checks
- ✨ Breach database integration
- ✨ Technology fingerprinting
- ✨ Streamlit web interface
- 🔒 Removed port scanning for legal compliance
- 🚀 Parallel execution for faster scans

### v1.0.0 (Original)
- Basic 10-category assessment
- Port scanning (deprecated)
- Simple CLI interface

---

## 🎓 Best Practices

### For Security Teams
1. **Baseline Assessment** - Run initial assessment to establish baseline
2. **Regular Monitoring** - Schedule weekly/monthly re-assessments
3. **Track Improvements** - Compare scores over time
4. **Prioritize by Risk** - Focus on Critical/High findings first
5. **Document Actions** - Keep records of remediation efforts

### For Compliance
1. **Evidence Collection** - Export JSON reports for audit trails
2. **Trend Analysis** - Track score improvements for compliance reports
3. **Policy Alignment** - Map findings to your security policies
4. **Third-Party Risk** - Use for vendor security assessments

### For Development Teams
1. **Pre-Production Checks** - Scan staging environments
2. **CI/CD Integration** - Automate scans in deployment pipeline
3. **Security Headers** - Implement missing headers first (quick wins)
4. **Certificate Management** - Set up automated renewal reminders

---

## 📄 License & Usage Terms

This tool is provided for **legitimate security assessment purposes** only. Users are responsible for ensuring they have authorization to scan target domains. The creators assume no liability for misuse.

**Acceptable Use:**
- ✅ Assessing your own domains
- ✅ Third-party risk management (with permission)
- ✅ Security research and education
- ✅ Compliance monitoring

**Prohibited Use:**
- ❌ Unauthorized scanning of third-party systems
- ❌ Any malicious or harmful activities
- ❌ Violation of applicable laws or regulations

---

**Ready to scan? Run:**
```bash
streamlit run cyber_security_web_en_v2.py
```

🛡️ **Stay secure!**