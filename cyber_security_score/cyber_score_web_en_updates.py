import os
import streamlit as st
import json
import time
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

# Import the enhanced scanner
try:
    from single_target_cyber_score_updates import enhanced_scan
except ImportError:
    st.error(
        "❌ Could not import enhanced_scan from single_target_cyber_score_updates.py"
    )
    st.stop()

# Page Configuration
st.set_page_config(
    page_title="Enhanced Cyber Security Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom CSS
st.markdown(
    """
    <style>
    .main-header {
        text-align: center;
        color: #1565C0;
        font-weight: 700;
        font-size: 2.8rem;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        text-align: center;
        color: #666;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f8f9fa;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin-bottom: 10px;
    }
    .stButton>button {
        background-color: #1565C0;
        color: white;
        font-weight: 600;
        border-radius: 8px;
        padding: 0.6rem 2rem;
        border: none;
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }
    .stButton>button:hover {
        background-color: #0D47A1;
        box-shadow: 0 4px 8px rgba(0,0,0,0.3);
    }
    </style>
""",
    unsafe_allow_html=True,
)

# Header Section
st.markdown(
    """
    <h1 class='main-header'>
        🛡️ Enhanced Cybersecurity Assessment Platform
    </h1>
    <p class='sub-header'>
        Advanced Security Posture Analysis | NIST CSF & CVSS Aligned | Passive Reconnaissance
    </p>
    """,
    unsafe_allow_html=True,
)

st.info(
    """
    ℹ️ **About this tool:** This assessment performs comprehensive, legally-compliant passive reconnaissance 
    including 15 security tests.
    """
)

# Input Section with Two Buttons
st.markdown("<br>", unsafe_allow_html=True)
st.markdown(
    "<h3 style='text-align:center; color:#1565C0; font-weight:600;'>🌐 Enter Target Domain</h3>",
    unsafe_allow_html=True,
)

with st.form(key="enhanced_scan_form"):
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        url_input = st.text_input(
            "",
            placeholder="example.com or https://example.com",
            label_visibility="collapsed",
            help="Enter the domain you want to assess",
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # Two buttons side by side
    col1, col2, col3, col4 = st.columns([0.5, 1, 1, 0.5])
    with col2:
        start_button = st.form_submit_button(
            "🚀 Start Enhanced Assessment", use_container_width=True
        )
    with col3:
        validate_button = st.form_submit_button(
            "✅ Score Validation", use_container_width=True
        )

# Friendly labels for all 15 categories
friendly_labels = {
    "tls_certificate": "TLS/Certificate",
    "security_headers": "Security Headers",
    "hsts_quality": "HSTS Config",
    "csp_quality": "CSP Implementation",
    "cookie_security": "Cookie Protection",
    "dns_security": "DNS Auth (SPF/DMARC)",
    "dnssec": "DNS Integrity",
    "caa_records": "CA Authorization",
    "ct_logs": "Cert Transparency",
    "breach_exposure": "Breach History",
    "tech_fingerprint": "Tech Stack",
    "dkim_records": "DKIM Auth",
    "mta_sts": "MTA-STS",
    "https_redirect": "HTTPS Enforcement",
    "mixed_content": "Mixed Content",
}

# ============================================================================
# SCAN EXECUTION LOGIC
# ============================================================================
if start_button:
    if not url_input.strip():
        st.warning("⚠️ Please enter a valid domain or URL.")
    else:
        progress_text = st.empty()
        progress_bar = st.progress(0)

        progress_steps = [
            "🔍 Initializing enhanced scan...",
            "🔐 Analyzing TLS/SSL certificates...",
            "📋 Inspecting security headers (HSTS, CSP, etc.)...",
            "🍪 Checking cookie security attributes...",
            "🌐 Verifying DNS security (SPF, DMARC, DNSSEC, CAA)...",
            "🔑 Checking DKIM email authentication...",
            "📬 Verifying MTA-STS (email security)...",
            "🔒 Testing HTTPS redirect enforcement...",
            "🔀 Detecting mixed content vulnerabilities...",
            "📜 Checking Certificate Transparency logs...",
            "🔎 Scanning breach databases...",
            "⚙️ Fingerprinting technologies...",
            "📊 Aggregating results and calculating scores...",
        ]

        try:
            for i, step in enumerate(progress_steps[:-1]):
                progress_text.text(step)
                progress_bar.progress(int((i + 1) / len(progress_steps) * 100))
                time.sleep(0.4)

            progress_text.text(progress_steps[-1])
            result = enhanced_scan(url_input.strip())

            progress_bar.progress(100)
            progress_text.text("✅ Assessment completed successfully!")
            time.sleep(0.5)
            progress_text.empty()
            progress_bar.empty()

            st.success("🎉 Security assessment completed!")

            # Score and Risk Level Display
            score = result["total_score"]
            risk = result["risk_level"]

            if score >= 80:
                score_color = "#388E3C"
                score_emoji = "🟢"
            elif score >= 60:
                score_color = "#F9A825"
                score_emoji = "🟡"
            elif score >= 40:
                score_color = "#FF6F00"
                score_emoji = "🟠"
            else:
                score_color = "#D32F2F"
                score_emoji = "🔴"

            risk_colors = {
                "Low": "#388E3C",
                "Medium": "#F9A825",
                "High": "#FF6F00",
                "Critical": "#D32F2F",
            }
            risk_color = risk_colors.get(risk, "#6E6E6E")

            st.markdown(
                f"""
                <div style='text-align:center; margin: 2rem 0;'>
                    <p style='font-size:48px; font-weight:700; margin-bottom:10px;'>
                        {score_emoji} <span style='color:{score_color};'>{score}</span>
                        <span style='color:#666; font-size:32px;'>/100</span>
                    </p>
                    <p style='font-size:28px; font-weight:600; margin-top:5px;'>
                        <span style='color:#333;'>Risk Level: </span>
                        <span style='color:{risk_color};'>{risk}</span>
                    </p>
                    <p style='font-size:14px; color:#666; margin-top:10px;'>
                        Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown("---")

            # Key Findings Section (4 columns)
            st.markdown("### 🎯 Key Findings")

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.markdown(
                    "<div class='metric-card'><h4 style='color:#1565C0; margin-bottom:10px;'>🔐 Certificate & TLS</h4></div>",
                    unsafe_allow_html=True,
                )
                tls_info = result.get("tls_certificate", {})
                if tls_info.get("has_tls"):
                    st.success("✅ TLS Enabled")
                    if tls_info.get("cert_valid"):
                        st.success("✅ Valid Certificate")
                    else:
                        st.error("❌ Invalid Certificate")
                    st.info(f"TLS Version: {tls_info.get('tls_version', 'Unknown')}")
                    days_left = tls_info.get("days_until_expiry")
                    if days_left is not None:
                        if days_left < 30:
                            st.warning(f"⚠️ Expires in {days_left} days")
                        else:
                            st.info(f"Valid for {days_left} days")
                else:
                    st.error("❌ TLS Not Detected")

            with col2:
                st.markdown(
                    "<div class='metric-card'><h4 style='color:#1565C0; margin-bottom:10px;'>🛡️ Security Headers</h4></div>",
                    unsafe_allow_html=True,
                )
                headers_info = result.get("security_headers", {})
                headers_found = headers_info.get("headers_found", {})
                headers_missing = headers_info.get("headers_missing", [])
                st.info(f"✅ {len(headers_found)} headers present")
                st.warning(f"⚠️ {len(headers_missing)} headers missing")
                if (
                    headers_info.get("header_quality", {})
                    .get("HSTS", {})
                    .get("present")
                ):
                    st.success("✅ HSTS Enabled")
                else:
                    st.error("❌ HSTS Missing")
                if headers_info.get("header_quality", {}).get("CSP", {}).get("present"):
                    st.success("✅ CSP Enabled")
                else:
                    st.error("❌ CSP Missing")

            with col3:
                st.markdown(
                    "<div class='metric-card'><h4 style='color:#1565C0; margin-bottom:10px;'>📧 DNS & Email Security</h4></div>",
                    unsafe_allow_html=True,
                )
                dns_info = result.get("dns_security", {})
                if dns_info.get("spf", {}).get("present"):
                    st.success("✅ SPF Record")
                else:
                    st.error("❌ SPF Missing")
                if dns_info.get("dmarc", {}).get("present"):
                    st.success("✅ DMARC Record")
                else:
                    st.error("❌ DMARC Missing")

                dkim_info = result.get("dkim_records", {})
                if len(dkim_info.get("selectors_found", [])) > 0:
                    st.success(
                        f"✅ DKIM ({len(dkim_info['selectors_found'])} selectors)"
                    )
                else:
                    st.warning("⚠️ DKIM Not Found")

                mta_info = result.get("mta_sts", {})
                if mta_info.get("dns_record") and mta_info.get("policy_file"):
                    st.success("✅ MTA-STS Configured")
                else:
                    st.warning("⚠️ MTA-STS Missing")

            with col4:
                st.markdown(
                    "<div class='metric-card'><h4 style='color:#1565C0; margin-bottom:10px;'>🔒 HTTPS & Content</h4></div>",
                    unsafe_allow_html=True,
                )

                https_redirect = result.get("https_redirect", {})
                if https_redirect.get("redirects_to_https"):
                    st.success("✅ HTTPS Enforced")
                else:
                    st.error("❌ HTTP Not Redirected")

                mixed_content = result.get("mixed_content", {})
                http_resources = len(mixed_content.get("http_resources", []))
                if mixed_content.get("is_https"):
                    if http_resources == 0:
                        st.success("✅ No Mixed Content")
                    else:
                        st.error(f"❌ {http_resources} HTTP Resources")
                else:
                    st.info("ℹ️ Not HTTPS Page")

                if dns_info.get("dnssec", {}).get("enabled"):
                    st.success("✅ DNSSEC Enabled")
                else:
                    st.warning("⚠️ DNSSEC Not Detected")

                if dns_info.get("caa", {}).get("present"):
                    st.success("✅ CAA Records")
                else:
                    st.info("ℹ️ No CAA Records")

            st.markdown("---")

            # Radar Chart
            st.markdown("### 📊 Security Posture Visualization")

            col1, col2 = st.columns([2, 1])

            with col1:
                subscores = result.get("subscores", {})

                categories = [friendly_labels.get(k, k) for k in subscores.keys()]
                values = list(subscores.values())
                N = len(categories)

                values += values[:1]
                angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
                angles += angles[:1]

                fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(polar=True))
                ax.plot(angles, values, linewidth=2.5, color="#1565C0", alpha=0.9)
                ax.fill(angles, values, color="#64B5F6", alpha=0.3)
                ax.set_xticks(angles[:-1])
                ax.set_xticklabels(
                    categories, fontsize=8, fontweight="600", color="#333"
                )
                ax.tick_params(axis="x", pad=15)
                ax.set_yticks([20, 40, 60, 80, 100])
                ax.set_yticklabels(
                    ["20", "40", "60", "80", "100"], fontsize=8, color="#555"
                )
                ax.set_ylim(0, 100)
                ax.spines["polar"].set_visible(False)
                ax.grid(True, linestyle="--", linewidth=0.6, alpha=0.7)
                st.pyplot(fig)

            with col2:
                st.markdown("#### 📈 Score Breakdown")
                for key, value in subscores.items():
                    label = friendly_labels.get(key, key)
                    if value >= 80:
                        color = "#388E3C"
                        icon = "🟢"
                    elif value >= 60:
                        color = "#F9A825"
                        icon = "🟡"
                    elif value >= 40:
                        color = "#FF6F00"
                        icon = "🟠"
                    else:
                        color = "#D32F2F"
                        icon = "🔴"
                    st.markdown(
                        f"{icon} **{label}**: <span style='color:{color}; font-weight:700;'>{value}</span>",
                        unsafe_allow_html=True,
                    )

            st.markdown("---")

            # Detailed Findings (5 tabs)
            with st.expander("🔍 Detailed Technical Findings", expanded=False):
                tab1, tab2, tab3, tab4, tab5 = st.tabs(
                    [
                        "🔐 TLS & Certificates",
                        "🛡️ Headers & Cookies",
                        "📧 Email Security",
                        "🔒 HTTPS & Content",
                        "🚨 Threats & Exposures",
                    ]
                )

                with tab1:
                    st.markdown("#### TLS/SSL Certificate Analysis")
                    tls_info = result.get("tls_certificate", {})
                    col1, col2 = st.columns(2)
                    with col1:
                        st.json(
                            {
                                "TLS Present": tls_info.get("has_tls"),
                                "Certificate Valid": tls_info.get("cert_valid"),
                                "TLS Version": tls_info.get("tls_version"),
                                "Cipher Suite": tls_info.get("cipher_suite"),
                                "Days Until Expiry": tls_info.get("days_until_expiry"),
                                "SAN Count": tls_info.get("san_count", 0),
                            }
                        )
                    with col2:
                        st.markdown("**Issues Detected:**")
                        issues = tls_info.get("issues", [])
                        if issues:
                            for issue in issues:
                                if "CRITICAL" in issue:
                                    st.error(issue)
                                elif "WARNING" in issue:
                                    st.warning(issue)
                                else:
                                    st.info(issue)
                        else:
                            st.success("✅ No major issues detected")

                with tab2:
                    st.markdown("#### Security Headers")
                    headers_info = result.get("security_headers", {})
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("**Present Headers:**")
                        for header, value in headers_info.get(
                            "headers_found", {}
                        ).items():
                            with st.expander(f"✅ {header}"):
                                st.code(value)
                    with col2:
                        st.markdown("**Missing Headers:**")
                        for header in headers_info.get("headers_missing", []):
                            st.warning(f"❌ {header}")

                    st.markdown("#### Cookie Security")
                    cookie_info = result.get("cookie_security", {})
                    st.json(
                        {
                            "Total Cookies": len(cookie_info.get("cookies", [])),
                            "Secure Cookies": cookie_info.get("secure_count", 0),
                            "HttpOnly Cookies": cookie_info.get("httponly_count", 0),
                            "SameSite Cookies": cookie_info.get("samesite_count", 0),
                        }
                    )

                with tab3:
                    st.markdown("#### DNS & Email Security Configuration")
                    dns_info = result.get("dns_security", {})
                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown("**SPF & DMARC:**")
                        spf_info = dns_info.get("spf", {})
                        if spf_info.get("present"):
                            st.success("✅ SPF Record")
                            if spf_info.get("record"):
                                st.code(spf_info.get("record")[:200])
                            st.caption(f"Policy: {spf_info.get('policy', 'N/A')}")
                        else:
                            st.error("❌ No SPF Record")

                        dmarc_info = dns_info.get("dmarc", {})
                        if dmarc_info.get("present"):
                            st.success("✅ DMARC Record")
                            if dmarc_info.get("record"):
                                st.code(dmarc_info.get("record")[:200])
                            st.caption(f"Policy: {dmarc_info.get('policy', 'N/A')}")
                        else:
                            st.error("❌ No DMARC Record")

                        st.markdown("---")
                        st.markdown("**DNSSEC & CAA:**")
                        if dns_info.get("dnssec", {}).get("enabled"):
                            st.success("✅ DNSSEC Enabled")
                        else:
                            st.warning("⚠️ DNSSEC Not Enabled")

                        caa_info = dns_info.get("caa", {})
                        if caa_info.get("present"):
                            st.success("✅ CAA Records")
                            for record in caa_info.get("records", [])[:3]:
                                st.code(record)
                        else:
                            st.info("ℹ️ No CAA Records")

                    with col2:
                        st.markdown("**DKIM Authentication:**")
                        dkim_info = result.get("dkim_records", {})
                        selectors_found = dkim_info.get("selectors_found", [])

                        if selectors_found:
                            st.success(
                                f"✅ {len(selectors_found)} DKIM Selector(s) Found"
                            )
                            for selector_data in selectors_found:
                                with st.expander(
                                    f"Selector: {selector_data['selector']}"
                                ):
                                    st.code(selector_data["record"])
                        else:
                            st.warning("⚠️ No DKIM Records Found")
                            st.caption(
                                f"Tested {len(dkim_info.get('selectors_tested', []))} common selectors"
                            )

                        if dkim_info.get("issues"):
                            for issue in dkim_info["issues"]:
                                if "WARNING" in issue:
                                    st.warning(issue)
                                else:
                                    st.info(issue)

                        st.markdown("---")
                        st.markdown("**MTA-STS (SMTP Security):**")
                        mta_info = result.get("mta_sts", {})

                        if mta_info.get("dns_record"):
                            st.success("✅ MTA-STS DNS Record")
                            st.code(mta_info["dns_record"])
                        else:
                            st.warning("⚠️ No MTA-STS DNS Record")

                        if mta_info.get("policy_file"):
                            st.success("✅ MTA-STS Policy File")
                            mode = mta_info.get("policy_mode", "unknown")
                            st.caption(f"Mode: {mode}")
                            with st.expander("View Policy"):
                                st.code(mta_info["policy_file"])
                        elif mta_info.get("dns_record"):
                            st.error("❌ Policy File Not Accessible")

                        if mta_info.get("issues"):
                            for issue in mta_info["issues"]:
                                if "WARNING" in issue:
                                    st.warning(issue)
                                else:
                                    st.info(issue)

                with tab4:
                    st.markdown("#### HTTPS Enforcement & Content Security")
                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown("**HTTPS Redirect Check:**")
                        https_redirect = result.get("https_redirect", {})

                        if https_redirect.get("http_accessible"):
                            if https_redirect.get("redirects_to_https"):
                                st.success("✅ HTTP Redirects to HTTPS")
                                if https_redirect.get("redirect_chain"):
                                    st.caption(
                                        f"{len(https_redirect['redirect_chain'])} redirect(s)"
                                    )
                                    with st.expander("View Redirect Chain"):
                                        for i, redirect in enumerate(
                                            https_redirect["redirect_chain"], 1
                                        ):
                                            st.write(
                                                f"**Hop {i}:** {redirect.get('code', 'N/A')}"
                                            )
                                            st.write(
                                                f"From: `{redirect.get('from', 'N/A')}`"
                                            )
                                            st.write(
                                                f"To: `{redirect.get('to', 'N/A')}`"
                                            )
                                            st.write("---")
                            else:
                                st.error("❌ HTTP Does Not Redirect to HTTPS")
                        else:
                            st.success("✅ HTTP Not Accessible (HTTPS-only)")

                        if https_redirect.get("issues"):
                            for issue in https_redirect["issues"]:
                                if "CRITICAL" in issue:
                                    st.error(issue)
                                elif "WARNING" in issue:
                                    st.warning(issue)
                                else:
                                    st.info(issue)

                    with col2:
                        st.markdown("**Mixed Content Detection:**")
                        mixed_content = result.get("mixed_content", {})

                        if mixed_content.get("is_https"):
                            http_resources = mixed_content.get("http_resources", [])
                            resource_types = mixed_content.get("resource_types", {})

                            if len(http_resources) == 0:
                                st.success("✅ No Mixed Content Detected")
                            else:
                                st.error(
                                    f"❌ {len(http_resources)} HTTP Resources Found"
                                )

                                if resource_types:
                                    st.markdown("**Resource Types:**")
                                    for res_type, count in resource_types.items():
                                        st.warning(f"• {res_type}: {count}")

                                with st.expander("View HTTP Resources"):
                                    for resource in http_resources[:10]:
                                        st.code(resource)
                                    if len(http_resources) > 10:
                                        st.caption(
                                            f"...and {len(http_resources) - 10} more"
                                        )
                        else:
                            st.info("ℹ️ Page Not HTTPS - Check Not Applicable")

                        if mixed_content.get("issues"):
                            for issue in mixed_content["issues"]:
                                if "CRITICAL" in issue:
                                    st.error(issue)
                                elif "WARNING" in issue:
                                    st.warning(issue)
                                else:
                                    st.info(issue)

                with tab5:
                    st.markdown("#### Breach Exposure")
                    breach_info = result.get("breach_exposure", {})
                    breach_count = breach_info.get("breach_count", 0)

                    if breach_count > 0:
                        st.error(
                            f"🚨 Domain found in {breach_count} known data breaches"
                        )
                        for breach in breach_info.get("breaches", []):
                            with st.expander(
                                f"⚠️ {breach.get('name')} - {breach.get('date')}"
                            ):
                                st.write(
                                    f"**Compromised accounts:** {breach.get('pwn_count', 'Unknown'):,}"
                                )
                                st.write(
                                    f"**Data exposed:** {', '.join(breach.get('data_classes', []))}"
                                )
                    else:
                        st.success("✅ No known data breaches found")

                    st.markdown("#### Technology Fingerprinting")
                    tech_info = result.get("tech_fingerprint", {})
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("**Detected Technologies:**")
                        techs = tech_info.get("technologies", {})
                        if techs:
                            for tech, value in techs.items():
                                st.info(f"• {tech}: {value}")
                        else:
                            st.info("No technologies detected")
                    with col2:
                        st.markdown("**Vulnerable Technologies:**")
                        vuln_techs = tech_info.get("vulnerable_techs", [])
                        if vuln_techs:
                            for tech in vuln_techs:
                                st.warning(f"⚠️ {tech}")
                        else:
                            st.success("✅ No known vulnerable technologies detected")

                    st.markdown("#### Certificate Transparency")
                    ct_info = result.get("ct_logs", {})
                    st.json(
                        {
                            "Certificates Found": ct_info.get("certificates_found", 0),
                            "Recent Certificates (90d)": ct_info.get("recent_count", 0),
                            "Certificate Issuers": (
                                ct_info.get("issuers", [])[:5]
                                if ct_info.get("issuers")
                                else []
                            ),
                        }
                    )

            # Recommendations
            with st.expander("💡 Security Recommendations", expanded=True):
                st.markdown("### 🛠️ Recommended Actions")

                all_issues = []
                for component in [
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
                    issues = result.get(component, {}).get("issues", [])
                    all_issues.extend(issues)

                if all_issues:
                    critical = [i for i in all_issues if "CRITICAL" in i]
                    warnings = [i for i in all_issues if "WARNING" in i]
                    info = [i for i in all_issues if "INFO" in i]

                    if critical:
                        st.markdown(
                            "#### 🔴 Critical Issues (Immediate Action Required)"
                        )
                        for issue in critical:
                            st.error(issue)

                    if warnings:
                        st.markdown("#### 🟡 Warnings (Should Be Addressed)")
                        for issue in warnings:
                            st.warning(issue)

                    if info:
                        st.markdown("#### ℹ️ Informational")
                        for issue in info[:10]:
                            st.info(issue)
                        if len(info) > 10:
                            st.caption(
                                f"...and {len(info) - 10} more informational items"
                            )
                else:
                    st.success(
                        "✅ No major issues detected! Your security posture looks good."
                    )

            # Export Options
            st.markdown("---")
            st.markdown("### 📥 Export Results")

            col1, col2, col3 = st.columns(3)

            with col1:
                json_data = json.dumps(result, indent=2, default=str)
                st.download_button(
                    label="📄 Download JSON Report",
                    data=json_data,
                    file_name=f"security_assessment_{url_input.replace('https://', '').replace('http://', '')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                )

            with col2:
                summary = f"""Security Assessment Report
===========================
Target: {result.get('domain', url_input)}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Overall Score: {score}/100
Risk Level: {risk}

Score Breakdown (15 Categories):
{chr(10).join([f'- {friendly_labels.get(k, k)}: {v}/100' for k, v in subscores.items()])}

Critical Issues:
{chr(10).join([f'- {i}' for i in all_issues if 'CRITICAL' in i]) or 'None'}

Warnings:
{chr(10).join([f'- {i}' for i in all_issues if 'WARNING' in i]) or 'None'}

Informational:
{chr(10).join([f'- {i}' for i in all_issues if 'INFO' in i][:10]) or 'None'}
"""
                st.download_button(
                    label="📝 Download Text Summary",
                    data=summary,
                    file_name=f"security_summary_{url_input.replace('https://', '').replace('http://', '')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                )

            with col3:
                st.button("🔄 Perform New Assessment", on_click=lambda: st.rerun())

        except Exception as e:
            st.error(f"❌ Assessment failed: {str(e)}")
            st.exception(e)

            with st.expander("🐛 Debug Information"):
                st.code(
                    f"""
Error Type: {type(e).__name__}
Error Message: {str(e)}

Please ensure:
1. single_target_cyber_score_updates.py is in the same directory
2. All required dependencies are installed:
   - pip install requests dnspython cryptography tldextract pyyaml
3. The domain is accessible and properly formatted
                """
                )

# ============================================================================
# SCORE VALIDATION LOGIC
# ============================================================================
elif validate_button:
    if not url_input.strip():
        st.warning("⚠️ Please enter a valid domain or URL to perform validation.")
    else:
        st.markdown("---")
        st.markdown("### ✅ Score Validation")

        st.info(
            """
        
        Our scoring methodology is comprehensively validated through:
        
        1. **Framework Alignment (50%)** 
        2. **External Benchmarking (50%)** 
        
        ⏳ **Please Note:** This process includes automatic benchmarking against external platforms 
        which may take 2-5 minutes to complete. The validation score is calculated based on BOTH 
        framework alignment AND benchmarking results for maximum credibility.
        """
        )

        st.markdown("#### 🔍 Validation Process")

        with st.spinner("🔄 Running comprehensive scan and validation..."):
            try:
                # First, run the security assessment
                progress_text = st.empty()
                progress_bar = st.progress(0)

                progress_text.text("🔍 Running security assessment...")
                progress_bar.progress(30)

                result = enhanced_scan(url_input.strip())

                progress_bar.progress(60)
                progress_text.text("✅ Assessment complete. Starting validation...")

                # Import and run validation
                from validation_module import ValidationEngine

                validator = ValidationEngine()

                progress_text.text(
                    "📋 Validating against NIST CSF, CIS Controls, and OWASP..."
                )
                progress_bar.progress(70)

                # Run validation WITH automatic benchmarking
                validation_report = validator.generate_validation_report(
                    result,
                    include_benchmark=True,  # Always run benchmarking automatically
                )

                progress_bar.progress(100)
                progress_text.text("✅ Validation complete!")
                time.sleep(0.5)
                progress_text.empty()
                progress_bar.empty()

                st.success("🎉 Scoring validation completed successfully!")

                # Display domain and score
                st.markdown("---")
                col1, col2, col3 = st.columns([1, 2, 1])
                with col2:
                    st.markdown(
                        f"""
                    <div style='text-align:center; padding:20px; background:#f8f9fa; border-radius:10px;'>
                        <h3 style='color:#1565C0; margin-bottom:10px;'>Target Domain</h3>
                        <p style='font-size:1.5rem; font-weight:600; color:#333;'>{result.get('domain', url_input)}</p>
                        <p style='font-size:1.2rem; color:#666; margin-top:10px;'>
                            Assessment Score: <span style='color:#1565C0; font-weight:700;'>{result['total_score']}/100</span>
                        </p>
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )

                st.markdown("---")

                # Framework Alignment Results
                st.markdown("### 📋 Framework Alignment Validation")
                st.markdown(
                    "*Verifying alignment with industry-standard cybersecurity frameworks*"
                )
                st.markdown("")

                col_a, col_b, col_c = st.columns(3)

                with col_a:
                    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
                    nist_cov = validation_report["framework_alignment"]["nist_csf"][
                        "coverage_percentage"
                    ]
                    st.metric("🏛️ NIST CSF 2.0 Coverage", f"{nist_cov}%")
                    st.caption(
                        f"**Functions Covered:** {validation_report['framework_alignment']['nist_csf']['functions_covered']}/{validation_report['framework_alignment']['nist_csf']['total_functions']}"
                    )

                    with st.expander("View Assessment"):
                        st.write(
                            validation_report["framework_alignment"]["nist_csf"][
                                "assessment"
                            ]
                        )
                        st.markdown("**Function Breakdown:**")
                        for func, data in validation_report["framework_alignment"][
                            "nist_csf"
                        ]["function_breakdown"].items():
                            if data["categories_mapped"] > 0:
                                st.success(
                                    f"✅ {func}: {data['categories_mapped']} categories"
                                )
                            else:
                                st.info(
                                    f"ℹ️ {func}: Not covered (requires internal access)"
                                )
                    st.markdown("</div>", unsafe_allow_html=True)

                with col_b:
                    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
                    cis_cov = validation_report["framework_alignment"]["cis_controls"][
                        "coverage_percentage"
                    ]
                    st.metric("🛡️ CIS Controls v8 Coverage", f"{cis_cov}%")
                    st.caption(
                        f"**Safeguards Covered:** {validation_report['framework_alignment']['cis_controls']['safeguards_covered']}/{validation_report['framework_alignment']['cis_controls']['total_safeguards']}"
                    )

                    with st.expander("View Assessment"):
                        st.write(
                            validation_report["framework_alignment"]["cis_controls"][
                                "assessment"
                            ]
                        )
                        st.markdown("**Implementation Groups:**")
                        for ig, count in validation_report["framework_alignment"][
                            "cis_controls"
                        ]["implementation_group_breakdown"].items():
                            st.info(f"{ig}: {count} safeguards covered")
                    st.markdown("</div>", unsafe_allow_html=True)

                with col_c:
                    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
                    owasp_cov = validation_report["framework_alignment"]["owasp"][
                        "coverage_percentage"
                    ]
                    st.metric("🔒 OWASP Top 10 Coverage", f"{owasp_cov}%")
                    st.caption(
                        f"**Categories Addressed:** {validation_report['framework_alignment']['owasp']['categories_addressed']}/{validation_report['framework_alignment']['owasp']['total_categories']}"
                    )

                    with st.expander("View Assessment"):
                        st.write(
                            validation_report["framework_alignment"]["owasp"][
                                "assessment"
                            ]
                        )
                        st.markdown("**Covered Categories:**")
                        for cat in validation_report["framework_alignment"]["owasp"][
                            "category_breakdown"
                        ]:
                            st.success(f"✅ {cat['owasp_category']}")
                    st.markdown("</div>", unsafe_allow_html=True)

                st.markdown("---")

                # Framework Alignment Assessment
                st.markdown("#### Framework Alignment Assessment")
                # st.markdown(
                #    "*Overall evaluation of framework coverage and alignment quality*"
                # )
                st.markdown("")

                # Calculate overall framework alignment
                nist_cov = validation_report["framework_alignment"]["nist_csf"][
                    "coverage_percentage"
                ]
                cis_cov = validation_report["framework_alignment"]["cis_controls"][
                    "coverage_percentage"
                ]
                owasp_cov = validation_report["framework_alignment"]["owasp"][
                    "coverage_percentage"
                ]
                avg_framework_cov = (nist_cov + cis_cov + owasp_cov) / 3

                # Determine assessment based on coverage
                if avg_framework_cov >= 75:
                    assessment_msg = (
                        f"✅ **Excellent Framework Alignment:** Average coverage of {avg_framework_cov:.1f}% across NIST CSF, CIS Controls, and OWASP Top 10. "
                        f"The scoring methodology demonstrates strong alignment with industry-standard cybersecurity frameworks, "
                        f"providing comprehensive security assessment suitable for cyber insurance underwriting. "
                        f"This high level of framework coverage ensures that critical security controls are evaluated systematically."
                    )
                    st.success(assessment_msg)
                elif avg_framework_cov >= 60:
                    assessment_msg = (
                        f"✅ **Good Framework Alignment:** Average coverage of {avg_framework_cov:.1f}% across major frameworks. "
                        f"The methodology aligns well with industry standards, covering key security domains including "
                        f"asset management, data protection, and threat detection. This coverage level is appropriate "
                        f"for external security assessments and risk evaluation."
                    )
                    st.success(assessment_msg)
                elif avg_framework_cov >= 45:
                    assessment_msg = (
                        f"ℹ️ **Moderate Framework Alignment:** Average coverage of {avg_framework_cov:.1f}% across frameworks. "
                        f"The methodology covers essential externally-assessable security controls. While comprehensive internal "
                        f"frameworks like CIS Controls v8 (153 safeguards) require organizational access, our passive assessment "
                        f"effectively evaluates the security posture visible through external analysis."
                    )
                    st.info(assessment_msg)
                else:
                    assessment_msg = (
                        f"⚠️ **Limited Framework Alignment:** Average coverage of {avg_framework_cov:.1f}% across frameworks. "
                        f"The current methodology focuses on specific security aspects. Consider expanding coverage to include "
                        f"additional security controls for more comprehensive framework alignment."
                    )
                    st.warning(assessment_msg)

                # Show key strengths from framework alignment
                with st.expander("📊 Detailed Framework Coverage Breakdown"):
                    col1, col2, col3 = st.columns(3)

                    with col1:
                        st.markdown(f"**NIST CSF 2.0: {nist_cov}%**")
                        nist_funcs = validation_report["framework_alignment"][
                            "nist_csf"
                        ]["functions_covered"]
                        st.write(f"• {nist_funcs}/6 core functions covered")
                        st.write("• Primary focus: Protect & Detect")
                        st.write("• Suitable for external assessment")

                    with col2:
                        st.markdown(f"**CIS Controls v8: {cis_cov}%**")
                        cis_safeguards = validation_report["framework_alignment"][
                            "cis_controls"
                        ]["safeguards_covered"]
                        st.write(f"• {cis_safeguards}/153 safeguards covered")
                        st.write("• Focus: IG1 Basic Cyber Hygiene")
                        st.write("• External controls evaluation")

                    with col3:
                        st.markdown(f"**OWASP Top 10: {owasp_cov}%**")
                        owasp_cats = validation_report["framework_alignment"]["owasp"][
                            "categories_addressed"
                        ]
                        st.write(f"• {owasp_cats}/10 risk categories addressed")
                        st.write("• Focus: Web application security")
                        st.write("• Config & crypto emphasis")

                st.markdown("---")

                # External Benchmarking Results (Automatic - Always Runs)
                st.markdown("### 🔬 External Benchmarking Results")
                st.markdown(
                    "*Automatically comparing against industry security rating platforms*"
                )
                st.markdown("")

                if validation_report.get("benchmark_comparison") and validation_report[
                    "benchmark_comparison"
                ].get("benchmarks"):
                    benchmark_report = validation_report["benchmark_comparison"]

                    st.info(
                        "✅ **Automatic Benchmarking Complete** - Results from external platforms have been integrated into the validation score."
                    )

                    # Display benchmark results in columns
                    benchmark_cols = st.columns(3)
                    col_idx = 0

                    for platform, data in benchmark_report.get(
                        "benchmarks", {}
                    ).items():
                        with benchmark_cols[col_idx % 3]:
                            st.markdown(
                                "<div class='metric-card'>", unsafe_allow_html=True
                            )

                            if data.get("status") == "success":
                                st.markdown(f"**{data.get('platform', platform)}**")
                                st.success(f"✅ Available")

                                # Display score comparison
                                col_a, col_b = st.columns(2)
                                with col_a:
                                    st.metric("Their Score", f"{data['score']}/100")
                                with col_b:
                                    diff = result["total_score"] - data["score"]
                                    st.metric(
                                        "Our Score",
                                        f"{result['total_score']}/100",
                                        delta=f"{diff:+.0f}",
                                    )

                                # Only show grade for Mozilla Observatory
                                if "grade" in data and "Mozilla" in data.get(
                                    "platform", ""
                                ):
                                    st.info(f"Grade: **{data['grade']}**")

                                if "url" in data:
                                    st.markdown(
                                        f"[📄 View Full Report]({data['url']})",
                                        unsafe_allow_html=True,
                                    )
                            else:
                                st.markdown(f"**{data.get('platform', platform)}**")
                                status_display = (
                                    data.get("status", "unknown")
                                    .replace("_", " ")
                                    .title()
                                )
                                st.warning(f"⚠️ {status_display}")

                                if "note" in data:
                                    st.caption(data["note"])
                                if "url" in data:
                                    st.markdown(f"[🔗 Check Manually]({data['url']})")

                            st.markdown("</div>", unsafe_allow_html=True)
                            col_idx += 1

                    # Benchmark Assessment (Simplified - Only show assessment message)
                    if benchmark_report.get("analysis"):
                        st.markdown("---")
                        st.markdown("#### External Benchmarking Assessment")

                        analysis = benchmark_report["analysis"]

                        # Calculate if we're more prudent or lenient and show assessment
                        if analysis.get("score_differences"):
                            scores = [
                                d["their_score"]
                                for d in analysis["score_differences"].values()
                            ]
                            if scores:
                                avg_their_score = sum(scores) / len(scores)
                                score_diff = result["total_score"] - avg_their_score

                                if score_diff < -10:
                                    # Our score is significantly lower (more prudent/strict)
                                    assessment_msg = (
                                        f"✅ **Excellent for Insurance Underwriting:** Our scoring is {abs(score_diff):.1f} points more prudent "
                                        f"than industry benchmarks (average: {avg_their_score:.1f}/100 vs our: {result['total_score']}/100). "
                                        f"This conservative approach provides better risk assessment for cyber insurance underwriting, "
                                        f"reducing potential false negatives and ensuring more accurate premium calculations."
                                    )
                                    st.success(assessment_msg)
                                elif score_diff < 0:
                                    # Our score is slightly lower (moderately prudent)
                                    assessment_msg = (
                                        f"✅ **Good for Insurance:** Our scoring is {abs(score_diff):.1f} points more prudent than benchmarks "
                                        f"(average: {avg_their_score:.1f}/100 vs our: {result['total_score']}/100). "
                                        f"This stricter evaluation aligns well with insurance underwriting needs."
                                    )
                                    st.success(assessment_msg)
                                elif score_diff <= 10:
                                    # Our score is close or slightly higher
                                    assessment_msg = (
                                        f"ℹ️ **Aligned with Industry:** Our scoring is within {score_diff:.1f} points of benchmarks "
                                        f"(average: {avg_their_score:.1f}/100 vs our: {result['total_score']}/100). "
                                        f"Scores are comparable to industry standards."
                                    )
                                    st.info(assessment_msg)
                                else:
                                    # Our score is significantly higher (more lenient)
                                    assessment_msg = (
                                        f"⚠️ **Review Recommended:** Our scoring is {score_diff:.1f} points higher (more lenient) than benchmarks "
                                        f"(average: {avg_their_score:.1f}/100 vs our: {result['total_score']}/100). "
                                        f"For cyber insurance underwriting, this may require additional investigation to ensure "
                                        f"adequate risk assessment and avoid underestimating security vulnerabilities."
                                    )
                                    st.warning(assessment_msg)
                        else:
                            st.info(analysis["assessment"])

                        if analysis.get("services_unavailable", 0) > 0:
                            st.caption(
                                f"⚠️ Note: {analysis['services_unavailable']} external service(s) were unavailable. Validation score adjusted accordingly."
                            )
                else:
                    st.warning(
                        """
                    ⚠️ **External benchmarking unavailable** - All external services were unreachable.
                    
                    Validation score is based on framework alignment only. External benchmarking services 
                    may be temporarily down or experiencing high traffic. The framework alignment validation 
                    provides reliable assessment independent of external APIs.
                    """
                    )

                st.markdown("---")

                # Overall Validation Score (Combined from Framework + Benchmarking)
                st.markdown("### 🎯 Overall Validation Results")
                st.markdown(
                    "*Combined validation score from framework alignment + external benchmarking*"
                )
                st.markdown("")

                val_score = validation_report["overall_validation"]["validation_score"]
                credibility = validation_report["overall_validation"][
                    "credibility_rating"
                ]

                # Show the components of the validation score
                framework_cov = validation_report["framework_alignment"][
                    "overall_coverage"
                ]

                # Check if benchmarking contributed to score
                has_benchmark_data = (
                    validation_report.get("benchmark_comparison")
                    and validation_report["benchmark_comparison"].get("benchmarks")
                    and any(
                        b.get("status") == "success"
                        for b in validation_report["benchmark_comparison"][
                            "benchmarks"
                        ].values()
                    )
                )

                # Color coding for validation score
                if val_score >= 85:
                    val_color = "#388E3C"
                    val_emoji = "🟢"
                elif val_score >= 70:
                    val_color = "#F9A825"
                    val_emoji = "🟡"
                elif val_score >= 55:
                    val_color = "#FF6F00"
                    val_emoji = "🟠"
                else:
                    val_color = "#D32F2F"
                    val_emoji = "🔴"

                st.markdown(
                    f"""
                <div style='text-align:center; padding:30px; background:linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius:15px; margin:20px 0;'>
                    <h2 style='color:white; margin-bottom:10px;'>Combined Validation Score</h2>
                    <p style='font-size:64px; font-weight:700; color:white; margin:10px 0;'>{val_score}<span style='font-size:36px;'>/100</span></p>
                </div>
                """,
                    unsafe_allow_html=True,
                )

                st.markdown("---")

                # Detailed Framework Mappings
                with st.expander("📊 Detailed Framework Mappings", expanded=False):
                    tab1, tab2, tab3 = st.tabs(
                        ["NIST CSF Details", "CIS Controls Details", "OWASP Details"]
                    )

                    with tab1:
                        st.markdown("#### NIST Cybersecurity Framework 2.0 Mapping")
                        st.markdown(
                            "*Showing how our 15 security tests map to NIST CSF functions*"
                        )

                        nist_data = validation_report["framework_alignment"]["nist_csf"]
                        for function, data in nist_data["function_breakdown"].items():
                            if data["categories_mapped"] > 0:
                                st.markdown(f"**{function}**")
                                st.write(
                                    f"Categories mapped: {', '.join(data['categories'])}"
                                )
                                # Fix: Ensure progress value is between 0 and 1
                                progress_value = min(
                                    1.0,
                                    data["categories_mapped"]
                                    / max(1, data["subcategories"]),
                                )
                                st.progress(progress_value)
                                st.markdown("---")

                    with tab2:
                        st.markdown("#### CIS Controls v8 Safeguard Mapping")
                        st.markdown(
                            "*External security controls covered by our assessment*"
                        )

                        cis_data = validation_report["framework_alignment"][
                            "cis_controls"
                        ]
                        for safeguard in cis_data.get("covered_safeguards", [])[:10]:
                            st.markdown(f"**{safeguard['safeguard']}**")
                            st.write(
                                f"Category: `{safeguard['category']}` | IG: `{safeguard['implementation_group']}` | Score: `{safeguard['score']}/100`"
                            )
                            st.markdown("---")

                        if len(cis_data.get("covered_safeguards", [])) > 10:
                            st.caption(
                                f"...and {len(cis_data.get('covered_safeguards', [])) - 10} more safeguards"
                            )

                    with tab3:
                        st.markdown("#### OWASP Top 10 (2021) Risk Coverage")
                        st.markdown("*Web application security risks addressed*")

                        owasp_data = validation_report["framework_alignment"]["owasp"]
                        for category in owasp_data["category_breakdown"]:
                            st.markdown(f"**{category['owasp_category']}**")
                            st.write(
                                f"Our categories: {', '.join(category['our_categories'])}"
                            )
                            st.write(f"Average score: {category['average_score']}/100")
                            st.progress(category["average_score"] / 100)
                            st.markdown("---")

                st.markdown("---")

                # Export Validation Report
                st.markdown("### 📥 Export Validation Report")

                col1, col2, col3 = st.columns(3)

                with col1:
                    validation_json = validator.export_validation_report(
                        validation_report, format="json"
                    )
                    st.download_button(
                        label="📄 Download JSON Report",
                        data=validation_json,
                        file_name=f"validation_report_{url_input.replace('https://', '').replace('http://', '')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                    )

                with col2:
                    validation_text = validator.export_validation_report(
                        validation_report, format="text"
                    )
                    st.download_button(
                        label="📝 Download Text Report",
                        data=validation_text,
                        file_name=f"validation_report_{url_input.replace('https://', '').replace('http://', '')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain",
                    )

                with col3:
                    st.button("🔄 New Validation", on_click=lambda: st.rerun())

            except ImportError:
                st.error(
                    "❌ Validation module not found. Please ensure validation_module.py is in the same directory."
                )
            except Exception as e:
                st.error(f"❌ Validation process failed: {str(e)}")
                st.exception(e)


# ============================================================================
# FOOTER
# ============================================================================
st.markdown("---")
st.markdown(
    """
    <div style='text-align:center; color:#666; font-size:0.9rem; padding:20px;'>
        <p><strong>Enhanced Cybersecurity Assessment Platform v2.0</strong></p>
        <p>Powered by NIST CSF, CVSS v4.0, and industry best practices</p>
        <p style='font-size:0.85rem; margin-top:10px;'>
            🎯 <strong>15 comprehensive security tests:</strong><br>
            TLS/Certificates • Security Headers • HSTS • CSP • Cookies • DNS Security • DNSSEC • CAA<br>
            Certificate Transparency • Breach Exposure • Technology Stack • DKIM • MTA-STS • HTTPS Redirect • Mixed Content
        </p>
        <p style='font-size:0.8rem; margin-top:10px;'>
            ⚠️ <strong>Disclaimer:</strong> This tool performs passive security reconnaissance only. 
            Results should be used as part of a comprehensive security strategy.  
        </p>
        <p style='font-size:0.8rem; color:#999;'>
            All scans are non-invasive and comply with legal requirements. 
            No unauthorized access or exploitation attempts are performed.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)
