import os
import streamlit as st
import json
import time
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

# Import the enhanced scanner
# Make sure single_target_cyber_score_updates.py is in the same directory
try:
    from single_target_cyber_score_updates import enhanced_scan
except ImportError:
    st.error(
        "❌ Could not import enhanced_scan from single_target_cyber_score_updates.py"
    )
    st.stop()

# -------------------------------------------------------
# 🔒 Password protection (optional)
# -------------------------------------------------------
# Uncomment to enable password protection
# PASSWORD = st.secrets.get("PASSWORD") or os.environ.get("PASSWORD")
# if PASSWORD:
#     st.title("🔒 Enhanced Cyber Security Scoring Tool (Protected)")
#     pwd_in = st.text_input("Enter password:", type="password")
#     if pwd_in != PASSWORD:
#         st.warning("⚠️ Incorrect password. Contact administrator for access.")
#         st.stop()

# -------------------------------------------------------
# Page Configuration
# -------------------------------------------------------
st.set_page_config(
    page_title="Enhanced Cyber Security Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom CSS for better styling
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

# -------------------------------------------------------
# Header Section
# -------------------------------------------------------
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

# Info banner
st.info(
    """
    ℹ️ **About this tool:** This assessment performs comprehensive, legally-compliant passive reconnaissance 
    including TLS analysis, security headers, DNS security (SPF/DMARC/DNSSEC/CAA), Certificate Transparency monitoring, 
    breach exposure checking, and technology fingerprinting.
    """
)

# -------------------------------------------------------
# Input Section
# -------------------------------------------------------
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

    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        start_button = st.form_submit_button(
            "🚀 Start Enhanced Assessment", use_container_width=True
        )

# -------------------------------------------------------
# Scan Execution Logic
# -------------------------------------------------------
if start_button:
    if not url_input.strip():
        st.warning("⚠️ Please enter a valid domain or URL.")
    else:
        # Progress tracking
        progress_text = st.empty()
        progress_bar = st.progress(0)

        progress_steps = [
            "🔍 Initializing enhanced scan...",
            "🔐 Analyzing TLS/SSL certificates...",
            "📋 Inspecting security headers (HSTS, CSP, etc.)...",
            "🍪 Checking cookie security attributes...",
            "🌐 Verifying DNS security (SPF, DMARC, DNSSEC, CAA)...",
            "📜 Checking Certificate Transparency logs...",
            "🔎 Scanning breach databases...",
            "⚙️ Fingerprinting technologies...",
            "📊 Aggregating results and calculating scores...",
        ]

        try:
            # Simulate progress
            for i, step in enumerate(progress_steps[:-1]):
                progress_text.text(step)
                progress_bar.progress(int((i + 1) / len(progress_steps) * 100))
                time.sleep(0.4)

            progress_text.text(progress_steps[-1])

            # Execute the actual scan
            result = enhanced_scan(url_input.strip())

            progress_bar.progress(100)
            progress_text.text("✅ Assessment completed successfully!")
            time.sleep(0.5)
            progress_text.empty()
            progress_bar.empty()

            st.success("🎉 Security assessment completed!")

            # -------------------------------------------------------
            # Results Display Section
            # -------------------------------------------------------

            # Score and Risk Level Display
            score = result["total_score"]
            risk = result["risk_level"]

            # Color mapping
            if score >= 80:
                score_color = "#388E3C"  # Green
                score_emoji = "🟢"
            elif score >= 60:
                score_color = "#F9A825"  # Yellow
                score_emoji = "🟡"
            elif score >= 40:
                score_color = "#FF6F00"  # Orange
                score_emoji = "🟠"
            else:
                score_color = "#D32F2F"  # Red
                score_emoji = "🔴"

            risk_colors = {
                "Low": "#388E3C",
                "Medium": "#F9A825",
                "High": "#FF6F00",
                "Critical": "#D32F2F",
            }
            risk_color = risk_colors.get(risk, "#6E6E6E")

            # Display score and risk
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

            # -------------------------------------------------------
            # Key Findings Section
            # -------------------------------------------------------
            st.markdown("### 🎯 Key Findings")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.markdown(
                    """
                <div class='metric-card'>
                    <h4 style='color:#1565C0; margin-bottom:10px;'>🔐 Certificate & TLS</h4>
                </div>
                """,
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
                    """
                <div class='metric-card'>
                    <h4 style='color:#1565C0; margin-bottom:10px;'>🛡️ Security Headers</h4>
                </div>
                """,
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
                    """
                <div class='metric-card'>
                    <h4 style='color:#1565C0; margin-bottom:10px;'>📧 DNS Security</h4>
                </div>
                """,
                    unsafe_allow_html=True,
                )

                dns_info = result.get("dns_security", {})

                if dns_info.get("spf", {}).get("present"):
                    st.success("✅ SPF Record Found")
                else:
                    st.error("❌ SPF Missing")

                if dns_info.get("dmarc", {}).get("present"):
                    st.success("✅ DMARC Record Found")
                else:
                    st.error("❌ DMARC Missing")

                if dns_info.get("dnssec", {}).get("enabled"):
                    st.success("✅ DNSSEC Enabled")
                else:
                    st.warning("⚠️ DNSSEC Not Detected")

                if dns_info.get("caa", {}).get("present"):
                    st.success("✅ CAA Records Found")
                else:
                    st.info("ℹ️ No CAA Records")

            st.markdown("---")

            # -------------------------------------------------------
            # Radar Chart
            # -------------------------------------------------------
            st.markdown("### 📊 Security Posture Visualization")

            col1, col2 = st.columns([2, 1])

            with col1:
                subscores = result.get("subscores", {})

                # Friendly labels aligned with enhanced model
                friendly_labels = {
                    "tls_certificate": "TLS/Certificate Security",
                    "security_headers": "Security Headers",
                    "hsts_quality": "HSTS Configuration",
                    "csp_quality": "CSP Implementation",
                    "cookie_security": "Cookie Protection",
                    "dns_security": "DNS Authentication",
                    "dnssec": "DNS Integrity",
                    "caa_records": "CA Authorization",
                    "ct_logs": "Certificate Transparency",
                    "breach_exposure": "Breach History",
                    "tech_fingerprint": "Technology Stack",
                }

                categories = [friendly_labels.get(k, k) for k in subscores.keys()]
                values = list(subscores.values())
                N = len(categories)

                # Close the radar loop
                values += values[:1]
                angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
                angles += angles[:1]

                # Create radar chart
                fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

                ax.plot(angles, values, linewidth=2.5, color="#1565C0", alpha=0.9)
                ax.fill(angles, values, color="#64B5F6", alpha=0.3)

                ax.set_xticks(angles[:-1])
                ax.set_xticklabels(
                    categories, fontsize=9, fontweight="600", color="#333"
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

                # Display subscores with color coding
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

            # -------------------------------------------------------
            # Detailed Findings
            # -------------------------------------------------------
            with st.expander("🔍 Detailed Technical Findings", expanded=False):
                tab1, tab2, tab3, tab4 = st.tabs(
                    [
                        "🔐 TLS & Certificates",
                        "🛡️ Headers & Cookies",
                        "🌐 DNS Security",
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
                    st.markdown("#### DNS Security Configuration")
                    dns_info = result.get("dns_security", {})

                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown("**Email Authentication:**")
                        spf_info = dns_info.get("spf", {})
                        if spf_info.get("present"):
                            st.success("✅ SPF Record")
                            if spf_info.get("record"):
                                st.code(spf_info.get("record"))
                        else:
                            st.error("❌ No SPF Record")

                        dmarc_info = dns_info.get("dmarc", {})
                        if dmarc_info.get("present"):
                            st.success("✅ DMARC Record")
                            if dmarc_info.get("record"):
                                st.code(dmarc_info.get("record"))
                        else:
                            st.error("❌ No DMARC Record")

                    with col2:
                        st.markdown("**DNS Integrity:**")
                        if dns_info.get("dnssec", {}).get("enabled"):
                            st.success("✅ DNSSEC Enabled")
                        else:
                            st.warning("⚠️ DNSSEC Not Enabled")

                        caa_info = dns_info.get("caa", {})
                        if caa_info.get("present"):
                            st.success("✅ CAA Records")
                            for record in caa_info.get("records", []):
                                st.code(record)
                        else:
                            st.info("ℹ️ No CAA Records")

                with tab4:
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
                        for tech, value in tech_info.get("technologies", {}).items():
                            st.info(f"• {tech}: {value}")

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
                            "Certificate Issuers": ct_info.get("issuers", []),
                        }
                    )

            # -------------------------------------------------------
            # Recommendations
            # -------------------------------------------------------
            with st.expander("💡 Security Recommendations", expanded=True):
                st.markdown("### 🛠️ Recommended Actions")

                all_issues = []

                # Collect all issues from different components
                for component in [
                    "tls_certificate",
                    "security_headers",
                    "dns_security",
                    "cookie_security",
                    "breach_exposure",
                    "tech_fingerprint",
                    "ct_logs",
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
                        for issue in info:
                            st.info(issue)
                else:
                    st.success(
                        "✅ No major issues detected! Your security posture looks good."
                    )

            # -------------------------------------------------------
            # Export Options
            # -------------------------------------------------------
            st.markdown("---")
            st.markdown("### 📥 Export Results")

            col1, col2, col3 = st.columns(3)

            with col1:
                # JSON export
                json_data = json.dumps(result, indent=2, default=str)
                st.download_button(
                    label="📄 Download JSON Report",
                    data=json_data,
                    file_name=f"security_assessment_{url_input.replace('https://', '').replace('http://', '')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                )

            with col2:
                # Summary text export
                summary = f"""
Security Assessment Report
===========================
Target: {result.get('domain', url_input)}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Overall Score: {score}/100
Risk Level: {risk}

Score Breakdown:
{chr(10).join([f'- {friendly_labels.get(k, k)}: {v}/100' for k, v in subscores.items()])}

Critical Issues:
{chr(10).join([f'- {i}' for i in all_issues if 'CRITICAL' in i]) or 'None'}

Warnings:
{chr(10).join([f'- {i}' for i in all_issues if 'WARNING' in i]) or 'None'}
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

# -------------------------------------------------------
# Validation Section (After Export Options)
# -------------------------------------------------------
st.markdown("---")
st.markdown("### ✅ Model Validation")

with st.expander("📊 Framework Alignment & Benchmarking", expanded=False):
    st.markdown(
        """
    Our scoring methodology is validated against industry-standard frameworks 
    and independently benchmarked against security rating platforms.
    """
    )

    # Add button to generate validation report
    col1, col2 = st.columns(2)

    with col1:
        if st.button("🔍 Generate Validation Report", key="validate_btn"):
            with st.spinner("Validating scoring model..."):
                try:
                    from validation_module import ValidationEngine

                    validator = ValidationEngine()
                    validation_report = validator.generate_validation_report(
                        result,
                        include_benchmark=False,  # Set True for live benchmarking (slower)
                    )

                    # Display framework alignment
                    st.markdown("#### 📋 Framework Alignment")

                    col_a, col_b, col_c = st.columns(3)

                    with col_a:
                        nist_cov = validation_report["framework_alignment"]["nist_csf"][
                            "coverage_percentage"
                        ]
                        st.metric("NIST CSF Coverage", f"{nist_cov}%", delta=None)
                        st.caption(
                            validation_report["framework_alignment"]["nist_csf"][
                                "assessment"
                            ]
                        )

                    with col_b:
                        cis_cov = validation_report["framework_alignment"][
                            "cis_controls"
                        ]["coverage_percentage"]
                        st.metric("CIS Controls Coverage", f"{cis_cov}%", delta=None)
                        st.caption(
                            validation_report["framework_alignment"]["cis_controls"][
                                "assessment"
                            ]
                        )

                    with col_c:
                        owasp_cov = validation_report["framework_alignment"]["owasp"][
                            "coverage_percentage"
                        ]
                        st.metric("OWASP Coverage", f"{owasp_cov}%", delta=None)
                        st.caption(
                            validation_report["framework_alignment"]["owasp"][
                                "assessment"
                            ]
                        )

                    # Overall validation score
                    st.markdown("---")
                    val_score = validation_report["overall_validation"][
                        "validation_score"
                    ]
                    credibility = validation_report["overall_validation"][
                        "credibility_rating"
                    ]

                    st.markdown(
                        f"""
                    <div style='text-align:center; padding:20px; background:#f0f8ff; border-radius:10px;'>
                        <h3 style='color:#1565C0;'>Validation Score: {val_score}/100</h3>
                        <p style='font-size:1.1rem;'>{credibility}</p>
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )

                    # Strengths and improvements
                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown("**✅ Strengths:**")
                        for strength in validation_report["overall_validation"][
                            "strengths"
                        ]:
                            st.success(strength)

                    with col2:
                        if validation_report["overall_validation"][
                            "areas_for_improvement"
                        ]:
                            st.markdown("**📈 Areas for Improvement:**")
                            for area in validation_report["overall_validation"][
                                "areas_for_improvement"
                            ]:
                                st.info(area)

                    # Download validation report
                    st.markdown("---")
                    validation_json = validator.export_validation_report(
                        validation_report, format="json"
                    )
                    st.download_button(
                        label="📥 Download Validation Report (JSON)",
                        data=validation_json,
                        file_name=f"validation_report_{url_input.replace('https://', '').replace('http://', '')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                    )

                except ImportError:
                    st.error(
                        "❌ Validation module not found. Please ensure validation_module.py is in the same directory."
                    )
                except Exception as e:
                    st.error(f"❌ Validation failed: {str(e)}")

    with col2:
        st.info(
            """
        **What is validated:**
        - NIST CSF 2.0 alignment
        - CIS Controls v8 mapping
        - OWASP Top 10 coverage
        - Benchmark comparison (optional)
        
        **Why this matters:**
        Industry-standard frameworks provide 
        credibility and ensure comprehensive 
        security assessment.
        """
        )

# -------------------------------------------------------
# Footer
# -------------------------------------------------------
st.markdown("---")
st.markdown(
    """
    <div style='text-align:center; color:#666; font-size:0.9rem; padding:20px;'>
        <p><strong>Enhanced Cybersecurity Assessment Platform v2.0</strong></p>
        <p>Powered by NIST CSF, CVSS v4.0, and industry best practices</p>
        <p style='font-size:0.8rem; margin-top:10px;'>
            ⚠️ <strong>Disclaimer:</strong> This tool performs passive security reconnaissance only. 
            Results should be used as part of a comprehensive security strategy. 
            This is not a substitute for professional penetration testing or security audits.
        </p>
        <p style='font-size:0.8rem; color:#999;'>
            All scans are non-invasive and comply with legal requirements. 
            No unauthorized access or exploitation attempts are performed.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)
