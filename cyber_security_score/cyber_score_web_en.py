import os
import streamlit as st
import json
import time
import matplotlib.pyplot as plt
import numpy as np
from single_target_cyber_score import single_scan

# -------------------------------------------------------
# 🔒 Password protection (optional)
# -------------------------------------------------------
# PASSWORD = st.secrets.get("PASSWORD") or os.environ.get("PASSWORD")
# st.title("🔒 Cyber Security Scoring Tool (Protected Access)")
# pwd_in = st.text_input("Enter password to access the tool:", type="password")
# if not PASSWORD or pwd_in != PASSWORD:
#     st.warning("Incorrect or missing password. Ask the owner for access.")
#     st.stop()

# -------------------------------------------------------
# Streamlit Page Configuration
# -------------------------------------------------------
st.set_page_config(page_title="Cyber Security Scoring Tool", layout="wide")

st.markdown(
    """
    <h1 style='text-align:center; color:#1E88E5; font-weight:700;'>
        Cyber Security Scoring Tool
    </h1>
    """,
    unsafe_allow_html=True,
)

st.markdown("<br>", unsafe_allow_html=True)

st.markdown(
    """
Enter a company or organization's website (for example `example.com` or `https://example.com`).
This tool performs a **cybersecurity assessment** and calculates a **security score (0–100)**.
"""
)

# Centered, styled title and input box
# -------------------------------------------------------
# Main workflow (with Enter-to-run support)
# -------------------------------------------------------

st.markdown(
    "<h3 style='text-align:center; color:#1E88E5; font-weight:600;'>🌐 Enter Website URL</h3>",
    unsafe_allow_html=True,
)

# Use a form so hitting Enter submits it automatically
with st.form(key="scan_form"):
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        url_input = st.text_input(
            "", placeholder="https://example.com", label_visibility="collapsed"
        )

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        start_button = st.form_submit_button(
            "Start Security Scan", use_container_width=True
        )

# -------------------------------------------------------
# Scan workflow logic
# -------------------------------------------------------
if start_button:
    if not url_input.strip():
        st.warning("Please enter a valid website.")
    else:
        progress_text = st.empty()
        progress_bar = st.progress(0)
        progress_steps = [
            "Initializing scan...",
            "Checking TLS / HTTPS...",
            "Analyzing security headers...",
            "Checking HSTS / CSP policies...",
            "Checking mixed content and cookies...",
            "Verifying DNS SPF / DMARC...",
            "Checking open ports...",
            "Aggregating results and generating report...",
        ]

        try:
            # --- Simulate progress bar ---
            for i, step in enumerate(progress_steps):
                progress_text.text(step)
                progress_bar.progress(int((i + 1) / len(progress_steps) * 100))
                time.sleep(0.3)
            progress_text.text("Finalizing results...")

            # --- Perform the real scan ---
            result = single_scan(url_input.strip())
            progress_bar.progress(100)
            progress_text.text("✅ Scan completed!")

            st.success("Scan completed successfully ✅")

            # --- Dynamic color display for score and risk level ---
            score = result["total_score"]
            risk = result["risk"]

            # 1️⃣ Choose color based on score
            if score < 40:
                score_color = "#D32F2F"  # red
            elif score <= 80:
                score_color = "#F9A825"  # yellow
            else:
                score_color = "#388E3C"  # green

            # 2️⃣ Choose color based on risk level
            risk_lower = str(risk).lower()
            if "critical" in risk_lower:
                risk_color = "#D32F2F"  # red
            elif "medium" in risk_lower:
                risk_color = "#F9A825"  # yellow
            elif "low" in risk_lower:
                risk_color = "#388E3C"  # green
            else:
                risk_color = "#6E6E6E"  # gray (fallback)

            # 3️⃣ Render formatted text (centered, partial color)
            st.markdown(
                f"""
                <div style='text-align:center;'>
                    <p style='font-size:32px; font-weight:700; margin-bottom:0;'>
                        <span style='color:black;'>Score: </span>
                        <span style='color:{score_color};'>{score}</span>
                        <span style='color:black;'>/100</span>
                    </p>
                    <p style='font-size:24px; font-weight:600; margin-top:5px;'>
                        <span style='color:black;'>Risk Level: </span>
                        <span style='color:{risk_color};'>{risk}</span>
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # --- Security Radar Chart (optimized professional style) ---
            st.subheader("Security Radar Chart")

            subscores = result["subscores"]

            # Friendly labels for client presentation
            friendly_labels = {
                "tls": "Infrastructure Resilience",
                "headers": "Application Safeguards",
                "hsts": "Data Transmission Integrity",
                "csp": "Information Control Measures",
                "mixed_content": "Content Consistency",
                "cookies": "Privacy Protection",
                "dns_email": "Communication Security",
                "mx": "Service Reliability",
                "robots_securitytxt": "Public Configuration Hygiene",
                "ports": "System Exposure",
            }

            # Replace keys with client-friendly labels
            categories = [friendly_labels.get(k, k) for k in subscores.keys()]
            values = list(subscores.values())
            N = len(categories)

            # Close radar loop
            values += values[:1]
            angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
            angles += angles[:1]

            # --- Styling ---
            plt.style.use("seaborn-v0_8-whitegrid")

            fig, ax = plt.subplots(figsize=(4.2, 4.2), subplot_kw=dict(polar=True))

            # Plot
            ax.plot(angles, values, linewidth=2.5, color="#1565C0", alpha=0.9)
            ax.fill(angles, values, color="#64B5F6", alpha=0.3)

            # Adjust axes
            ax.set_xticks(angles[:-1])
            ax.set_xticklabels(categories, fontsize=4, fontweight="600", color="#333")
            ax.tick_params(
                axis="x", pad=12
            )  # push labels away from circle to prevent overlap

            ax.set_yticks([20, 40, 60, 80, 100])
            ax.set_yticklabels(
                ["20", "40", "60", "80", "100"], fontsize=6.5, color="#555"
            )
            ax.set_ylim(0, 100)

            # Remove polar spine (outer circle)
            ax.spines["polar"].set_visible(False)
            ax.grid(True, linestyle="--", linewidth=0.6, alpha=0.7)

            # # Add subtle title for visual separation
            # ax.set_title(
            #     "Overall Cybersecurity Dimensions",
            #     va="bottom",
            #     fontsize=9,
            #     color="#1565C0",
            #     pad=18,
            # )

            # Final render
            st.pyplot(fig)

            # # --- Report summary ---
            # st.subheader("🧾 Summary Report")
            # col1, col2 = st.columns(2)

            # tls = result["tls"]
            # headers = result["headers_analysis"]

            # with col1:
            #     st.markdown(
            #         f"**TLS:** {'✅ Enabled' if tls['present'] else '❌ Not enabled'}"
            #     )
            #     st.markdown(f"- Verification status: {tls['verified']}")
            #     st.markdown(f"- TLS version: {tls['tls_version']}")
            #     st.markdown(f"- Certificate valid days left: {tls.get('days_left')}")
            #     st.markdown(
            #         f"**Security headers found:** {list(headers['found_headers'].keys())}"
            #     )
            #     st.markdown(f"**Server Header:** {headers['server']}")
            #     st.markdown(f"**Cookies Flags:** {headers['cookies']}")

            # with col2:
            #     st.markdown(f"**HSTS:** {result['hsts_value']}")
            #     st.markdown(
            #         f"**CSP:** {'✅ Present' if result['csp_value'] else '❌ Missing'}"
            #     )
            #     st.markdown(
            #         f"**Mixed Content:** {('Unknown' if result['mixed_content'] is None else ('⚠️ Found' if result['mixed_content'] else '✅ None'))}"
            #     )
            #     st.markdown(f"**SPF:** {result['spf']}")
            #     st.markdown(f"**DMARC:** {result['dmarc']}")
            #     st.markdown(f"**MX Records:** {result['mx']}")
            #     st.markdown(f"**Open Ports:** {result['open_ports']}")

            # --- Subscores table ---
            st.subheader("Subscores Table (0–100)")

            # Use same friendly labels as radar chart
            friendly_labels = {
                "tls": "Infrastructure Resilience",
                "headers": "Application Safeguards",
                "hsts": "Data Transmission Integrity",
                "csp": "Information Control Measures",
                "mixed_content": "Content Consistency",
                "cookies": "Privacy Protection",
                "dns_email": "Communication Security",
                "mx": "Service Reliability",
                "robots_securitytxt": "Public Configuration Hygiene",
                "ports": "System Exposure",
            }

            # Replace technical KPI names with friendly names
            table_data = [
                {"Category": friendly_labels.get(k, k), "Score": v}
                for k, v in subscores.items()
            ]

            st.table(table_data)

            # # --- Recommendations ---
            # st.subheader("🛠 Recommendations and Improvements")
            # recs = []
            # if not tls["present"]:
            #     recs.append("Enable HTTPS (TLS) to protect data in transit.")
            # elif tls["verified"] is False:
            #     recs.append(
            #         "TLS certificate is not verified by a trusted CA. Check the certificate chain."
            #     )
            # elif tls.get("days_left") and tls["days_left"] < 30:
            #     recs.append("Certificate will expire soon. Renew promptly.")
            # if result["subscores"]["hsts"] < 50:
            #     recs.append("Add or extend HSTS (recommended max-age ≥ 1 year).")
            # if result["subscores"]["csp"] < 50:
            #     recs.append(
            #         "Implement a strong Content-Security-Policy to prevent XSS."
            #     )
            # if result["subscores"]["mixed_content"] == 0:
            #     recs.append("Fix mixed content (HTTPS pages loading HTTP resources).")
            # if result["subscores"]["cookies"] < 80:
            #     recs.append("Ensure cookies use Secure and HttpOnly flags.")
            # if result["subscores"]["dns_email"] < 100:
            #     recs.append("Add or validate SPF / DMARC DNS records.")
            # if result["subscores"]["ports"] < 80:
            #     recs.append("Review exposed ports and firewall configurations.")

            # if recs:
            #     for r in recs:
            #         st.markdown(f"- {r}")
            # else:
            #     st.markdown("✅ No major improvement recommendations found.")

            # # --- View raw JSON results ---
            # with st.expander("📂 View full raw results (JSON)"):
            #     st.json(result)

        except Exception as e:
            st.error(f"Scan failed: {e}")
