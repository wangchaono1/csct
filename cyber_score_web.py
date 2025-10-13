import streamlit as st
import json
import time
import matplotlib.pyplot as plt
import numpy as np
from single_target_cyber_score import single_scan

# --- Basic password protection (local / small-team use) ---
PASSWORD = "Cybastion2025"  # <-- change this
st.set_page_config(page_title="Cyber Security Scoring Tool", layout="wide")

st.title("🔒 Cyber Security Scoring Tool (Secure Version)")
st.markdown("请输入密码以访问工具：")

password_input = st.text_input("Password:", type="password")
if password_input != PASSWORD:
    st.warning("🚫 密码错误或未输入，无法访问此页面。")
    st.stop()


# Streamlit 页面配置
st.set_page_config(page_title="Cyber Security Scoring Tool", layout="wide")

st.title("🔒 Cyber Security Scoring Tool (Enhanced Web Version)")
st.markdown("""
输入一个公司的网址（例如 `example.com` 或 `https://example.com`），
系统会执行非侵入式安全检测，计算安全评分（1–100），并展示雷达图和改进建议。
""")

url_input = st.text_input("请输入公司网址：", placeholder="https://example.com")

if st.button("开始检测"):
    if not url_input.strip():
        st.warning("请输入一个网址。")
    else:
        progress_text = st.empty()
        progress_bar = st.progress(0)
        progress_steps = [
            "初始化扫描...",
            "检测 TLS / HTTPS...",
            "分析安全头部...",
            "检查 HSTS / CSP...",
            "检测混合内容与 Cookies...",
            "检查 DNS SPF / DMARC...",
            "检测开放端口...",
            "汇总结果并生成报告..."
        ]

try:
    for i, step in enumerate(progress_steps):
        progress_text.text(step)
        progress_bar.progress(int((i + 1) / len(progress_steps) * 100))
        time.sleep(0.3)
    progress_text.text("正在汇总结果...")

    result = single_scan(url_input.strip())
    progress_bar.progress(100)
    progress_text.text("✅ 检测完成！")

    st.success("检测完成 ✅")

    # --- 总分与风险标签 ---
    st.metric(label="Cyber Security Score", value=f"{result['total_score']}/100")
    st.markdown(f"**风险等级：** :red[{result['risk']}]")

    # --- 雷达图展示 ---
    st.subheader("📈 安全雷达图")
    subscores = result["subscores"]
    categories = list(subscores.keys())
    values = list(subscores.values())
    N = len(categories)

    values += values[:1]
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
    ax.plot(angles, values, linewidth=2)
    ax.fill(angles, values, alpha=0.25)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=9)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(["20", "40", "60", "80", "100"])
    ax.set_ylim(0, 100)
    st.pyplot(fig)

# --- 检测报告 ---
st.subheader("🧾 检测报告摘要")
col1, col2 = st.columns(2)

with col1:
tls = result["tls"]
st.markdown(f"**TLS:** {'✅ 启用' if tls['present'] else '❌ 未启用'}")
st.markdown(f"- 验证状态: {tls['verified']}")
st.markdown(f"- TLS 版本: {tls['tls_version']}")
st.markdown(f"- 证书有效天数: {tls.get('days_left')}")
headers = result["headers_analysis"]
st.markdown(f"**安全头部存在:** {list(headers['found_headers'].keys())}")
st.markdown(f"**Server Header:** {headers['server']}")
st.markdown(f"**Cookies Flags:** {headers['cookies']}")

with col2:
st.markdown(f"**HSTS:** {result['hsts_value']}")
st.markdown(f"**CSP:** {'✅ 存在' if result['csp_value'] else '❌ 无'}")
st.markdown(f"**混合内容:** {('未知' if result['mixed_content'] is None else ('⚠️ 有' if result['mixed_content'] else '✅ 无'))}")
st.markdown(f"**SPF:** {result['spf']}")
st.markdown(f"**DMARC:** {result['dmarc']}")
st.markdown(f"**MX记录:** {result['mx']}")
st.markdown(f"**开放端口:** {result['open_ports']}")

# --- 分项得分表 ---
st.subheader("📊 各项子分数 (0–100)")
st.table(
[{"项目": k, "分数": v} for k, v in subscores.items()]
)

# --- 改进建议 ---
st.subheader("🛠 建议与改进方向")
recs = []
if not tls["present"]:
recs.append("启用 HTTPS（TLS）以保护传输安全。")
elif tls["verified"] is False:
recs.append("TLS 证书未通过系统 CA 验证，请检查证书链。")
elif tls.get("days_left") and tls["days_left"] < 30:
recs.append("证书即将到期，请尽快续签。")
if result["subscores"]["hsts"] < 50:
recs.append("添加或延长 HSTS（建议 max-age ≥ 1年）。")
if result["subscores"]["csp"] < 50:
recs.append("增加 Content-Security-Policy 以防止 XSS 攻击。")
if result["subscores"]["mixed_content"] == 0:
recs.append("修复混合内容（HTTPS 页面中含 HTTP 资源）。")
if result["subscores"]["cookies"] < 80:
recs.append("确保 cookies 使用 Secure 和 HttpOnly 属性。")
if result["subscores"]["dns_email"] < 100:
recs.append("补全或验证 SPF / DMARC 记录。")
if result["subscores"]["ports"] < 80:
recs.append("检查外部暴露的端口与防火墙策略。")

if recs:
for r in recs:
st.markdown(f"- {r}")
else:
st.markdown("✅ 暂无明显改进建议。")

# --- 查看原始 JSON ---
with st.expander("📂 查看完整原始结果数据 (JSON)"):
st.json(result)

except Exception as e:
st.error(f"检测失败: {e}")
