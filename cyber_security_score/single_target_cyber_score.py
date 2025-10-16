#!/usr/bin/env python3
"""
single_target_cyber_score.py
单网址 -> 被动/低侵入 快速网络安全评分（手动输入一个公司网址）
输出: 总分 (1-100), 风险标签, 简洁检测报告
依赖: requests, dnspython
安装: pip install requests dnspython
用法:
  python single_target_cyber_score.py            # 会提示输入网址
  python single_target_cyber_score.py example.com  # 可直接带域名或含 scheme
"""

import sys
import socket
import ssl
import requests
import dns.resolver
from urllib.parse import urlparse, urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import re

# ------- 配置（可按需调整权重） -------
TIMEOUT = 5
COMMON_PORTS = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443]
WEIGHTS = {
    "tls": 20,
    "headers": 18,
    "hsts": 8,
    "csp": 12,
    "mixed_content": 8,
    "cookies": 6,
    "dns_email": 10,
    "mx": 4,
    "robots_securitytxt": 6,
    "ports": 8
}
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ------- 辅助 & 检测函数 -------
def normalize_url(input_url):
    if not input_url.startswith(("http://", "https://")):
        input_url = "https://" + input_url
    p = urlparse(input_url)
    scheme = p.scheme
    host = p.netloc.split(":")[0]
    base = f"{scheme}://{host}"
    return base, host, scheme

def fetch_root(base_url):
    try:
        return requests.get(base_url, timeout=TIMEOUT, allow_redirects=True)
    except Exception:
        return None

def check_tls(host):
    res = {"present": False, "verified": None, "tls_version": None, "days_left": None}
    # 尝试带验证连接（可表明证书是否由系统 CA 验证）
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, 443))
            res["present"] = True
            res["tls_version"] = s.version()
            res["verified"] = True
    except ssl.SSLCertVerificationError:
        res["present"] = True
        res["verified"] = False
    except Exception:
        return res

    # 读取证书详情（允许不验证链来拿到 notAfter）
    try:
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        with ctx2.wrap_socket(socket.socket(), server_hostname=host) as s2:
            s2.settimeout(TIMEOUT)
            s2.connect((host, 443))
            cert = s2.getpeercert()
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    res["days_left"] = (dt - datetime.utcnow()).days
                except Exception:
                    res["days_left"] = None
    except Exception:
        pass
    return res

def analyze_headers(resp):
    if not resp:
        return {"found_headers": {}, "server": None, "x_powered_by": None, "cookies": {"has_set_cookie": False, "secure_flag": False, "httponly_flag": False}}
    found = {h: resp.headers.get(h) for h in SECURITY_HEADERS if h in resp.headers}
    server = resp.headers.get("Server")
    x_powered = resp.headers.get("X-Powered-By")
    cookies_raw = resp.headers.get("Set-Cookie")
    cookie_info = {"has_set_cookie": bool(cookies_raw), "secure_flag": False, "httponly_flag": False}
    if cookies_raw:
        if re.search(r";\s*secure\b", cookies_raw, flags=re.I):
            cookie_info["secure_flag"] = True
        if re.search(r";\s*httponly\b", cookies_raw, flags=re.I):
            cookie_info["httponly_flag"] = True
    return {"found_headers": found, "server": server, "x_powered_by": x_powered, "cookies": cookie_info}

def analyze_hsts(hsts_header_value):
    if not hsts_header_value:
        return 0, None
    m = re.search(r"max-age=(\d+)", hsts_header_value)
    if m:
        try:
            max_age = int(m.group(1))
            if max_age >= 31536000:
                return 100, max_age
            elif max_age >= 2592000:
                return 70, max_age
            elif max_age > 0:
                return 40, max_age
        except:
            return 20, None
    return 20, None

def analyze_csp(csp_value):
    if not csp_value: return 0
    v = csp_value.lower()
    score = 30
    if "default-src" in v or "script-src" in v:
        score += 30
    if "unsafe-inline" in v or "unsafe-eval" in v:
        score -= 30
    if "'self'" in v or "https:" in v:
        score += 20
    return max(0, min(100, score))

def detect_mixed_content(resp, base_scheme):
    if not resp: return None
    if base_scheme != "https": return False
    content = resp.text or ""
    matches = re.findall(r'(?:src|href)\s*=\s*["\']http://', content, flags=re.I)
    return len(matches) > 0

def check_spf_dmarc(host):
    has_spf = False
    has_dmarc = False
    try:
        answers = dns.resolver.resolve(host, 'TXT', lifetime=TIMEOUT)
        for r in answers:
            txt = "".join(r.strings) if hasattr(r, 'strings') else str(r)
            if "v=spf1" in txt.lower():
                has_spf = True
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(f"_dmarc.{host}", 'TXT', lifetime=TIMEOUT)
        for r in answers:
            txt = "".join(r.strings) if hasattr(r, 'strings') else str(r)
            if "v=dmarc1" in txt.lower():
                has_dmarc = True
    except Exception:
        pass
    return has_spf, has_dmarc

def check_mx(host):
    try:
        answers = dns.resolver.resolve(host, 'MX', lifetime=TIMEOUT)
        return len(answers) > 0
    except Exception:
        return False

def check_well_known(base_url):
    res = {"security_txt": False, "robots_txt": False, "sitemap": False}
    try:
        r = requests.get(urljoin(base_url, "/.well-known/security.txt"), timeout=TIMEOUT, allow_redirects=True)
        if r.status_code == 200 and len(r.text.strip()) > 20:
            res["security_txt"] = True
    except:
        pass
    try:
        r2 = requests.get(urljoin(base_url, "/robots.txt"), timeout=TIMEOUT, allow_redirects=True)
        if r2.status_code == 200:
            res["robots_txt"] = True
            if "Sitemap:" in r2.text:
                res["sitemap"] = True
    except:
        pass
    return res

def try_connect_port(host, port):
    s = socket.socket()
    s.settimeout(TIMEOUT)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

# ------- 评分函数 -------
def score_tls(info):
    if not info["present"]:
        return 0
    score = 0
    if info["verified"] is True:
        score += 40
    elif info["verified"] is False:
        score += 15
    else:
        score += 10
    v = (info["tls_version"] or "").lower()
    if "1.3" in v:
        score += 30
    elif "1.2" in v:
        score += 20
    elif v:
        score += 5
    days = info.get("days_left")
    if days is None:
        score += 0
    elif days < 0:
        score += 0
    elif days < 30:
        score += 5
    elif days < 90:
        score += 10
    else:
        score += 15
    return int(min(100, score))

def score_headers_analysis(h):
    found = h["found_headers"]
    base = int((len(found) / len(SECURITY_HEADERS)) * 100)
    penalty = 0
    if h["server"]:
        penalty += 10
    if h["x_powered_by"]:
        penalty += 10
    final = max(0, base - penalty)
    return final

def score_hsts(value):
    s, _ = analyze_hsts(value)
    return s

def score_csp(value):
    return analyze_csp(value)

def score_mixed(m):
    if m is None: return 50
    return 0 if m else 100

def score_cookies(ci):
    if not ci["has_set_cookie"]: return 100
    s = 0
    if ci["secure_flag"]: s += 50
    if ci["httponly_flag"]: s += 50
    return s

def score_dns_email(spf, dmarc):
    s = 0
    if spf: s += 50
    if dmarc: s += 50
    return s

def score_mx(has_mx):
    return 100 if has_mx else 0

def score_ports(open_count, total):
    ratio = open_count / total
    return int((1 - ratio) * 100)

def aggregate(subscores):
    total = 0.0
    for k, w in WEIGHTS.items():
        total += subscores[k] * (w / 100.0)
    return int(round(total))

# ------- 主流程 -------
def single_scan(input_url):
    base_url, host, scheme = normalize_url(input_url)
    results = {"input": input_url, "base_url": base_url, "host": host, "scheme": scheme}

    with ThreadPoolExecutor(max_workers=12) as ex:
        f_tls = ex.submit(check_tls, host)
        f_fetch = ex.submit(fetch_root, base_url)
        f_spf = ex.submit(check_spf_dmarc, host)
        f_mx = ex.submit(check_mx, host)
        f_wk = ex.submit(check_well_known, base_url)
        port_fs = {p: ex.submit(try_connect_port, host, p) for p in COMMON_PORTS}

        tls_info = f_tls.result()
        resp = f_fetch.result()
        spf, dmarc = f_spf.result()
        mx = f_mx.result()
        wk = f_wk.result()
        open_ports = [p for p, fut in port_fs.items() if fut.result()]

    headers_analysis = analyze_headers(resp)
    hsts_val = headers_analysis["found_headers"].get("Strict-Transport-Security")
    csp_val = headers_analysis["found_headers"].get("Content-Security-Policy")
    mixed = detect_mixed_content(resp, scheme) if resp else None

    subscores = {}
    subscores["tls"] = score_tls(tls_info)
    subscores["headers"] = score_headers_analysis(headers_analysis)
    subscores["hsts"] = score_hsts(hsts_val)
    subscores["csp"] = score_csp(csp_val)
    subscores["mixed_content"] = score_mixed(mixed)
    subscores["cookies"] = score_cookies(headers_analysis["cookies"])
    subscores["dns_email"] = score_dns_email(spf, dmarc)
    subscores["mx"] = score_mx(mx)
    subscores["robots_securitytxt"] = int((1 if wk["security_txt"] else 0) * 50 + (1 if wk["robots_txt"] else 0) * 50)
    subscores["ports"] = score_ports(len(open_ports), len(COMMON_PORTS))

    total = aggregate(subscores)
    if total >= 80:
        risk = "Low"
    elif total >= 60:
        risk = "Medium"
    elif total >= 40:
        risk = "High"
    else:
        risk = "Critical"

    results.update({
        "tls": tls_info,
        "headers_analysis": headers_analysis,
        "hsts_value": hsts_val,
        "csp_value": csp_val,
        "mixed_content": mixed,
        "spf": spf, "dmarc": dmarc, "mx": mx,
        "well_known": wk,
        "open_ports": open_ports,
        "subscores": subscores,
        "total_score": total,
        "risk": risk
    })
    return results

# ------- 输出报告（简洁） -------
def print_report(r):
    print("\n=== Quick Passive Cyber Score ===")
    print(f"Target: {r['input']}")
    print(f"Score : {r['total_score']}/100    Risk: {r['risk']}")
    print("----------------------------------------")
    t = r['tls']
    print(f"TLS present: {t['present']}   Verified by CA: {t['verified']}   TLS version: {t['tls_version']}   Cert days left: {t.get('days_left')}")
    print(f"Security headers found: {list(r['headers_analysis']['found_headers'].keys())}")
    print(f"HSTS: {r['hsts_value']}   CSP present: {bool(r['csp_value'])}   Mixed content on HTTPS page: {('Unknown' if r['mixed_content'] is None else ('Yes' if r['mixed_content'] else 'No'))}")
    print(f"Set-Cookie flags: {r['headers_analysis']['cookies']}")
    print(f"SPF: {r['spf']}   DMARC: {r['dmarc']}   MX present: {r['mx']}")
    print(f"Well-known: security.txt: {r['well_known']['security_txt']}   robots.txt: {r['well_known']['robots_txt']}")
    print(f"Open common ports: {r['open_ports']}")
    print("\nSubscores (0-100) and weights:")
    for k, v in r['subscores'].items():
        print(f"  {k:18s}: {v:3d}  (weight {WEIGHTS[k]:2d}%)")
    print("----------------------------------------")
    print("Recommendations (quick):")
    if not r['tls']['present']:
        print(" - Enable HTTPS on public endpoints.")
    else:
        if r['tls']['verified'] is False:
            print(" - Certificate chain not validated by system CA: check chain / intermediate certs.")
        if r['tls'].get('days_left') is not None and r['tls']['days_left'] < 30:
            print(" - Certificate expiring soon: renew.")
    if r['subscores']['hsts'] < 50:
        print(" - Add/strengthen HSTS (long max-age, includeSubDomains) if appropriate.")
    if r['subscores']['csp'] < 50:
        print(" - Add/strengthen CSP to mitigate XSS.")
    if r['subscores']['mixed_content'] == 0:
        print(" - Fix mixed-content (http resources served on https pages).")
    if r['subscores']['cookies'] < 80:
        print(" - Ensure cookies use Secure and HttpOnly where appropriate.")
    if r['subscores']['dns_email'] < 100:
        print(" - Add/validate SPF and DMARC DNS records.")
    if r['subscores']['ports'] < 80:
        print(" - Review exposed services and firewall management ports.")
    print("\nNote: 这是快速、被动检测。对于权威结论请进行授权的深度评估或渗透测试。\n")

# ------- CLI -------
def main():
    if len(sys.argv) >= 2:
        url = sys.argv[1]
    else:
        url = input("请输入公司网址 (例如 example.com 或 https://example.com): ").strip()
    if not url:
        print("未输入网址，退出。")
        return
    r = single_scan(url)
    print_report(r)

if __name__ == "__main__":
    main()
