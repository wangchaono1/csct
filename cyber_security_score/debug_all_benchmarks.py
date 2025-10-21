"""
Debug script to test all benchmark APIs
"""

import requests
import time
import json
import re


def test_mozilla_observatory(domain):
    """Test Mozilla Observatory"""
    print(f"\n{'='*60}")
    print("Testing Mozilla HTTP Observatory")
    print(f"{'='*60}")

    try:
        response = requests.post(
            f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={domain}",
            headers={"User-Agent": "CyberScoreValidation/1.0"},
            timeout=10,
        )
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            print(f"Response: {json.dumps(response.json(), indent=2)}")
        else:
            print(f"Error: HTTP {response.status_code}")
            print(f"Content: {response.text[:200]}")
    except Exception as e:
        print(f"Exception: {e}")


def test_security_headers(domain):
    """Test SecurityHeaders.com"""
    print(f"\n{'='*60}")
    print("Testing SecurityHeaders.com")
    print(f"{'='*60}")

    try:
        url = f"https://securityheaders.com/?q={domain}&followRedirects=on"
        response = requests.get(
            url, headers={"User-Agent": "CyberScoreValidation/1.0"}, timeout=15
        )
        print(f"Status Code: {response.status_code}")

        if response.status_code == 200:
            # Look for grade
            grade_match = re.search(r'class="grade-([A-F][\+\-]?)"', response.text)
            if grade_match:
                grade = grade_match.group(1)
                print(f"✅ Found Grade: {grade}")
            else:
                print("❌ Could not find grade in HTML")
                # Show snippet of HTML
                print(f"HTML snippet: {response.text[:500]}")
        else:
            print(f"Error: HTTP {response.status_code}")
    except Exception as e:
        print(f"Exception: {e}")


def test_ssl_labs(domain):
    """Test SSL Labs API"""
    print(f"\n{'='*60}")
    print("Testing SSL Labs")
    print(f"{'='*60}")
    print("⚠️ Note: This can take 2-5 minutes...")

    try:
        # First check if there's a cached result
        response = requests.get(
            "https://api.ssllabs.com/api/v3/analyze",
            params={"host": domain, "fromCache": "on", "all": "done"},
            headers={"User-Agent": "CyberScoreValidation/1.0"},
            timeout=10,
        )

        print(f"Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"Status: {data.get('status')}")
            print(f"Full Response: {json.dumps(data, indent=2)[:1000]}")

            if data.get("status") == "READY":
                endpoints = data.get("endpoints", [])
                if endpoints:
                    grade = endpoints[0].get("grade", "Unknown")
                    print(f"✅ Grade: {grade}")
                else:
                    print("❌ No endpoints found")
            else:
                print(f"Status: {data.get('status')} - Scan may need to be initiated")
        else:
            print(f"Error: HTTP {response.status_code}")
            print(f"Content: {response.text[:200]}")
    except Exception as e:
        print(f"Exception: {e}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python debug_all_benchmarks.py <domain>")
        print("Example: python debug_all_benchmarks.py apple.com")
        sys.exit(1)

    domain = sys.argv[1]

    print(f"\n{'#'*60}")
    print(f"TESTING ALL BENCHMARK SERVICES FOR: {domain}")
    print(f"{'#'*60}")

    test_mozilla_observatory(domain)
    time.sleep(2)

    test_security_headers(domain)
    time.sleep(2)

    test_ssl_labs(domain)

    print(f"\n{'#'*60}")
    print("TESTING COMPLETE")
    print(f"{'#'*60}\n")
