"""
Debug script to test Mozilla Observatory API
"""

import requests
import time
import json


def test_mozilla_observatory(domain):
    """Test Mozilla Observatory API with detailed logging"""

    print(f"\n{'='*60}")
    print(f"Testing Mozilla Observatory API for: {domain}")
    print(f"{'='*60}\n")

    api_url = "https://http-observatory.security.mozilla.org/api/v1/analyze"
    headers = {"User-Agent": "CyberScoreValidation/1.0"}

    # Step 1: Initiate scan
    print("Step 1: Initiating scan...")
    try:
        response = requests.post(
            f"{api_url}?host={domain}", headers=headers, timeout=10
        )
        print(f"  Status Code: {response.status_code}")
        print(f"  Response: {json.dumps(response.json(), indent=2)}")

        if response.status_code not in [200, 201]:
            print(f"  ❌ Failed to initiate scan")
            return None

        data = response.json()
        scan_id = data.get("scan_id")
        state = data.get("state")

        print(f"  Scan ID: {scan_id}")
        print(f"  Initial State: {state}")

    except Exception as e:
        print(f"  ❌ Error: {e}")
        return None

    # Step 2: Poll for results
    print("\nStep 2: Polling for results...")
    max_retries = 15

    for i in range(max_retries):
        print(f"  Poll attempt {i+1}/{max_retries}...")
        time.sleep(3)

        try:
            status_response = requests.get(
                f"{api_url}?host={domain}", headers=headers, timeout=10
            )

            if status_response.status_code == 200:
                result = status_response.json()
                state = result.get("state")
                score = result.get("score")

                print(f"    State: {state}, Score: {score}")

                if state == "FINISHED":
                    print(f"\n  ✅ Scan completed!")
                    print(f"  Final Result: {json.dumps(result, indent=2)}")

                    # Normalize score
                    raw_score = result.get("score", 0)
                    normalized_score = min(100, max(0, raw_score))

                    return {
                        "platform": "Mozilla HTTP Observatory",
                        "score": normalized_score,
                        "grade": result.get("grade", "Unknown"),
                        "tests_passed": result.get("tests_passed", 0),
                        "tests_failed": result.get("tests_failed", 0),
                        "url": f"https://observatory.mozilla.org/analyze/{domain}",
                        "status": "success",
                    }
                elif state == "FAILED":
                    print(f"  ❌ Scan failed")
                    return None

        except Exception as e:
            print(f"    ❌ Error: {e}")

    print(f"\n  ⚠️ Timeout: Scan did not complete in {max_retries * 3} seconds")
    return None


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python debug_benchmark.py <domain>")
        print("Example: python debug_benchmark.py apple.com")
        sys.exit(1)

    domain = sys.argv[1]
    result = test_mozilla_observatory(domain)

    if result:
        print(f"\n{'='*60}")
        print("SUCCESS!")
        print(f"{'='*60}")
        print(f"Platform: {result['platform']}")
        print(f"Score: {result['score']}/100")
        print(f"Grade: {result['grade']}")
        print(f"Tests Passed: {result['tests_passed']}")
        print(f"Tests Failed: {result['tests_failed']}")
        print(f"URL: {result['url']}")
    else:
        print(f"\n{'='*60}")
        print("FAILED - No results obtained")
        print(f"{'='*60}")
