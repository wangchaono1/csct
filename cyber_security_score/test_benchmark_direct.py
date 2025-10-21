"""
Direct test of benchmark functions
"""

from validation_module import ValidationEngine
import json

validator = ValidationEngine()
domain = "allianz.com"

print("\n" + "=" * 60)
print("Testing SecurityHeaders.com")
print("=" * 60)
result = validator._check_security_headers(domain)
print(json.dumps(result, indent=2))

print("\n" + "=" * 60)
print("Testing SSL Labs")
print("=" * 60)
result = validator._check_ssl_labs(domain)
print(json.dumps(result, indent=2))

print("\n" + "=" * 60)
print("Testing benchmark_against_platforms")
print("=" * 60)
result = validator.benchmark_against_platforms(domain, 70)
print(f"\nTotal benchmarks: {len(result['benchmarks'])}")
print(json.dumps(result, indent=2))
