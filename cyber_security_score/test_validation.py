"""
test_validation.py
Test script to demonstrate validation functionality
"""

from validation_module import ValidationEngine
from single_target_cyber_score_updates import enhanced_scan


def test_validation():
    """Test validation on a sample domain"""
    # Test domain (use a well-known site)
    test_domain = "apple.com"

    print("\n" + "=" * 70)
    print("VALIDATION MODULE TEST")
    print("=" * 70)
    print(f"\nTesting domain: {test_domain}\n")

    # Step 1: Run scan
    print("Step 1: Running security scan...")
    scan_results = enhanced_scan(test_domain)
    print(f"✅ Scan complete. Score: {scan_results['total_score']}/100")

    # Step 2: Initialize validator
    print("\nStep 2: Initializing validation engine...")
    validator = ValidationEngine()
    print("✅ Validator initialized")

    # Step 3: Framework alignment only (fast)
    print("\nStep 3: Validating framework alignment...")
    framework_validation = validator.validate_framework_alignment(scan_results)
    print(f"✅ Framework validation complete")
    print(
        f" - NIST CSF Coverage: {framework_validation['nist_csf']['coverage_percentage']}%"
    )
    print(
        f" - CIS Controls Coverage: {framework_validation['cis_controls']['coverage_percentage']}%"
    )
    print(f" - OWASP Coverage: {framework_validation['owasp']['coverage_percentage']}%")

    # Step 4: Full validation with benchmarking (slower)
    print("\nStep 4: Running full validation (including benchmarking)...")
    print("⏳ This may take 30-60 seconds...")
    full_validation = validator.generate_validation_report(
        scan_results, include_benchmark=True
    )
    print("✅ Full validation complete")

    # Step 5: Display results
    print("\n" + "=" * 70)
    print("VALIDATION RESULTS")
    print("=" * 70)
    print(validator._format_text_report(full_validation))

    print("\n✅ Test complete!\n")


if __name__ == "__main__":
    test_validation()
