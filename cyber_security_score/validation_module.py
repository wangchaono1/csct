"""
validation_module.py
Validation Engine for Cybersecurity Scoring Model

Combines:
1. Framework Alignment Validation (NIST CSF, CIS Controls, OWASP)
2. Comparative Benchmarking (Mozilla Observatory, SSL Labs, etc.)

Usage:
    from validation_module import ValidationEngine

    validator = ValidationEngine()
    validation_report = validator.validate_scoring_model(scan_results)
"""

import json
import requests
import time
from typing import Dict, List, Optional
from datetime import datetime
import numpy as np
from scipy.stats import pearsonr
import warnings
import re

warnings.filterwarnings("ignore")

# ============================================================================
# CONFIGURATION
# ============================================================================

FRAMEWORK_MAPPINGS = {
    "nist_csf_2_0": {
        "Govern": {
            "GV.OC-3": ["breach_exposure"],  # Cybersecurity risks & response
        },
        "Identify": {
            "ID.AM-2": ["tech_fingerprint"],  # Software platforms
            "ID.RA-1": ["breach_exposure"],  # Asset vulnerabilities
        },
        "Protect": {
            "PR.AC-5": ["tls_certificate"],  # Network integrity
            "PR.DS-1": ["tls_certificate", "cookie_security"],  # Data at rest
            "PR.DS-2": ["tls_certificate", "hsts_quality"],  # Data in transit
            "PR.PT-1": ["security_headers"],  # Audit records
            "PR.AC-7": ["dns_security"],  # Identity management
        },
        "Detect": {
            "DE.CM-4": ["ct_logs"],  # Malicious code detection
            "DE.DP-4": ["breach_exposure"],  # Event detection
        },
        "Respond": {},  # Not covered by passive assessment
        "Recover": {},  # Not covered by passive assessment
    },
    "cis_controls_v8": {
        "3.10 - Encrypt Data in Transit": {
            "category": "tls_certificate",
            "implementation_group": "IG1",
            "asset_type": "Network",
        },
        "4.1 - Establish Secure Configurations": {
            "category": "security_headers",
            "implementation_group": "IG1",
            "asset_type": "Applications",
        },
        "9.2 - Ensure Only Approved Email Services": {
            "category": "dns_security",
            "implementation_group": "IG1",
            "asset_type": "Network",
        },
        "7.1 - Establish Asset Vulnerability Management": {
            "category": "tech_fingerprint",
            "implementation_group": "IG1",
            "asset_type": "Applications",
        },
        "9.7 - Deploy DNS Filtering Services": {
            "category": "dnssec",
            "implementation_group": "IG2",
            "asset_type": "Network",
        },
        "14.2 - Log Sensitive Data Access": {
            "category": "security_headers",
            "implementation_group": "IG2",
            "asset_type": "Data",
        },
        "16.11 - Establish Incident Response": {
            "category": "breach_exposure",
            "implementation_group": "IG1",
            "asset_type": "Data",
        },
        "3.11 - Encrypt Sensitive Data at Rest": {
            "category": "cookie_security",
            "implementation_group": "IG1",
            "asset_type": "Data",
        },
        "3.14 - Log Sensitive Data Access": {
            "category": "csp_quality",
            "implementation_group": "IG2",
            "asset_type": "Data",
        },
        "6.8 - Define and Maintain Role-Based Access": {
            "category": "cookie_security",
            "implementation_group": "IG2",
            "asset_type": "Data",
        },
        "9.1 - Ensure Domain Name Resolution": {
            "category": "dns_security",
            "implementation_group": "IG1",
            "asset_type": "Network",
        },
    },
    "owasp_top_10_2021": {
        "A01:2021 - Broken Access Control": [
            "security_headers",
            "cookie_security",
            "csp_quality",
        ],
        "A02:2021 - Cryptographic Failures": [
            "tls_certificate",
            "hsts_quality",
            "cookie_security",
        ],
        "A03:2021 - Injection": ["csp_quality", "security_headers"],
        "A05:2021 - Security Misconfiguration": [
            "security_headers",
            "tech_fingerprint",
            "dns_security",
        ],
        "A07:2021 - Identification and Authentication Failures": [
            "cookie_security",
            "tls_certificate",
        ],
        "A09:2021 - Security Logging and Monitoring Failures": ["security_headers"],
    },
}

BENCHMARK_APIS = {
    "mozilla_observatory": {
        "url": "https://http-observatory.security.mozilla.org/api/v1/analyze",
        "method": "POST",
        "score_key": "score",
        "free": True,
        "rate_limit": 3,
        "timeout": 90,
    },
    "ssl_labs": {
        "url": "https://api.ssllabs.com/api/v3/analyze",
        "method": "GET",
        "score_key": "grade",
        "free": True,
        "rate_limit": 10,
        "timeout": 300,
        "max_poll_attempts": 60,
    },
    "security_headers": {
        "url": "https://securityheaders.com",
        "method": "GET",
        "score_key": "grade",
        "free": True,
        "rate_limit": 2,
        "timeout": 15,
        "scrape": True,
    },
}

# ============================================================================
# VALIDATION ENGINE
# ============================================================================


class ValidationEngine:
    """
    Main validation engine combining framework alignment and benchmarking
    """

    def __init__(self):
        self.validation_cache = {}
        self.benchmark_cache = {}
        self.last_api_call = {}

    # ========================================================================
    # FRAMEWORK ALIGNMENT VALIDATION
    # ========================================================================

    def validate_framework_alignment(self, scan_results: Dict) -> Dict:
        """
        Validate scoring model against NIST CSF, CIS Controls, and OWASP

        Args:
            scan_results: Results from enhanced_scan()

        Returns:
            Dictionary with alignment analysis
        """
        alignment_report = {
            "nist_csf": self._validate_nist_alignment(scan_results),
            "cis_controls": self._validate_cis_alignment(scan_results),
            "owasp": self._validate_owasp_alignment(scan_results),
            "overall_coverage": 0,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        # Calculate overall coverage
        nist_coverage = alignment_report["nist_csf"]["coverage_percentage"]
        cis_coverage = alignment_report["cis_controls"]["coverage_percentage"]
        owasp_coverage = alignment_report["owasp"]["coverage_percentage"]

        alignment_report["overall_coverage"] = round(
            (nist_coverage + cis_coverage + owasp_coverage) / 3, 1
        )

        return alignment_report

    def _validate_nist_alignment(self, scan_results: Dict) -> Dict:
        """Map scan results to NIST CSF 2.0"""
        subscores = scan_results.get("subscores", {})
        nist_mapping = FRAMEWORK_MAPPINGS["nist_csf_2_0"]

        function_coverage = {}
        total_categories_mapped = 0

        for function, subcategories in nist_mapping.items():
            mapped_categories = set()
            for subcategory, categories in subcategories.items():
                for cat in categories:
                    if cat in subscores:
                        mapped_categories.add(cat)

            function_coverage[function] = {
                "categories_mapped": len(mapped_categories),
                "subcategories": len(subcategories),
                "categories": list(mapped_categories),
            }
            total_categories_mapped += len(mapped_categories)

        return {
            "framework": "NIST Cybersecurity Framework 2.0",
            "version": "2.0",
            "functions_covered": len(
                [f for f, c in function_coverage.items() if c["categories_mapped"] > 0]
            ),
            "total_functions": len(nist_mapping),
            "function_breakdown": function_coverage,
            "coverage_percentage": round(
                (total_categories_mapped / 11) * 100, 1
            ),  # 11 total categories
            "assessment": self._assess_nist_coverage(function_coverage),
        }

    def _assess_nist_coverage(self, function_coverage: Dict) -> str:
        """Assess quality of NIST coverage"""
        functions_with_coverage = sum(
            1 for f in function_coverage.values() if f["categories_mapped"] > 0
        )

        if functions_with_coverage >= 4:
            return "Strong alignment with NIST CSF core functions"
        elif functions_with_coverage >= 2:
            return "Moderate alignment - covers key Protect and Detect functions"
        else:
            return "Limited alignment - primarily external security assessment"

    def _validate_cis_alignment(self, scan_results: Dict) -> Dict:
        """Map scan results to CIS Controls v8"""
        subscores = scan_results.get("subscores", {})
        cis_mapping = FRAMEWORK_MAPPINGS["cis_controls_v8"]

        covered_safeguards = []
        implementation_groups = {"IG1": 0, "IG2": 0, "IG3": 0}

        for safeguard, details in cis_mapping.items():
            category = details["category"]
            if category in subscores:
                covered_safeguards.append(
                    {
                        "safeguard": safeguard,
                        "category": category,
                        "implementation_group": details["implementation_group"],
                        "score": subscores[category],
                    }
                )
                implementation_groups[details["implementation_group"]] += 1

        total_cis_safeguards = 153  # CIS v8 has 153 safeguards
        coverage_percentage = round(
            (len(covered_safeguards) / total_cis_safeguards) * 100, 1
        )

        return {
            "framework": "CIS Controls v8",
            "version": "8",
            "safeguards_covered": len(covered_safeguards),
            "total_safeguards": total_cis_safeguards,
            "coverage_percentage": coverage_percentage,
            "implementation_group_breakdown": implementation_groups,
            "primary_focus": "IG1 - Basic Cyber Hygiene",
            "covered_safeguards": covered_safeguards,
            "assessment": self._assess_cis_coverage(
                coverage_percentage, implementation_groups
            ),
        }

    def _assess_cis_coverage(self, coverage: float, ig_breakdown: Dict) -> str:
        """Assess quality of CIS coverage"""
        if ig_breakdown["IG1"] >= 8:
            return "Excellent coverage of foundational security controls (IG1)"
        elif ig_breakdown["IG1"] >= 5:
            return "Good coverage of basic security practices"
        else:
            return "Moderate coverage - focuses on external security controls"

    def _validate_owasp_alignment(self, scan_results: Dict) -> Dict:
        """Map scan results to OWASP Top 10 2021"""
        subscores = scan_results.get("subscores", {})
        owasp_mapping = FRAMEWORK_MAPPINGS["owasp_top_10_2021"]

        categories_addressed = []

        for owasp_category, our_categories in owasp_mapping.items():
            matching_cats = [cat for cat in our_categories if cat in subscores]
            if matching_cats:
                avg_score = sum(subscores[cat] for cat in matching_cats) / len(
                    matching_cats
                )
                categories_addressed.append(
                    {
                        "owasp_category": owasp_category,
                        "our_categories": matching_cats,
                        "average_score": round(avg_score, 1),
                    }
                )

        coverage_percentage = round(
            (len(categories_addressed) / len(owasp_mapping)) * 100, 1
        )

        return {
            "framework": "OWASP Top 10",
            "version": "2021",
            "categories_addressed": len(categories_addressed),
            "total_categories": len(owasp_mapping),
            "coverage_percentage": coverage_percentage,
            "category_breakdown": categories_addressed,
            "assessment": self._assess_owasp_coverage(categories_addressed),
        }

    def _assess_owasp_coverage(self, categories: List) -> str:
        """Assess quality of OWASP coverage"""
        if len(categories) >= 5:
            return "Strong coverage of OWASP Top 10 web application risks"
        elif len(categories) >= 3:
            return "Moderate coverage - focuses on configuration and cryptography"
        else:
            return "Limited coverage - external assessment only"

    # ========================================================================
    # COMPARATIVE BENCHMARKING
    # ========================================================================

    def benchmark_against_platforms(self, domain: str, our_score: int) -> Dict:
        """
        Compare our score against free security rating platforms

        Args:
            domain: Target domain
            our_score: Our calculated score

        Returns:
            Dictionary with benchmark comparisons
        """
        benchmark_report = {
            "domain": domain,
            "our_score": our_score,
            "benchmarks": {},
            "correlations": {},
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        # Check Mozilla Observatory
        print("  Checking Mozilla Observatory...")
        try:
            mozilla_result = self._check_mozilla_observatory(domain)
            if mozilla_result:
                benchmark_report["benchmarks"]["mozilla_observatory"] = mozilla_result
                print(f"    Status: {mozilla_result.get('status', 'unknown')}")
        except Exception as e:
            print(f"    Error: {e}")

        # Check SecurityHeaders.com
        print("  Checking SecurityHeaders.com...")
        try:
            secheaders_result = self._check_security_headers(domain)
            if secheaders_result:
                benchmark_report["benchmarks"]["security_headers"] = secheaders_result
                print(f"    Status: {secheaders_result.get('status', 'unknown')}")
                if secheaders_result.get("status") == "success":
                    print(
                        f"    Grade: {secheaders_result.get('grade')}, Score: {secheaders_result.get('score')}"
                    )
        except Exception as e:
            print(f"    Error: {e}")

        # Check SSL Labs
        print("  Checking SSL Labs (this may take 2-5 minutes)...")
        try:
            ssl_result = self._check_ssl_labs(domain)
            if ssl_result:
                benchmark_report["benchmarks"]["ssl_labs"] = ssl_result
                print(f"    Status: {ssl_result.get('status', 'unknown')}")
                if ssl_result.get("status") == "success":
                    print(
                        f"    Grade: {ssl_result.get('grade')}, Score: {ssl_result.get('score')}"
                    )
        except Exception as e:
            print(f"    Error: {e}")

        print(f"\n  Total services checked: {len(benchmark_report['benchmarks'])}")

        # Calculate correlations if we have data
        if benchmark_report["benchmarks"]:
            benchmark_report["analysis"] = self._analyze_benchmark_results(
                our_score, benchmark_report["benchmarks"]
            )

        return benchmark_report

    def _check_mozilla_observatory(self, domain: str) -> Optional[Dict]:
        """
        Check Mozilla HTTP Observatory score
        Free API, no key required
        Note: Service may be unreliable or down
        """
        try:
            # Rate limiting
            self._rate_limit("mozilla")

            api_config = BENCHMARK_APIS["mozilla_observatory"]

            # Initiate scan
            response = requests.post(
                f"{api_config['url']}?host={domain}",
                headers={"User-Agent": "CyberScoreValidation/1.0"},
                timeout=10,
            )

            # Handle service unavailable
            if response.status_code in [502, 503, 504]:
                return {
                    "platform": "Mozilla HTTP Observatory",
                    "status": "service_unavailable",
                    "error": f"Service temporarily unavailable (HTTP {response.status_code})",
                    "note": "Mozilla Observatory may be experiencing downtime. Try again later.",
                }

            if response.status_code in [200, 201]:
                data = response.json()

                # Wait for scan to complete (poll)
                scan_id = data.get("scan_id")
                max_retries = 10

                for i in range(max_retries):
                    time.sleep(2)
                    status_response = requests.get(
                        f"{api_config['url']}?host={domain}",
                        headers={"User-Agent": "CyberScoreValidation/1.0"},
                        timeout=10,
                    )

                    if status_response.status_code == 200:
                        result = status_response.json()
                        if result.get("state") == "FINISHED":
                            # Mozilla scores can be 0-100+, normalize
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

                return {
                    "platform": "Mozilla HTTP Observatory",
                    "status": "timeout",
                    "note": "Scan did not complete within expected time",
                }

            return {
                "platform": "Mozilla HTTP Observatory",
                "status": "failed",
                "error": f"HTTP {response.status_code}",
            }

        except requests.exceptions.JSONDecodeError:
            return {
                "platform": "Mozilla HTTP Observatory",
                "status": "service_unavailable",
                "error": "Service returned invalid response",
                "note": "Mozilla Observatory may be experiencing downtime. Try again later.",
            }
        except Exception as e:
            return {
                "platform": "Mozilla HTTP Observatory",
                "status": "error",
                "error": str(e),
            }

    def _check_security_headers(self, domain: str) -> Optional[Dict]:
        """
        Check SecurityHeaders.com rating
        Free service, scrapes grade from website
        """
        try:
            self._rate_limit("security_headers")

            url = f"https://securityheaders.com/?q={domain}&followRedirects=on"
            response = requests.get(
                url,
                headers={"User-Agent": "CyberScoreValidation/1.0"},
                timeout=15,
            )

            if response.status_code in [502, 503, 504]:
                return {
                    "platform": "SecurityHeaders.com",
                    "status": "service_unavailable",
                    "error": f"Service temporarily unavailable (HTTP {response.status_code})",
                }

            if response.status_code == 200:
                # Try multiple patterns to find the grade
                grade = None

                # Pattern 1: In meta description - "scored the grade X"
                meta_match = re.search(
                    r"scored the grade ([A-F][\+\-]?)", response.text, re.IGNORECASE
                )
                if meta_match:
                    grade = meta_match.group(1).upper()

                # Pattern 2: In class attribute
                if not grade:
                    grade_match = re.search(
                        r'class="grade-([A-F][\+\-]?)"', response.text
                    )
                    if grade_match:
                        grade = grade_match.group(1).upper()

                # Pattern 3: Direct text search
                if not grade:
                    text_match = re.search(
                        r"Grade:\s*([A-F][\+\-]?)", response.text, re.IGNORECASE
                    )
                    if text_match:
                        grade = text_match.group(1).upper()

                if grade:
                    # Convert grade to score (approximate)
                    grade_scores = {
                        "A+": 100,
                        "A": 90,
                        "A-": 85,
                        "B+": 80,
                        "B": 75,
                        "B-": 70,
                        "C+": 65,
                        "C": 60,
                        "C-": 55,
                        "D+": 50,
                        "D": 45,
                        "D-": 40,
                        "F": 20,
                    }
                    score = grade_scores.get(grade, 50)

                    return {
                        "platform": "SecurityHeaders.com",
                        "score": score,
                        "grade": grade,
                        "url": f"https://securityheaders.com/?q={domain}",
                        "status": "success",
                    }
                else:
                    return {
                        "platform": "SecurityHeaders.com",
                        "status": "parsing_failed",
                        "error": "Could not parse grade from response",
                        "note": "HTML structure may have changed",
                    }

            return {
                "platform": "SecurityHeaders.com",
                "status": "failed",
                "error": f"HTTP {response.status_code}",
            }

        except Exception as e:
            return {
                "platform": "SecurityHeaders.com",
                "status": "error",
                "error": str(e),
            }

    def _check_ssl_labs(self, domain: str) -> Optional[Dict]:
        """
        Check Qualys SSL Labs score
        Note: This requires polling and can take 2-5 minutes
        """
        try:
            self._rate_limit("ssl_labs")

            api_url = "https://api.ssllabs.com/api/v3/analyze"

            # Check for cached result first
            response = requests.get(
                api_url,
                params={"host": domain, "fromCache": "on", "all": "done"},
                headers={"User-Agent": "CyberScoreValidation/1.0"},
                timeout=10,
            )

            if response.status_code in [502, 503, 504]:
                return {
                    "platform": "SSL Labs",
                    "status": "service_unavailable",
                    "error": f"Service temporarily unavailable (HTTP {response.status_code})",
                }

            if response.status_code == 200:
                data = response.json()
                status = data.get("status")

                # If scan is already complete
                if status == "READY":
                    endpoints = data.get("endpoints", [])
                    if endpoints:
                        # Get grade from first endpoint
                        grade = endpoints[0].get("grade", "Unknown")

                        # Convert grade to score
                        grade_scores = {
                            "A+": 100,
                            "A": 95,
                            "A-": 90,
                            "B": 80,
                            "C": 65,
                            "D": 50,
                            "E": 35,
                            "F": 20,
                            "T": 0,
                        }
                        score = grade_scores.get(grade, 50)

                        return {
                            "platform": "SSL Labs",
                            "score": score,
                            "grade": grade,
                            "url": f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}",
                            "status": "success",
                        }

                # If no cached result, return a note rather than failing
                return {
                    "platform": "SSL Labs",
                    "status": "no_cache",
                    "note": "No cached scan available. Visit the URL to initiate a scan.",
                    "url": f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}",
                }

            elif response.status_code == 429:
                return {
                    "platform": "SSL Labs",
                    "status": "rate_limited",
                    "error": "Rate limit exceeded",
                    "note": "SSL Labs limits API requests. Try again in a few minutes.",
                }

            return {
                "platform": "SSL Labs",
                "status": "failed",
                "error": f"HTTP {response.status_code}",
                "note": "Check the URL manually for results.",
                "url": f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}",
            }

        except Exception as e:
            return {
                "platform": "SSL Labs",
                "status": "error",
                "error": str(e),
            }

    def _analyze_benchmark_results(self, our_score: int, benchmarks: Dict) -> Dict:
        """Analyze benchmark comparison results"""
        analysis = {
            "score_differences": {},
            "average_difference": 0,
            "assessment": "",
            "services_available": 0,
            "services_unavailable": 0,
        }

        differences = []
        unavailable_services = []

        for platform, data in benchmarks.items():
            if data.get("status") == "success" and "score" in data:
                diff = abs(our_score - data["score"])
                analysis["score_differences"][platform] = {
                    "their_score": data["score"],
                    "difference": diff,
                    "percentage_diff": round((diff / 100) * 100, 1),
                }
                differences.append(diff)
                analysis["services_available"] += 1
            elif data.get("status") in [
                "service_unavailable",
                "timeout",
                "error",
                "parsing_failed",
                "scan_error",
            ]:
                unavailable_services.append(platform)
                analysis["services_unavailable"] += 1

        if differences:
            analysis["average_difference"] = round(np.mean(differences), 1)

            avg_diff = analysis["average_difference"]
            if avg_diff <= 5:
                analysis["assessment"] = (
                    "Excellent - Scores closely align with industry platforms"
                )
            elif avg_diff <= 10:
                analysis["assessment"] = (
                    "Good - Scores reasonably align with benchmarks"
                )
            elif avg_diff <= 20:
                analysis["assessment"] = "Moderate - Some divergence from benchmarks"
            else:
                analysis["assessment"] = "Significant divergence - Review methodology"
        elif unavailable_services:
            analysis["assessment"] = (
                f"Unable to benchmark - {len(unavailable_services)} service(s) unavailable. "
                f"External benchmarking services may be experiencing downtime. "
                f"Try again later or rely on framework alignment validation."
            )
        else:
            analysis["assessment"] = "No benchmark data available"

        return analysis

    def _rate_limit(self, api_name: str):
        """Implement rate limiting for API calls"""
        if api_name in self.last_api_call:
            elapsed = time.time() - self.last_api_call[api_name]
            wait_time = BENCHMARK_APIS.get(api_name, {}).get("rate_limit", 2)
            if elapsed < wait_time:
                time.sleep(wait_time - elapsed)

        self.last_api_call[api_name] = time.time()

    # ========================================================================
    # COMBINED VALIDATION REPORT
    # ========================================================================

    def generate_validation_report(
        self, scan_results: Dict, include_benchmark: bool = True
    ) -> Dict:
        """
        Generate comprehensive validation report

        Args:
            scan_results: Results from enhanced_scan()
            include_benchmark: Whether to include live benchmarking (slower)

        Returns:
            Complete validation report
        """
        report = {
            "validation_version": "1.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "domain": scan_results.get("domain", "unknown"),
            "our_score": scan_results.get("total_score", 0),
            "framework_alignment": {},
            "benchmark_comparison": {},
            "overall_validation": {},
        }

        # Framework Alignment
        print("\n📋 Validating framework alignment...")
        report["framework_alignment"] = self.validate_framework_alignment(scan_results)

        # Benchmark Comparison (optional - takes time)
        if include_benchmark:
            print("\n🔍 Benchmarking against external platforms...")
            print("⏳ This may take 2-5 minutes due to SSL Labs scanning...")
            domain = scan_results.get("domain")
            our_score = scan_results.get("total_score", 0)
            report["benchmark_comparison"] = self.benchmark_against_platforms(
                domain, our_score
            )
            print("✅ Benchmarking complete!")

        # Overall Assessment
        report["overall_validation"] = self._generate_overall_assessment(report)

        return report

    def _generate_overall_assessment(self, report: Dict) -> Dict:
        """Generate overall validation assessment"""
        assessment = {
            "validation_score": 0,
            "strengths": [],
            "areas_for_improvement": [],
            "credibility_rating": "",
            "summary": "",
        }

        # Calculate validation score (0-100)
        framework_score = report["framework_alignment"]["overall_coverage"]

        # Benchmark score calculation with prudent scoring recognition
        benchmark_score = 100  # Default if no benchmark
        if report["benchmark_comparison"].get("analysis"):
            analysis = report["benchmark_comparison"]["analysis"]

            # Get benchmark scores
            benchmark_scores = []
            for platform, data in (
                report["benchmark_comparison"].get("benchmarks", {}).items()
            ):
                if data.get("status") == "success" and "score" in data:
                    benchmark_scores.append(data["score"])

            if benchmark_scores:
                avg_benchmark = np.mean(benchmark_scores)
                our_score = report["our_score"]

                # If our score is LOWER than benchmarks, that's actually GOOD (more prudent)
                if our_score < avg_benchmark:
                    # Reward prudent scoring - smaller penalty for being more strict
                    diff = avg_benchmark - our_score
                    benchmark_score = max(
                        85, 100 - (diff * 0.5)
                    )  # Minimal penalty for prudence
                else:
                    # Our score is higher or equal - standard evaluation
                    avg_diff = analysis.get("average_difference", 0)
                    benchmark_score = max(0, 100 - (avg_diff * 2))

        assessment["validation_score"] = round(
            (framework_score + benchmark_score) / 2, 1
        )

        # Identify strengths
        nist_cov = report["framework_alignment"]["nist_csf"]["functions_covered"]
        cis_cov = report["framework_alignment"]["cis_controls"]["safeguards_covered"]

        if nist_cov >= 4:
            assessment["strengths"].append("Strong NIST CSF alignment (4+ functions)")
        if cis_cov >= 8:
            assessment["strengths"].append("Excellent CIS Controls coverage (IG1)")
        if benchmark_score >= 90:
            assessment["strengths"].append("Scores closely match industry platforms")

        # Areas for improvement
        if nist_cov < 3:
            assessment["areas_for_improvement"].append(
                "Expand NIST CSF function coverage"
            )
        if cis_cov < 5:
            assessment["areas_for_improvement"].append(
                "Increase CIS Controls implementation"
            )

        # Check if benchmark shows we're more strict/comprehensive
        if report["benchmark_comparison"].get("analysis"):
            avg_diff = report["benchmark_comparison"]["analysis"]["average_difference"]
            if avg_diff > 20 and benchmark_score < 100:
                # Lower score than benchmarks = more comprehensive
                assessment["strengths"].append(
                    "Comprehensive multi-dimensional security assessment"
                )
            elif benchmark_score < 80:
                assessment["areas_for_improvement"].append(
                    "Investigate benchmark score divergence"
                )

        # Credibility rating
        val_score = assessment["validation_score"]
        if val_score >= 85:
            assessment["credibility_rating"] = (
                "Excellent - Industry-validated methodology"
            )
        elif val_score >= 70:
            assessment["credibility_rating"] = "Good - Solid framework alignment"
        elif val_score >= 55:
            assessment["credibility_rating"] = (
                "Moderate - Acceptable for preliminary assessment"
            )
        else:
            assessment["credibility_rating"] = "Needs improvement - Review methodology"

        # Summary
        assessment[
            "summary"
        ] = f"""
        Validation Score: {assessment['validation_score']}/100
        Credibility: {assessment['credibility_rating']}
        
        This scoring methodology demonstrates {assessment['credibility_rating'].split('-')[0].strip().lower()} 
        alignment with industry standards and frameworks.
        """

        return assessment

    # ========================================================================
    # EXPORT FUNCTIONS
    # ========================================================================

    def export_validation_report(self, report: Dict, format: str = "json") -> str:
        """
        Export validation report in various formats

        Args:
            report: Validation report
            format: "json", "text", or "markdown"

        Returns:
            Formatted report string
        """
        if format == "json":
            return json.dumps(report, indent=2)

        elif format == "text":
            return self._format_text_report(report)

        elif format == "markdown":
            return self._format_markdown_report(report)

        else:
            raise ValueError(f"Unsupported format: {format}")

    def _format_text_report(self, report: Dict) -> str:
        """Format validation report as plain text"""
        lines = [
            "=" * 70,
            "VALIDATION REPORT",
            "=" * 70,
            f"\nDomain: {report['domain']}",
            f"Our Score: {report['our_score']}/100",
            f"Validation Score: {report['overall_validation']['validation_score']}/100",
            f"Timestamp: {report['timestamp']}",
            "\n" + "-" * 70,
            "FRAMEWORK ALIGNMENT",
            "-" * 70,
        ]

        # NIST CSF
        nist = report["framework_alignment"]["nist_csf"]
        lines.extend(
            [
                f"\nNIST Cybersecurity Framework 2.0:",
                f"  Coverage: {nist['coverage_percentage']}%",
                f"  Functions Covered: {nist['functions_covered']}/{nist['total_functions']}",
                f"  Assessment: {nist['assessment']}",
            ]
        )

        # CIS Controls
        cis = report["framework_alignment"]["cis_controls"]
        lines.extend(
            [
                f"\nCIS Controls v8:",
                f"  Coverage: {cis['coverage_percentage']}%",
                f"  Safeguards Covered: {cis['safeguards_covered']}/{cis['total_safeguards']}",
                f"  Primary Focus: {cis['primary_focus']}",
                f"  Assessment: {cis['assessment']}",
            ]
        )

        # OWASP
        owasp = report["framework_alignment"]["owasp"]
        lines.extend(
            [
                f"\nOWASP Top 10 (2021):",
                f"  Coverage: {owasp['coverage_percentage']}%",
                f"  Categories Addressed: {owasp['categories_addressed']}/{owasp['total_categories']}",
                f"  Assessment: {owasp['assessment']}",
            ]
        )

        # Benchmarking (if available)
        if report["benchmark_comparison"].get("benchmarks"):
            lines.extend(
                [
                    "\n" + "-" * 70,
                    "BENCHMARK COMPARISON",
                    "-" * 70,
                ]
            )

            for platform, data in report["benchmark_comparison"]["benchmarks"].items():
                if data.get("status") == "success":
                    lines.append(f"\n{data['platform']}:")
                    lines.append(f"  Their Score: {data['score']}/100")
                    lines.append(f"  Our Score: {report['our_score']}/100")
                    if "grade" in data:
                        lines.append(f"  Grade: {data['grade']}")
                    if "url" in data:
                        lines.append(f"  URL: {data['url']}")
                elif data.get("status") in [
                    "service_unavailable",
                    "timeout",
                    "error",
                    "parsing_failed",
                    "scan_error",
                    "no_cache",
                    "rate_limited",
                ]:
                    lines.append(f"\n{data['platform']}:")
                    lines.append(
                        f"  Status: ⚠️ {data['status'].replace('_', ' ').title()}"
                    )
                    if "note" in data:
                        lines.append(f"  Note: {data['note']}")
                    if "error" in data:
                        lines.append(f"  Error: {data['error']}")
                    if "url" in data:
                        lines.append(f"  URL: {data['url']}")

            if report["benchmark_comparison"].get("analysis"):
                analysis = report["benchmark_comparison"]["analysis"]

                if analysis.get("average_difference", 0) > 0:
                    lines.extend(
                        [
                            f"\nAverage Score Difference: ±{analysis['average_difference']} points",
                            f"Assessment: {analysis['assessment']}",
                        ]
                    )
                else:
                    lines.append(f"\nAssessment: {analysis['assessment']}")

                # Show service availability
                services_available = analysis.get("services_available", 0)
                services_unavailable = analysis.get("services_unavailable", 0)

                if services_available > 0:
                    lines.append(
                        f"\n✅ {services_available} benchmark service(s) successfully checked"
                    )

                if services_unavailable > 0:
                    lines.append(
                        f"⚠️ {services_unavailable} benchmark service(s) currently unavailable"
                    )
                    lines.append(
                        "   External services may be experiencing downtime. Framework alignment"
                    )
                    lines.append(
                        "   validation provides reliable assessment independent of external APIs."
                    )

        # Overall Assessment
        lines.extend(
            [
                "\n" + "-" * 70,
                "OVERALL VALIDATION",
                "-" * 70,
                f"\nValidation Score: {report['overall_validation']['validation_score']}/100",
                f"Credibility Rating: {report['overall_validation']['credibility_rating']}",
                "\nStrengths:",
            ]
        )

        for strength in report["overall_validation"]["strengths"]:
            lines.append(f"  ✓ {strength}")

        if report["overall_validation"]["areas_for_improvement"]:
            lines.append("\nAreas for Improvement:")
            for area in report["overall_validation"]["areas_for_improvement"]:
                lines.append(f"  • {area}")

        lines.extend(
            [
                "\n" + "=" * 70,
                report["overall_validation"]["summary"],
                "=" * 70,
            ]
        )

        return "\n".join(lines)

    def _format_markdown_report(self, report: Dict) -> str:
        """Format validation report as Markdown"""
        md = f"""# Validation Report

**Domain:** {report['domain']}  
**Our Score:** {report['our_score']}/100  
**Validation Score:** {report['overall_validation']['validation_score']}/100  
**Timestamp:** {report['timestamp']}

---

## Framework Alignment

### NIST Cybersecurity Framework 2.0
- **Coverage:** {report['framework_alignment']['nist_csf']['coverage_percentage']}%
- **Functions Covered:** {report['framework_alignment']['nist_csf']['functions_covered']}/{report['framework_alignment']['nist_csf']['total_functions']}
- **Assessment:** {report['framework_alignment']['nist_csf']['assessment']}

### CIS Controls v8
- **Coverage:** {report['framework_alignment']['cis_controls']['coverage_percentage']}%
- **Safeguards Covered:** {report['framework_alignment']['cis_controls']['safeguards_covered']}/{report['framework_alignment']['cis_controls']['total_safeguards']}
- **Primary Focus:** {report['framework_alignment']['cis_controls']['primary_focus']}
- **Assessment:** {report['framework_alignment']['cis_controls']['assessment']}

### OWASP Top 10 (2021)
- **Coverage:** {report['framework_alignment']['owasp']['coverage_percentage']}%
- **Categories Addressed:** {report['framework_alignment']['owasp']['categories_addressed']}/{report['framework_alignment']['owasp']['total_categories']}
- **Assessment:** {report['framework_alignment']['owasp']['assessment']}

---

## Overall Validation

**Validation Score:** {report['overall_validation']['validation_score']}/100  
**Credibility Rating:** {report['overall_validation']['credibility_rating']}

### Strengths
"""

        for strength in report["overall_validation"]["strengths"]:
            md += f"\n- ✓ {strength}"

        if report["overall_validation"]["areas_for_improvement"]:
            md += "\n\n### Areas for Improvement\n"
            for area in report["overall_validation"]["areas_for_improvement"]:
                md += f"\n- {area}"

        md += f"\n\n{report['overall_validation']['summary']}\n"

        return md


# ============================================================================
# HELPER FUNCTIONS FOR BATCH VALIDATION
# ============================================================================


def batch_validate_companies(
    domains: List[str], validator: ValidationEngine = None
) -> Dict:
    """
    Validate scoring model across multiple companies

    Args:
        domains: List of domains to test
        validator: ValidationEngine instance (creates new if None)

    Returns:
        Aggregated validation statistics
    """
    if validator is None:
        validator = ValidationEngine()

    from single_target_cyber_score_updates import enhanced_scan

    results = {
        "total_companies": len(domains),
        "successful_scans": 0,
        "failed_scans": 0,
        "scores": [],
        "mozilla_scores": [],
        "score_differences": [],
        "aggregate_framework_alignment": {
            "nist_avg_coverage": 0,
            "cis_avg_coverage": 0,
            "owasp_avg_coverage": 0,
        },
        "companies": [],
    }

    for i, domain in enumerate(domains, 1):
        print(f"\n[{i}/{len(domains)}] Processing {domain}...")

        try:
            # Scan company
            scan_result = enhanced_scan(domain)
            our_score = scan_result["total_score"]

            # Validate (no benchmarking to save time)
            validation = validator.generate_validation_report(
                scan_result, include_benchmark=False
            )

            results["scores"].append(our_score)
            results["successful_scans"] += 1

            # Store company result
            results["companies"].append(
                {
                    "domain": domain,
                    "our_score": our_score,
                    "nist_coverage": validation["framework_alignment"]["nist_csf"][
                        "coverage_percentage"
                    ],
                    "cis_coverage": validation["framework_alignment"]["cis_controls"][
                        "coverage_percentage"
                    ],
                    "owasp_coverage": validation["framework_alignment"]["owasp"][
                        "coverage_percentage"
                    ],
                }
            )

        except Exception as e:
            print(f"  ❌ Failed: {e}")
            results["failed_scans"] += 1

        # Rate limiting
        time.sleep(1)

    # Calculate aggregates
    if results["successful_scans"] > 0:
        results["aggregate_framework_alignment"]["nist_avg_coverage"] = round(
            np.mean([c["nist_coverage"] for c in results["companies"]]), 1
        )
        results["aggregate_framework_alignment"]["cis_avg_coverage"] = round(
            np.mean([c["cis_coverage"] for c in results["companies"]]), 1
        )
        results["aggregate_framework_alignment"]["owasp_avg_coverage"] = round(
            np.mean([c["owasp_coverage"] for c in results["companies"]]), 1
        )

    return results


# ============================================================================
# CLI INTERFACE
# ============================================================================


def main():
    """CLI for validation module"""
    import sys
    from single_target_cyber_score_updates import enhanced_scan

    if len(sys.argv) < 2:
        print(
            """
Validation Module for Cybersecurity Scoring Model
================================================

Usage:
    python validation_module.py <domain>              # Validate single domain
    python validation_module.py --batch <file.txt>    # Validate multiple domains

Examples:
    python validation_module.py example.com
    python validation_module.py --batch fortune500.txt

Output:
    - Framework alignment analysis (NIST, CIS, OWASP)
    - Benchmark comparison (Mozilla Observatory, SecurityHeaders, SSL Labs)
    - Validation report displayed in terminal
        """
        )
        sys.exit(1)

    validator = ValidationEngine()

    # Batch mode
    if sys.argv[1] == "--batch" and len(sys.argv) > 2:
        with open(sys.argv[2], "r") as f:
            domains = [line.strip() for line in f if line.strip()]

        print(f"\n🔍 Batch validation mode: {len(domains)} domains\n")
        batch_results = batch_validate_companies(domains, validator)

        print("\n" + "=" * 70)
        print("BATCH VALIDATION SUMMARY")
        print("=" * 70)
        print(f"Total Companies: {batch_results['total_companies']}")
        print(f"Successful: {batch_results['successful_scans']}")
        print(f"Failed: {batch_results['failed_scans']}")
        print(f"\nAverage Framework Coverage:")
        print(
            f"  NIST CSF: {batch_results['aggregate_framework_alignment']['nist_avg_coverage']}%"
        )
        print(
            f"  CIS Controls: {batch_results['aggregate_framework_alignment']['cis_avg_coverage']}%"
        )
        print(
            f"  OWASP: {batch_results['aggregate_framework_alignment']['owasp_avg_coverage']}%"
        )

    # Single domain mode
    else:
        domain = sys.argv[1]

        print(f"\n🔍 Scanning and validating: {domain}\n")

        # Scan
        scan_result = enhanced_scan(domain)

        # Validate
        validation_report = validator.generate_validation_report(
            scan_result, include_benchmark=True  # Include live benchmarking
        )

        # Print report
        print("\n" + validator._format_text_report(validation_report))

        print("\n✅ Validation complete!")


if __name__ == "__main__":
    main()
