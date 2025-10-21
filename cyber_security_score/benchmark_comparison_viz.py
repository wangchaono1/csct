"""
benchmark_comparison_viz.py
Visualization tools for benchmark comparison results

Creates professional charts and reports for client presentations
"""

import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List
import json


def create_benchmark_comparison_chart(
    benchmark_data: Dict, output_file: str = "benchmark_comparison.png"
):
    """
    Create a professional bar chart comparing scores across platforms

    Args:
        benchmark_data: Benchmark comparison data
        output_file: Output filename for chart
    """
    our_score = benchmark_data.get("our_score", 0)
    benchmarks = benchmark_data.get("benchmarks", {})

    # Extract scores
    platforms = ["Our Score"]
    scores = [our_score]
    colors = ["#1565C0"]  # Blue for our score

    for platform, data in benchmarks.items():
        if data.get("status") == "success" and "score" in data:
            platforms.append(data.get("platform", platform))
            scores.append(data["score"])

            # Color based on comparison
            diff = abs(our_score - data["score"])
            if diff <= 10:
                colors.append("#388E3C")  # Green - close match
            elif diff <= 20:
                colors.append("#F9A825")  # Yellow - moderate
            else:
                colors.append("#FF6F00")  # Orange - divergent

    # Create figure
    fig, ax = plt.subplots(figsize=(12, 6))

    # Create bars
    bars = ax.bar(
        platforms, scores, color=colors, alpha=0.8, edgecolor="black", linewidth=1.5
    )

    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            height,
            f"{int(height)}",
            ha="center",
            va="bottom",
            fontsize=12,
            fontweight="bold",
        )

    # Styling
    ax.set_ylabel("Security Score (0-100)", fontsize=14, fontweight="bold")
    ax.set_title(
        "Benchmark Comparison: Our Score vs Industry Platforms",
        fontsize=16,
        fontweight="bold",
        pad=20,
    )
    ax.set_ylim(0, 110)
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.set_axisbelow(True)

    # Add reference line at our score
    ax.axhline(y=our_score, color="#1565C0", linestyle="--", linewidth=2, alpha=0.5)

    # Rotate x labels if many platforms
    if len(platforms) > 5:
        plt.xticks(rotation=45, ha="right")

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches="tight")
    print(f"✅ Chart saved: {output_file}")

    return output_file


def generate_client_presentation_report(
    validation_report: Dict, output_file: str = "client_validation_report.html"
):
    """
    Generate a professional HTML report for client presentations

    Args:
        validation_report: Complete validation report
        output_file: Output HTML filename
    """
    domain = validation_report.get("domain", "Unknown")
    our_score = validation_report.get("our_score", 0)
    timestamp = validation_report.get("timestamp", "")

    # Framework alignment
    framework = validation_report.get("framework_alignment", {})
    nist = framework.get("nist_csf", {})
    cis = framework.get("cis_controls", {})
    owasp = framework.get("owasp", {})

    # Benchmark comparison
    benchmark = validation_report.get("benchmark_comparison", {})
    benchmarks = benchmark.get("benchmarks", {})
    analysis = benchmark.get("analysis", {})
    summary = benchmark.get("summary", {})

    # Overall validation
    overall = validation_report.get("overall_validation", {})

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Validation Report - {domain}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header {{
            text-align: center;
            border-bottom: 3px solid #1565C0;
            padding-bottom: 30px;
            margin-bottom: 40px;
        }}
        
        .header h1 {{
            color: #1565C0;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            color: #666;
            font-size: 1.2em;
        }}
        
        .score-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 40px;
        }}
        
        .score-card .score {{
            font-size: 4em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .score-card .label {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #1565C0;
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #1565C0;
        }}
        
        .card h3 {{
            color: #1565C0;
            margin-bottom: 10px;
            font-size: 1.3em;
        }}
        
        .metric {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .metric:last-child {{
            border-bottom: none;
        }}
        
        .metric .label {{
            font-weight: 600;
            color: #555;
        }}
        
        .metric .value {{
            color: #1565C0;
            font-weight: bold;
        }}
        
        .benchmark-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        .benchmark-table th,
        .benchmark-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .benchmark-table th {{
            background: #1565C0;
            color: white;
            font-weight: 600;
        }}
        
        .benchmark-table tr:hover {{
            background: #f5f5f5;
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .status-success {{
            background: #4CAF50;
            color: white;
        }}
        
        .status-partial {{
            background: #FFC107;
            color: #333;
        }}
        
        .status-failed {{
            background: #F44336;
            color: white;
        }}
        
        .grade {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        
        .grade-a {{ background: #4CAF50; color: white; }}
        .grade-b {{ background: #8BC34A; color: white; }}
        .grade-c {{ background: #FFC107; color: #333; }}
        .grade-d {{ background: #FF9800; color: white; }}
        .grade-f {{ background: #F44336; color: white; }}
        
        .strengths {{
            background: #e8f5e9;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #4CAF50;
            margin-bottom: 20px;
        }}
        
        .strengths h3 {{
            color: #4CAF50;
            margin-bottom: 10px;
        }}
        
        .strengths ul {{
            list-style: none;
            padding-left: 0;
        }}
        
        .strengths li {{
            padding: 8px 0;
            padding-left: 25px;
            position: relative;
        }}
        
        .strengths li:before {{
            content: "✓";
            position: absolute;
            left: 0;
            color: #4CAF50;
            font-weight: bold;
            font-size: 1.2em;
        }}
        
        .improvements {{
            background: #fff3e0;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #FF9800;
        }}
        
        .improvements h3 {{
            color: #FF9800;
            margin-bottom: 10px;
        }}
        
        .improvements ul {{
            list-style: none;
            padding-left: 0;
        }}
        
        .improvements li {{
            padding: 8px 0;
            padding-left: 25px;
            position: relative;
        }}
        
        .improvements li:before {{
            content: "•";
            position: absolute;
            left: 0;
            color: #FF9800;
            font-weight: bold;
            font-size: 1.5em;
        }}
        
        .footer {{
            text-align: center;
            padding-top: 30px;
            margin-top: 40px;
            border-top: 2px solid #e0e0e0;
            color: #666;
            font-size: 0.9em;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scoring Validation Report</h1>
            <p class="subtitle">Domain: <strong>{domain}</strong></p>
            <p class="subtitle">Generated: {timestamp}</p>
        </div>
        
        <div class="score-card">
            <div class="label">Overall Validation Score</div>
            <div class="score">{overall.get('validation_score', 0)}/100</div>
            <div class="label">{overall.get('credibility_rating', '')}</div>
        </div>
        
        <div class="section">
            <h2>📋 Framework Alignment</h2>
            <div class="grid">
                <div class="card">
                    <h3>NIST Cybersecurity Framework 2.0</h3>
                    <div class="metric">
                        <span class="label">Coverage:</span>
                        <span class="value">{nist.get('coverage_percentage', 0)}%</span>
                    </div>
                    <div class="metric">
                        <span class="label">Functions Covered:</span>
                        <span class="value">{nist.get('functions_covered', 0)}/{nist.get('total_functions', 6)}</span>
                    </div>
                    <p style="margin-top: 10px; color: #666; font-size: 0.9em;">
                        {nist.get('assessment', '')}
                    </p>
                </div>
                
                <div class="card">
                    <h3>CIS Controls v8</h3>
                    <div class="metric">
                        <span class="label">Coverage:</span>
                        <span class="value">{cis.get('coverage_percentage', 0)}%</span>
                    </div>
                    <div class="metric">
                        <span class="label">Safeguards Covered:</span>
                        <span class="value">{cis.get('safeguards_covered', 0)}/{cis.get('total_safeguards', 153)}</span>
                    </div>
                    <p style="margin-top: 10px; color: #666; font-size: 0.9em;">
                        {cis.get('assessment', '')}
                    </p>
                </div>
                
                <div class="card">
                    <h3>OWASP Top 10 (2021)</h3>
                    <div class="metric">
                        <span class="label">Coverage:</span>
                        <span class="value">{owasp.get('coverage_percentage', 0)}%</span>
                    </div>
                    <div class="metric">
                        <span class="label">Categories Addressed:</span>
                        <span class="value">{owasp.get('categories_addressed', 0)}/{owasp.get('total_categories', 10)}</span>
                    </div>
                    <p style="margin-top: 10px; color: #666; font-size: 0.9em;">
                        {owasp.get('assessment', '')}
                    </p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 Benchmark Comparison</h2>
            
            <table class="benchmark-table">
                <thead>
                    <tr>
                        <th>Platform</th>
                        <th>Status</th>
                        <th>Score</th>
                        <th>Grade</th>
                        <th>Difference</th>
                        <th>Agreement</th>
                    </tr>
                </thead>
                <tbody>
                    <tr style="background: #e3f2fd;">
                        <td><strong>Our Score</strong></td>
                        <td><span class="status-badge status-success">Reference</span></td>
                        <td><strong>{our_score}</strong></td>
                        <td>-</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
"""

    # Add benchmark rows
    for platform, data in benchmarks.items():
        status = data.get("status", "unknown")
        status_class = (
            "status-success"
            if status == "success"
            else "status-partial" if status == "partial" else "status-failed"
        )

        score = data.get("score", "-")
        grade = data.get("grade", "-")

        # Get difference and agreement
        diff_data = analysis.get("score_differences", {}).get(platform, {})
        difference = diff_data.get("difference", "-")
        agreement = diff_data.get("agreement", "-")

        if grade != "-":
            grade_class = f"grade-{grade[0].lower()}"
            grade_html = f'<span class="grade {grade_class}">{grade}</span>'
        else:
            grade_html = "-"

        html_content += f"""
                    <tr>
                        <td><strong>{data.get('platform', platform)}</strong></td>
                        <td><span class="status-badge {status_class}">{status}</span></td>
                        <td>{score}</td>
                        <td>{grade_html}</td>
                        <td>{difference if isinstance(difference, str) else f'±{difference}'}</td>
                        <td>{agreement}</td>
                    </tr>
"""

    html_content += f"""
                </tbody>
            </table>
            
            <div class="grid">
                <div class="card">
                    <h3>Summary Statistics</h3>
                    <div class="metric">
                        <span class="label">Platforms Tested:</span>
                        <span class="value">{summary.get('total_platforms_tested', 0)}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Successful Checks:</span>
                        <span class="value">{summary.get('successful_checks', 0)}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Average Competitor Score:</span>
                        <span class="value">{summary.get('average_competitor_score', 'N/A')}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Our Position:</span>
                        <span class="value">{summary.get('our_position', 'N/A')}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Statistical Analysis</h3>
                    <div class="metric">
                        <span class="label">Average Difference:</span>
                        <span class="value">±{analysis.get('average_difference', 'N/A')} points</span>
                    </div>
                    <div class="metric">
                        <span class="label">Platforms with Scores:</span>
                        <span class="value">{analysis.get('platforms_with_scores', 0)}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Overall Assessment:</span>
                        <span class="value" style="font-size: 0.9em;">{analysis.get('assessment', 'N/A')}</span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>✅ Overall Validation Assessment</h2>
            
            <div class="strengths">
                <h3>Strengths</h3>
                <ul>
"""

    for strength in overall.get("strengths", []):
        html_content += f"                    <li>{strength}</li>\n"

    html_content += """
                </ul>
            </div>
"""

    if overall.get("areas_for_improvement"):
        html_content += """
            <div class="improvements">
                <h3>Areas for Improvement</h3>
                <ul>
"""
        for area in overall.get("areas_for_improvement", []):
            html_content += f"                    <li>{area}</li>\n"

        html_content += """
                </ul>
            </div>
"""

    html_content += f"""
        </div>
        
        <div class="footer">
            <p><strong>Enhanced Cybersecurity Assessment Platform v2.0</strong></p>
            <p>Validated against NIST CSF, CIS Controls, OWASP standards</p>
            <p>Benchmarked against {summary.get('successful_checks', 0)} independent security platforms</p>
            <p style="margin-top: 10px; font-size: 0.85em; color: #999;">
                This validation report demonstrates the credibility and accuracy of our security scoring methodology.
                For questions or detailed methodology documentation, please contact your security team.
            </p>
        </div>
    </div>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"✅ Client report saved: {output_file}")
    return output_file


# ============================================================================
# MAIN EXECUTION
# ============================================================================


def main():
    """Demo script for visualization"""
    import sys

    if len(sys.argv) < 2:
        print(
            """
Benchmark Visualization Tool
=============================

Usage:
    python benchmark_comparison_viz.py <validation_report.json>

Generates:
    - benchmark_comparison.png (bar chart)
    - correlation_scatter.png (scatter plot)
    - grade_distribution.png (pie chart)
    - client_validation_report.html (professional report)
        """
        )
        sys.exit(1)

    # Load validation report
    with open(sys.argv[1], "r") as f:
        validation_report = json.load(f)

    print("\n🎨 Generating visualizations...\n")

    # Extract benchmark data
    benchmark_data = validation_report.get("benchmark_comparison", {})
    our_score = validation_report.get("our_score", 0)

    # Generate charts
    create_benchmark_comparison_chart(benchmark_data)
    create_correlation_scatter(our_score, benchmark_data.get("benchmarks", {}))
    create_grade_distribution_chart(benchmark_data)

    # Generate client report
    generate_client_presentation_report(validation_report)

    print("\n✅ All visualizations generated successfully!\n")


if __name__ == "__main__":
    main()

    print(f"✅ Chart saved: {output_file}")

    return output_file


def create_correlation_scatter(
    our_score: int, benchmarks: Dict, output_file: str = "correlation_scatter.png"
):
    """
    Create scatter plot showing correlation between our scores and benchmark scores

    Args:
        our_score: Our calculated score
        benchmarks: Dictionary of benchmark results
        output_file: Output filename
    """
    competitor_scores = []
    platform_names = []

    for platform, data in benchmarks.items():
        if data.get("status") == "success" and "score" in data:
            competitor_scores.append(data["score"])
            platform_names.append(data.get("platform", platform))

    if len(competitor_scores) < 2:
        print("⚠️  Need at least 2 benchmark scores for correlation plot")
        return None

    our_scores = [our_score] * len(competitor_scores)

    # Create figure
    fig, ax = plt.subplots(figsize=(10, 8))

    # Scatter plot
    ax.scatter(
        competitor_scores,
        our_scores,
        s=200,
        alpha=0.6,
        c="#1565C0",
        edgecolors="black",
        linewidth=2,
    )

    # Add platform labels
    for i, platform in enumerate(platform_names):
        ax.annotate(
            platform,
            (competitor_scores[i], our_scores[i]),
            xytext=(10, 5),
            textcoords="offset points",
            fontsize=10,
            bbox=dict(boxstyle="round,pad=0.5", facecolor="yellow", alpha=0.3),
        )

    # Add ideal correlation line (y=x)
    min_score = min(min(competitor_scores), min(our_scores))
    max_score = max(max(competitor_scores), max(our_scores))
    ax.plot(
        [min_score, max_score],
        [min_score, max_score],
        "r--",
        linewidth=2,
        alpha=0.5,
        label="Perfect Correlation",
    )

    # Styling
    ax.set_xlabel("Benchmark Platform Score", fontsize=14, fontweight="bold")
    ax.set_ylabel("Our Score", fontsize=14, fontweight="bold")
    ax.set_title("Score Correlation Analysis", fontsize=16, fontweight="bold", pad=20)
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=12)

    # Calculate and display correlation
    if len(competitor_scores) >= 2:
        from scipy.stats import pearsonr

        try:
            corr, p_value = pearsonr(competitor_scores, our_scores)
            ax.text(
                0.05,
                0.95,
                f"Pearson r = {corr:.3f}\np-value = {p_value:.4f}",
                transform=ax.transAxes,
                fontsize=12,
                verticalalignment="top",
                bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.5),
            )
        except:
            pass

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches="tight")
    print(f"✅ Chart saved: {output_file}")

    return output_file


def create_grade_distribution_chart(
    benchmark_data: Dict, output_file: str = "grade_distribution.png"
):
    """
    Create pie chart showing grade distribution across platforms

    Args:
        benchmark_data: Benchmark comparison data
        output_file: Output filename
    """
    benchmarks = benchmark_data.get("benchmarks", {})
    summary = benchmark_data.get("summary", {})

    grade_dist = summary.get("grade_distribution", {})

    if not grade_dist:
        print("⚠️  No grade data available for distribution chart")
        return None

    # Prepare data
    grades = list(grade_dist.keys())
    counts = list(grade_dist.values())

    # Color mapping
    grade_colors = {
        "A+": "#4CAF50",
        "A": "#8BC34A",
        "A-": "#CDDC39",
        "B": "#FFC107",
        "C": "#FF9800",
        "D": "#FF5722",
        "F": "#F44336",
    }
    colors = [grade_colors.get(g, "#9E9E9E") for g in grades]

    # Create figure
    fig, ax = plt.subplots(figsize=(10, 8))

    wedges, texts, autotexts = ax.pie(
        counts,
        labels=grades,
        colors=colors,
        autopct="%1.1f%%",
        startangle=90,
        textprops={"fontsize": 14, "fontweight": "bold"},
    )

    # Make percentage text more visible
    for autotext in autotexts:
        autotext.set_color("white")
        autotext.set_fontweight("bold")
        autotext.set_fontsize(12)

    ax.set_title(
        "Security Grade Distribution Across Platforms",
        fontsize=16,
        fontweight="bold",
        pad=20,
    )

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches="tight")
