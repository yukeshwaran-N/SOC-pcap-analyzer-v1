#!/usr/bin/env python3
"""
SOC PCAP Analyzer - Automated Security Incident Analysis Tool

A comprehensive tool for analyzing PCAP files and generating
professional security incident reports.
"""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from src.analyzers import AttackDetector, AnomalyDetector, TrafficAnalyzer
from src.analyzers.base_analyzer import AnalysisResult
from src.pcap_parser import PCAPParser, ParsedPCAP
from src.reporting import ReportGenerator
from src.reporting.exporters import get_exporter
from src.threat_intel import IOCChecker, MitreMapper
from src.threat_intel.api_clients import (
    AbuseIPDBClient,
    ThreatIntelAggregator,
    VirusTotalClient,
)
from src.utils import load_config, setup_logger
from src.utils.n8n_client import send_to_n8n


# ---------------- ARGUMENT PARSING ---------------- #

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="SOC PCAP Analyzer - Automated Security Incident Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze capture.pcap
  %(prog)s analyze capture.pcap --format pdf --output report.pdf
  %(prog)s analyze capture.pcap --quick --format markdown
  %(prog)s analyze capture.pcap -v --config custom_config.yaml
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze a PCAP file and generate a report"
    )
    analyze_parser.add_argument("pcap_file", help="Path to PCAP file to analyze")
    analyze_parser.add_argument(
        "-o", "--output", help="Output file path (default: output/report.<format>)"
    )
    analyze_parser.add_argument(
        "-f",
        "--format",
        choices=["pdf", "markdown", "md", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    analyze_parser.add_argument(
        "-c", "--config", default="config.yaml", help="Configuration file path"
    )
    analyze_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    analyze_parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan mode (skip some deep analysis)",
    )
    analyze_parser.add_argument(
        "--no-api",
        action="store_true",
        help="Disable external API lookups (VirusTotal, AbuseIPDB)",
    )

    # 🔥 ADDITIVE FLAG (NEW)
    analyze_parser.add_argument(
        "--send-n8n",
        action="store_true",
        help="Send analysis results to n8n webhook after completion",
    )

    # Info command
    info_parser = subparsers.add_parser("info", help="Get basic info about a PCAP file")
    info_parser.add_argument("pcap_file", help="Path to PCAP file")

    # Version
    parser.add_argument("--version", action="version", version="SOC PCAP Analyzer 1.0.0")

    return parser.parse_args()


# ---------------- ANALYSIS PIPELINE ---------------- #

def run_analysis(
    pcap_path: str,
    config: dict,
    quick_mode: bool = False,
    use_api: bool = True,
    verbose: bool = False,
) -> tuple[ParsedPCAP, list[AnalysisResult], float]:
    """
    Run full analysis on a PCAP file.
    """
    start_time = time.time()

    parser = PCAPParser(config)

    print(f"[*] Parsing PCAP file: {pcap_path}")
    pcap_data = parser.parse(pcap_path)
    print(f"    Parsed {pcap_data.packet_count} packets, {len(pcap_data.connections)} connections")

    analyzers = []

    print("[*] Running traffic analysis...")
    analyzers.append(TrafficAnalyzer(config))

    print("[*] Running anomaly detection...")
    analyzers.append(AnomalyDetector(config))

    print("[*] Running attack detection...")
    rules_path = Path("rules/attack_signatures.yaml")
    analyzers.append(
        AttackDetector(config, rules_path=str(rules_path) if rules_path.exists() else None)
    )

    results: list[AnalysisResult] = []
    for analyzer in analyzers:
        result = analyzer.analyze(pcap_data)
        results.append(result)
        if verbose:
            print(f"    {analyzer.name}: {result.finding_count} findings")

    if not quick_mode:
        print("[*] Checking IOCs...")
        threat_intel = None

        if use_api:
            ti_config = config.get("threat_intel", {})
            vt_key = os.getenv("VIRUSTOTAL_API_KEY") or ti_config.get("virustotal", {}).get("api_key")
            ab_key = os.getenv("ABUSEIPDB_API_KEY") or ti_config.get("abuseipdb", {}).get("api_key")

            vt_client = (
                VirusTotalClient(vt_key, rate_limit=ti_config.get("virustotal", {}).get("rate_limit", 4))
                if vt_key else None
            )
            ab_client = (
                AbuseIPDBClient(ab_key, rate_limit=ti_config.get("abuseipdb", {}).get("rate_limit", 1000))
                if ab_key else None
            )

            if vt_client or ab_client:
                threat_intel = ThreatIntelAggregator(vt_client, ab_client)

        ioc_checker = IOCChecker(
            ioc_file="rules/ioc_lists.yaml" if Path("rules/ioc_lists.yaml").exists() else None,
            threat_intel=threat_intel,
            config=config,
        )

        external_ips = [
            ip for ip in list(pcap_data.unique_ips)[:100]
            if not ip.startswith(("10.", "172.16.", "192.168.", "127."))
        ]

        if external_ips and verbose:
            print(f"    Checking {len(external_ips)} external IPs...")

        ioc_matches = ioc_checker.check_all_ips(external_ips, use_api=use_api, limit=20)

        if ioc_matches:
            from src.analyzers.base_analyzer import Finding, Severity

            ioc_findings = [
                Finding(
                    title=f"Malicious {m.indicator_type.upper()} Detected",
                    description=f"Indicator {m.indicator} matched: {m.description}",
                    severity=Severity.HIGH if m.severity == "high" else Severity.CRITICAL,
                    category="IOC Match",
                    source_ip=m.indicator if m.indicator_type == "ip" else None,
                    evidence=[f"Source: {m.source}", f"Category: {m.category}"],
                    recommendations=[
                        f"Block {m.indicator} at the firewall",
                        "Investigate affected systems",
                    ],
                )
                for m in ioc_matches
            ]

            results.append(
                AnalysisResult(
                    analyzer_name="IOCChecker",
                    findings=ioc_findings,
                    iocs={"ips": [m.indicator for m in ioc_matches if m.indicator_type == "ip"]},
                )
            )

    duration = time.time() - start_time
    return pcap_data, results, duration


# ---------------- WEBHOOK PAYLOAD ---------------- #

def report_to_webhook_payload(report_data, pcap_path: str) -> dict:
    return {
        "pcap_path": pcap_path,
        "report_id": report_data.report_id,
        "risk_level": report_data._get_risk_level(),
        "summary": {
            "total_findings": len(report_data.findings),
            "critical": report_data.critical_count,
            "high": report_data.high_count,
            "medium": report_data.medium_count,
            "low": report_data.low_count,
        },
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category,
                "description": f.description,
                "source_ip": f.source_ip,
                "destination_ip": f.destination_ip,
            }
            for f in report_data.findings
        ],
    }


# ---------------- MAIN ---------------- #

def main() -> int:
    args = parse_args()

    if not args.command:
        print("Error: No command specified. Use --help for usage information.")
        return 1

    config_path = getattr(args, "config", "config.yaml")
    config = load_config(config_path) if Path(config_path).exists() else {}

    log_config = config.get("logging", {})
    setup_logger(
        level=log_config.get("level", "INFO") if not getattr(args, "verbose", False) else "DEBUG",
        log_file=log_config.get("file"),
    )

    if args.command == "info":
        from src.pcap_parser import get_pcap_info
        info = get_pcap_info(args.pcap_file)
        print(f"\nPCAP File Information:")
        print(f"  Path: {info['file_path']}")
        print(f"  Size: {info['file_size']:,} bytes")
        print(f"  Packets: {info['packet_count']:,}")
        return 0

    if args.command == "analyze":
        pcap_path = Path(args.pcap_file).expanduser().resolve()
        if not pcap_path.exists():
            print(f"Error: PCAP file not found: {pcap_path}")
            return 1

        print("\n" + "=" * 60)
        print("  SOC PCAP Analyzer - Security Incident Analysis")
        print("=" * 60 + "\n")

        pcap_data, results, duration = run_analysis(
            str(pcap_path),
            config,
            quick_mode=args.quick,
            use_api=not args.no_api,
            verbose=args.verbose,
        )

        print("[*] Generating report...")
        report_gen = ReportGenerator(config)
        report_data = report_gen.generate(pcap_data, results, duration)

        output_format = args.format.lower()
        if output_format == "md":
            output_format = "markdown"

        if args.output:
            output_path = args.output
        else:
            ext = "md" if output_format == "markdown" else output_format
            output_path = f"output/report_{report_data.report_id}.{ext}"

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        template_dir = Path("src/reporting/templates")
        exporter = get_exporter(
            output_format,
            template_dir=str(template_dir) if template_dir.exists() else None,
        )
        exported_path = exporter.export(report_data, output_path)

        print("\n" + "=" * 60)
        print("  Analysis Complete")
        print("=" * 60)
        print(f"\n  Risk Level: {report_data._get_risk_level()}")
        print(f"  Total Findings: {len(report_data.findings)}")
        print(f"    - Critical: {report_data.critical_count}")
        print(f"    - High: {report_data.high_count}")
        print(f"    - Medium: {report_data.medium_count}")
        print(f"    - Low: {report_data.low_count}")
        print(f"\n  Report saved to: {exported_path}")
        print(f"  Analysis duration: {duration:.2f} seconds\n")

        # 🔥 SEND TO N8N (ADDITIVE ONLY)
        if args.send_n8n:
            payload = report_to_webhook_payload(report_data, str(pcap_path))
            webhook_url = "http://localhost:5678/webhook-test/pcap-test"


            print("[*] Sending results to n8n webhook...")
            if send_to_n8n(payload, webhook_url):
                print("[+] Results successfully delivered to n8n")
            else:
                print("[!] Failed to deliver results to n8n")

        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
