# SOC PCAP Analyzer

An automated SOC analyst tool for processing PCAP files and generating professional security incident reports with optional SOC automation via n8n.

# n8n SOC Automation Workflow
![n8n Workflow](/media/Workflow.png)


## Features

- **PCAP Analysis**: Parse network captures using `tshark` with stream processing for large files
- **Attack Detection**: Identify port scans, brute-force attacks, C2 beaconing, data exfiltration, SQL injection, and more
- **Threat Intelligence**: Check indicators against local IOC databases and external APIs (VirusTotal, AbuseIPDB)
- **MITRE ATT&CK Mapping**: Map findings to MITRE ATT&CK techniques and tactics
- **SOC Automation (n8n)**: Send analysis results to n8n via webhook for automated workflows
- **Slack Alerts**: Automatically notify SOC teams for malicious PCAP detections
- **Jira Incident Creation**: Automatically create Jira incident tickets for detected threats
- **Professional Reports**: Generate reports in PDF, Markdown, or JSON format

# Installation

### Prerequisites

- Python 3.10+
- `tshark` (part of Wireshark)
- Kali Linux (recommended) or any Linux distribution / macOS

### Setup

```bash
# Navigate to the project directory
cd SOC-pcap-analyzer-v1

# Install Python dependencies
pip3 install -r requirements.txt

# Verify tshark is installed
tshark --version
```

## Usage

### Basic Analysis

```bash
# Analyze a PCAP file (outputs Markdown report)
python main.py analyze capture.pcap

# Generate PDF report
python main.py analyze capture.pcap --format pdf --output report.pdf

# Quick scan mode (faster, skips deep analysis)
python main.py analyze capture.pcap --quick

# Verbose output
python main.py analyze capture.pcap -v
```

### Get PCAP Info

```bash
python main.py info capture.pcap
```

### Command Line Options

```
usage: main.py analyze [-h] [-o OUTPUT] [-f {pdf,markdown,md,json}]
                       [-c CONFIG] [-v] [--quick] [--no-api] pcap_file

positional arguments:
  pcap_file             Path to PCAP file to analyze

optional arguments:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   Output file path
  -f, --format          Output format: pdf, markdown, json (default: markdown)
  -c, --config CONFIG   Configuration file path (default: config.yaml)
  -v, --verbose         Enable verbose output
  --quick               Quick scan mode (skip deep analysis)
  --no-api              Disable external API lookups
  --send-n8n            Send analysis results to n8n webhook
```

# Configuration
Edit config.yaml to customize behavior:

```yaml
analysis:
  max_packets: 0          # 0 = unlimited
  timeout_seconds: 300
  chunk_size: 10000

detection:
  port_scan_threshold: 20
  brute_force_threshold: 5
  beacon_interval_tolerance: 0.1

reporting:
  default_format: pdf
  include_raw_packets: false

threat_intel:
  virustotal:
    enabled: true
    api_key: "YOUR_API_KEY"
  abuseipdb:
    enabled: true
    api_key: "YOUR_API_KEY"
```

## Detection Capabilities

| Attack Type | Detection Method | MITRE ATT&CK |
|-------------|------------------|--------------|
| Port Scan | Multiple ports from single IP | T1046 |
| Brute Force | Repeated auth attempts | T1110 |
| C2 Beaconing | Regular interval connections | T1071 |
| Data Exfiltration | Large outbound transfers | T1048 |
| DNS Tunneling | Long DNS queries | T1071.004 |
| SQL Injection | Malicious patterns in HTTP | T1190 |
| Command Injection | Shell command patterns | T1059 |
| ARP Spoofing | Excessive ARP traffic | T1557.002 |
| DoS/DDoS | High traffic volume | T1498 |

## Report Sections

Generated reports include:

1. **Executive Summary** - High-level risk assessment
2. **Network Statistics** - Packet counts, duration, unique IPs
3. **Findings by Severity** - Critical, High, Medium, Low
4. **IOCs** - Suspicious IPs, domains, ports
5. **MITRE ATT&CK Coverage** - Mapped techniques
6. **Timeline** - Chronological events
7. **Recommendations** - Prioritized remediation steps

## Extending the Tool

### Adding Custom Detection Rules

Edit `rules/attack_signatures.yaml`:

```yaml
my_custom_rule:
  description: "Detect custom attack pattern"
  enabled: true
  patterns:
    - "pattern1"
    - "pattern2"
  severity: high
  mitre_technique: T1234
```

### Adding IOCs

Edit `rules/ioc_lists.yaml`:

```yaml
malicious_ips:
  - ip: "1.2.3.4"
    category: "malware_c2"
    severity: "critical"
```

## API Keys Setup

For threat intelligence lookups:

1. **VirusTotal**: Get free API key from https://www.virustotal.com/
2. **AbuseIPDB**: Get free API key from https://www.abuseipdb.com/

Add keys to `config.yaml` or use environment variables.

## Example Output

```
============================================================
  SOC PCAP Analyzer - Security Incident Analysis
============================================================

[*] Parsing PCAP file: capture.pcap
    Parsed 15432 packets, 234 connections
[*] Running traffic analysis...
[*] Running anomaly detection...
[*] Running attack detection...
[*] Checking IOCs...
[*] Generating report...

============================================================
  Analysis Complete
============================================================

  Risk Level: HIGH
  Total Findings: 10
    - Critical: 2
    - High: 2
    - Medium: 3
    - Low: 2

  Report saved to: output/report.md
  Analysis duration: 3.23 seconds
```

## SOC Automation (n8n + Slack + Jira)

SOC PCAP Analyzer supports full SOC-style automation using n8n, enabling real-time alerting and automatic incident ticket creation after PCAP analysis.

# n8n workflow
![n8n Workflow](/media/n8n.png)

## Included n8n Workflow

This repository includes a ready-to-use n8n workflow file:

`n8n.json`

You can import this file directly into n8n to enable automation.

# Automation Flow
PCAP Analysis → n8n Webhook → Severity Check → Slack Alert + Jira Ticket

Alerts and tickets are triggered when:

- Critical findings > 0
- High findings > 0
- Medium findings > 0
- Low-only findings are ignored.

# n8n Setup

1. Open n8n

2. Click Import workflow

3. Paste contents of n8n.json

4. Save the workflow

# Configure credentials:

- Slack Incoming Webhook
- Jira Cloud API credentials

## Webhook Endpoint

The workflow listens on the following endpoint:

`POST /webhook-test/pcap-test`

Example URL:

`http://localhost:5678/webhook-test/pcap-test`


## Running with Automation Enabled

Run analysis and send results to n8n:

``` bash
python main.py analyze capture.pcap --send-n8n
```

##Successful execution:
```
[*] Sending results to n8n webhook...
[+] Results successfully delivered to n8n
```
## Automation Output

# Slack setup
- Slack: SOC alert with PCAP path, risk level, and findings summary


![n8n Workflow](/media/Slack.png)

# Jira setup
- Jira: Automatically created incident ticket for analyst investigation

![n8n Workflow](/media/Jira.png)

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![SOC](https://img.shields.io/badge/SOC-Automation-red)
![n8n](https://img.shields.io/badge/n8n-Workflow-orange)
![Slack](https://img.shields.io/badge/Slack-Alerts-purple)
![Jira](https://img.shields.io/badge/Jira-Incident%20Tracking-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-black)
