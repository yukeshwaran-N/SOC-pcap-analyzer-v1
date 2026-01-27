# SOC PCAP Analyzer

A SOC-style network traffic analysis tool that processes PCAP files to identify suspicious activity and assist analysts during incident investigation and threat hunting.

---

## Overview

In Security Operations Centers (SOCs), PCAP files are frequently analyzed during incident response, malware investigations, and post-incident reviews.  
This process is often manual, time-consuming, and heavily dependent on analyst experience.

The SOC PCAP Analyzer is designed as an **analyst-assist tool** that automates the initial analysis of PCAP files, highlights suspicious network behaviors, and produces structured reports to support investigation and decision-making.

This project focuses on **defensive security**, emphasizing explainable detections over black-box analysis.

---

## Project Goals

- Automate initial PCAP traffic analysis
- Identify suspicious behaviors using behavioral and rule-based logic
- Reduce analyst effort during triage and investigation
- Present findings in a clear, SOC-friendly format
- Map detections to the MITRE ATT&CK framework for better contextual understanding

---

## Planned Capabilities

- PCAP parsing and traffic summarization
- Detection of suspicious behaviors, including:
  - Port scanning
  - Brute-force authentication attempts
  - Beaconing-like traffic patterns
  - Unusual data transfer behavior
- Configurable detection thresholds and rules
- Mapping of findings to MITRE ATT&CK techniques
- Generation of structured reports in:
  - Markdown
  - JSON (for future SIEM or automation integration)

---

## Project Status

🚧 **Work in Progress**

This project is under active development.

Current focus areas:
- Building a reliable PCAP parsing pipeline
- Establishing consistent traffic baselining
- Implementing initial detection logic with minimal false positives

Features and structure may evolve as the project matures.

---

## Use Cases

- SOC analyst PCAP triage
- Incident response investigations
- Security learning and training
- Detection logic experimentation
- Blue-team skill development

---

## Tech Stack

- **Language:** Python 3
- **Packet Analysis:** tshark (Wireshark CLI)
- **Configuration:** YAML
- **Frameworks & Standards:** MITRE ATT&CK
- **Operating System:** Linux (recommended)

---

## Repository Structure (Planned)

```text
soc-pcap-analyzer/
├── main.py                 # CLI entry point
├── src/
│   ├── pcap_parser.py      # PCAP parsing logic
│   ├── analyzers/          # Traffic and detection modules
│   ├── reporting/          # Report generation
│   └── utils/              # Helper utilities
├── rules/                  # Detection rules (YAML)
├── tests/                  # Unit tests
├── output/                 # Generated reports
├── config.yaml             # Configuration file
└── README.md
```

##  Disclaimer

This tool is intended for defensive security research and educational purposes only.

It is not a replacement for enterprise-grade SIEM, IDS, or EDR solutions.
All detections should be validated by a human analyst before making security decisions.

---

## Future Improvements

Enhanced behavioral baselining

Reduction of false positives through context awareness

Timeline-based visualization of network events

Integration with external threat intelligence sources

Export formats compatible with SOC workflows

---

## Contributing

Contributions, ideas, and suggestions are welcome.
Feel free to open issues or submit pull requests as the project evolves.

---

## License

MIT License
