# SIEM Log Parser (Python Security Tool)

A lightweight Python Security Information and Event Management (SIEM) log parser designed to inspect Linux authentication logs (`auth.log`), aggregate failed SSH login attempts per IP address, and flag potential brute-force attack patterns.

## Features
- **Regex Parsing:** Efficiently scans log files for SSH authentication failure patterns.
- **Configurable Alerting Threshold:** Customizable failure threshold to minimize false positives.
- **Terminal Reporting:** Formatted CLI table output highlighting high-risk IP addresses.
- **CSV Export Support:** Saves audit reports directly to `.csv` for further incident response analysis.

## Project Structure
```text
siem-log-parser/
│
├── siem_parse.py       # Main Python script
├── sample_auth.log     # Sample SSH authentication log file
├── report.csv          # Exported CSV report
└── README.md           # Documentation
## Sample Output
![Terminal Output](siem%20as.png)
