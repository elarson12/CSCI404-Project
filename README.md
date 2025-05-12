# CSCI404-Project
Port Scanner with Python for CSCI 404 group project. 

# Cyberattack Threat Characterization System

A comprehensive system for identifying, analyzing, and characterizing cyber threats based on network scan data and threat intelligence.

## Overview

This project implements a Cyberattack Threat Characterization System with four main components:

1. **Threat Data Input Mechanism**: Imports threat data from public repositories
2. **System Scan Data Input Mechanism**: Collects network and system data
3. **Threat Identification Mechanism**: Matches threats with scan data
4. **Threat Characterization Mechanism**: Analyzes potential impact of identified threats

## Features

- Sophisticated port scanner with service detection
- Integration with multiple threat intelligence sources
- Advanced threat identification using multi-factor matching
- Risk assessment with confidence scoring
- Impact analysis and prioritized remediation recommendations
- Detailed report generation in multiple formats

## Requirements

- Python 3.8 or higher
- Required packages (see requirements.txt)

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/cyber-threat-characterization.git
cd cyber-threat-characterization
```

2. Install required packages:
```
pip install -r requirements.txt
```

3. Install optional dependencies for enhanced functionality:
```
pip install python-nmap
```

## Usage

### Basic Usage

Run a basic scan against a target:

```
python src/main.py --target 192.168.1.100
```

### Advanced Options

```
python src/main.py --target 192.168.1.100 --ports 20-25,80,443 --timeout 5 --update-threats --output report.md
```

Command line arguments:
- `--target`, `-t`: Target host to scan (IP address or hostname)
- `--ports`, `-p`: Port range to scan (e.g., '1-1024' or '22,80,443')
- `--timeout`: Timeout for port scanning in seconds
- `--update-threats`: Update threat database before scanning
- `--output`, `-o`: Output file for report
- `--log-level`: Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

## Project Structure

```
CSCI404-Project/
│
├── src/                           # Source code directory
│   ├── threat_data/               # Threat data input mechanism
│   ├── system_scan/               # System scan data input mechanism
│   ├── threat_identification/     # Threat identification mechanism
│   ├── threat_characterization/   # Threat characterization mechanism
│   └── main.py                    # Main application entry point
│
├── data/                          # Data directory
│   ├── threat_feeds/              # Downloaded threat data
│   ├── scan_results/              # System scan results storage
│   └── reports/                   # Generated reports
│
├── tests/                         # Test directory
│
├── logs/                          # Log files
│
├── config/                        # Configuration files
│
├── docs/                          # Documentation
│
├── requirements.txt               # Python dependencies
├── setup.py                       # Installation script
└── README.md                      # Project overview
```

## Configuration

Configuration files are located in the `config/` directory:

- `settings.json`: General application settings
- `threat_sources.json`: Threat data sources configuration

## Report Formats

The tool generates reports in the following formats:

- **Markdown**: Human-readable format with rich formatting
- **JSON**: Machine-readable format for integration with other tools
- **Text**: Plain text format for compatibility

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and defensive purposes only. Always obtain proper authorization before scanning any systems or networks you do not own.