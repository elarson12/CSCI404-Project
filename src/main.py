#!/usr/bin/env python3

import os
import sys
import json
import argparse
import logging
from datetime import datetime
import traceback

# Add src directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import components
from threat_data.data_importer import ThreatDataImporter
from system_scan.port_scanner import PortScanner
from system_scan.service_detector import ServiceDetector
from system_scan.system_info import SystemInfo
from threat_identification.matcher import ThreatMatcher
from threat_identification.risk_assessor import RiskAssessor
from threat_characterization.impact_analyzer import ImpactAnalyzer
from threat_characterization.report_generator import ReportGenerator

def setup_logging(log_level="INFO", log_file="logs/app.log"):
    """Set up logging configuration"""
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("threat_analyzer")

def load_config():
    """Load configuration files"""
    try:
        with open("config/settings.json", "r") as f:
            settings = json.load(f)
        
        with open("config/threat_sources.json", "r") as f:
            threat_sources = json.load(f)
        
        return settings, threat_sources
    except FileNotFoundError as e:
        logging.error(f"Configuration file not found: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in configuration file: {e}")
        sys.exit(1)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Cyberattack Threat Characterization System")
    
    parser.add_argument("--target", "-t", type=str, required=True,
                        help="Target host to scan (IP address or hostname)")
    
    parser.add_argument("--ports", "-p", type=str, default="1-1024",
                        help="Port range to scan (e.g., '1-1024' or '22,80,443')")
    
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="Timeout for port scanning in seconds")
    
    parser.add_argument("--update-threats", action="store_true",
                        help="Update threat database before scanning")
    
    parser.add_argument("--output", "-o", type=str,
                        help="Output file for report (default: auto-generated)")
    
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        default="INFO", help="Set logging level")
    
    return parser.parse_args()

def parse_port_range(port_str):
    """Parse port range string into a list of ports"""
    ports = []
    
    if "-" in port_str:
        start, end = map(int, port_str.split("-"))
        ports = list(range(start, end + 1))
    else:
        ports = [int(p) for p in port_str.split(",")]
    
    return ports

def main():
    """Main function"""
    args = parse_arguments()
    
    # Load configurations
    settings, threat_sources = load_config()
    
    # Setup logging
    log_level = args.log_level or settings["app"]["log_level"]
    log_file = settings["app"]["log_file"]
    logger = setup_logging(log_level, log_file)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_id = f"{args.target.replace('.', '_')}_{timestamp}"
    
    try:
        logger.info(f"Starting threat analysis for {args.target} with scan ID: {scan_id}")
        
        # Import threat data
        logger.info("Importing threat data...")
        threat_importer = ThreatDataImporter(threat_sources)
        if args.update_threats:
            threat_importer.update_threat_data()
        threat_data = threat_importer.load_threat_data()
        logger.info(f"Loaded {len(threat_data)} threat records")
        
        # Get system information
        logger.info("Collecting system information...")
        system_info = SystemInfo()
        sys_info_data = system_info.get_system_info()
        
        # Scan ports
        logger.info(f"Scanning ports for {args.target}...")
        ports = parse_port_range(args.ports)
        scanner = PortScanner(timeout=args.timeout)
        scan_results = scanner.scan(args.target, ports)
        logger.info(f"Found {len(scan_results['open_ports'])} open ports")
        
        # Detect services
        logger.info("Detecting services on open ports...")
        service_detector = ServiceDetector()
        service_info = service_detector.detect_services(args.target, scan_results["open_ports"])
        scan_results.update({"services": service_info})
        
        # Save scan results
        scan_file = f"data/scan_results/{scan_id}_scan.json"
        os.makedirs(os.path.dirname(scan_file), exist_ok=True)
        with open(scan_file, "w") as f:
            json.dump(scan_results, f, indent=2)
        logger.info(f"Saved scan results to {scan_file}")
        
        # Identify threats
        logger.info("Identifying potential threats...")
        matcher = ThreatMatcher(settings["threat_identification"]["confidence_threshold"])
        threats = matcher.match_threats(scan_results, threat_data)
        logger.info(f"Identified {len(threats)} potential threats")
        
        # Assess risks
        logger.info("Assessing risk levels...")
        risk_assessor = RiskAssessor()
        risk_assessment = risk_assessor.assess_risks(threats, scan_results)
        
        # Analyze impact
        logger.info("Analyzing potential impact...")
        impact_analyzer = ImpactAnalyzer(settings["threat_characterization"]["impact_factors"])
        impact_analysis = impact_analyzer.analyze_impact(risk_assessment, scan_results)
        
        # Generate report
        logger.info("Generating threat characterization report...")
        report_generator = ReportGenerator()
        report_file = args.output or f"data/reports/{scan_id}_report.md"
        os.makedirs(os.path.dirname(report_file), exist_ok=True)
        
        report_data = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "target": args.target,
            "system_info": sys_info_data,
            "scan_results": scan_results,
            "threats": threats,
            "risk_assessment": risk_assessment,
            "impact_analysis": impact_analysis
        }
        
        report_generator.generate_report(report_data, report_file)
        logger.info(f"Report generated and saved to {report_file}")
        
        # Display summary
        print("\n" + "=" * 60)
        print(f"Scan Summary for {args.target}")
        print("=" * 60)
        print(f"Scan ID: {scan_id}")
        print(f"Open Ports: {len(scan_results['open_ports'])}")
        print(f"Threats Identified: {len(threats)}")
        
        risk_counts = {level: 0 for level in settings["threat_characterization"]["risk_levels"]}
        for threat in risk_assessment:
            risk_counts[threat["risk_level"]] += 1
        
        print("\nRisk Assessment:")
        for level, count in risk_counts.items():
            print(f"  {level}: {count}")
        
        print(f"\nFull report saved to: {report_file}")
        print("=" * 60)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during threat analysis: {str(e)}")
        logger.debug(traceback.format_exc())
        print(f"Error: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())