#!/usr/bin/env python3

import logging
import json
import os
from datetime import datetime
from tabulate import tabulate
import re

class ReportGenerator:
    """Class to generate threat characterization reports"""
    
    def __init__(self, format="markdown"):
        """Initialize ReportGenerator
        
        Args:
            format (str): Report format ("markdown", "json", or "text")
        """
        self.logger = logging.getLogger("threat_analyzer.report_generator")
        self.format = format
    
    def generate_report(self, report_data, output_file=None):
        """Generate threat characterization report
        
        Args:
            report_data (dict): Report data
            output_file (str): Output file path
        
        Returns:
            str: Report content
        """
        self.logger.info(f"Generating {self.format} report")
        
        if self.format == "markdown":
            report_content = self._generate_markdown_report(report_data)
        elif self.format == "json":
            report_content = self._generate_json_report(report_data)
        elif self.format == "text":
            report_content = self._generate_text_report(report_data)
        else:
            self.logger.warning(f"Unsupported format '{self.format}', defaulting to markdown")
            report_content = self._generate_markdown_report(report_data)
        
        # Save report to file if output_file is provided
        if output_file:
            try:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                
                with open(output_file, "w") as f:
                    f.write(report_content)
                
                self.logger.info(f"Report saved to {output_file}")
            except Exception as e:
                self.logger.error(f"Error saving report to {output_file}: {str(e)}")
        
        return report_content
    
    def _generate_markdown_report(self, report_data):
        """Generate markdown report
        
        Args:
            report_data (dict): Report data
        
        Returns:
            str: Markdown report
        """
        scan_id = report_data.get("scan_id", "unknown")
        timestamp = report_data.get("timestamp", datetime.now().isoformat())
        target = report_data.get("target", "unknown")
        scan_results = report_data.get("scan_results", {})
        threats = report_data.get("threats", [])
        risk_assessment = report_data.get("risk_assessment", [])
        impact_analysis = report_data.get("impact_analysis", [])
        
        # Convert timestamp to readable format
        try:
            dt = datetime.fromisoformat(timestamp)
            timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
        
        # Start building the report
        report = f"# Cyberattack Threat Characterization Report\n\n"
        
        # Summary section
        report += f"## Summary\n\n"
        report += f"- **Scan ID**: {scan_id}\n"
        report += f"- **Timestamp**: {timestamp}\n"
        report += f"- **Target**: {target}\n"
        report += f"- **Open Ports**: {len(scan_results.get('open_ports', []))}\n"
        report += f"- **Threats Identified**: {len(threats)}\n\n"
        
        # Calculate risk distribution
        risk_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for risk in risk_assessment:
            risk_level = risk.get("risk_level", "INFO")
            risk_distribution[risk_level] += 1
        
        # Add risk distribution
        report += "### Risk Distribution\n\n"
        report += "| Risk Level | Count |\n"
        report += "| ---------- | ----- |\n"
        for level, count in risk_distribution.items():
            report += f"| {level} | {count} |\n"
        
        report += "\n"
        
        # System Information
        report += f"## System Information\n\n"
        
        system_info = report_data.get("system_info", {})
        if system_info:
            report += f"### Scanner System\n\n"
            report += f"- **Hostname**: {system_info.get('hostname', 'unknown')}\n"
            
            os_info = system_info.get("os", {})
            report += f"- **Operating System**: {os_info.get('name', 'unknown')} {os_info.get('version', '')}\n"
            
            network_info = system_info.get("network", {})
            report += f"- **IP Address**: {network_info.get('default_ip', 'unknown')}\n\n"
        
        # Open Ports
        report += f"## Open Ports\n\n"
        
        open_ports = scan_results.get("open_ports", [])
        if open_ports:
            report += "| Port | State | Service | Version |\n"
            report += "| ---- | ----- | ------- | ------- |\n"
            
            for port_info in open_ports:
                port = port_info.get("port", "")
                state = port_info.get("state", "")
                service = port_info.get("service", "")
                version = port_info.get("version", "")
                
                report += f"| {port} | {state} | {service} | {version} |\n"
            
            report += "\n"
        else:
            report += "No open ports found.\n\n"
        
        # Threats
        report += f"## Identified Threats\n\n"
        
        if threats:
            # Sort threats by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_threats = sorted(threats, key=lambda x: severity_order.get(x.get("severity", "INFO"), 5))
            
            for i, threat in enumerate(sorted_threats):
                threat_id = threat.get("threat_id", "unknown")
                name = threat.get("name", "Unknown Threat")
                description = threat.get("description", "")
                severity = threat.get("severity", "INFO")
                confidence = threat.get("confidence", 0.0)
                
                # Add severity-based emoji
                severity_emoji = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢",
                    "INFO": "🔵"
                }.get(severity, "")
                
                report += f"### {severity_emoji} {name} ({threat_id})\n\n"
                report += f"**Severity**: {severity}\n"
                report += f"**Confidence**: {confidence:.2f}\n\n"
                
                if description:
                    report += f"**Description**:\n{description}\n\n"
                
                # Add matched ports
                matched_ports = threat.get("matched_ports", [])
                if matched_ports:
                    report += f"**Affected Ports**: {', '.join(map(str, matched_ports))}\n\n"
                
                # Add matched services
                matched_services = threat.get("matched_services", [])
                if matched_services:
                    service_names = []
                    for service in matched_services:
                        if isinstance(service, dict):
                            service_name = service.get("service", "")
                            service_version = service.get("version", "")
                            if service_name and service_version:
                                service_names.append(f"{service_name} {service_version}")
                            elif service_name:
                                service_names.append(service_name)
                    
                    if service_names:
                        report += f"**Affected Services**: {', '.join(service_names)}\n\n"
                
                # Add remediation if available
                if "remediation" in threat and threat["remediation"]:
                    report += f"**Remediation**:\n{threat['remediation']}\n\n"
        else:
            report += "No threats identified.\n\n"
        
        # Risk Assessment
        report += f"## Risk Assessment\n\n"
        
        if risk_assessment:
            # Sort by risk score (descending)
            sorted_risks = sorted(risk_assessment, key=lambda x: x.get("risk_score", 0.0), reverse=True)
            
            for i, risk in enumerate(sorted_risks):
                threat_id = risk.get("threat_id", "unknown")
                name = risk.get("name", "Unknown Threat")
                risk_level = risk.get("risk_level", "INFO")
                risk_score = risk.get("risk_score", 0.0)
                
                # Find matching impact analysis
                matching_impact = next(
                    (impact for impact in impact_analysis if impact.get("threat_id") == threat_id),
                    {}
                )
                
                impact_level = matching_impact.get("impact_level", "UNKNOWN")
                mitigation_priority = matching_impact.get("mitigation_priority", "UNKNOWN")
                
                # Add risk-based emoji
                risk_emoji = {
                    "CRITICAL": "⚠️",
                    "HIGH": "🚨",
                    "MEDIUM": "⚡",
                    "LOW": "✓",
                    "INFO": "ℹ️"
                }.get(risk_level, "")
                
                report += f"### {risk_emoji} {name} ({threat_id})\n\n"
                report += f"**Risk Level**: {risk_level}\n"
                report += f"**Risk Score**: {risk_score:.2f}\n"
                report += f"**Impact Level**: {impact_level}\n"
                report += f"**Mitigation Priority**: {mitigation_priority}\n\n"
                
                # Add risk factors
                risk_factors = risk.get("risk_factors", {})
                if risk_factors:
                    report += "**Risk Factors**:\n"
                    for factor, value in risk_factors.items():
                        factor_name = factor.replace("_", " ").title()
                        report += f"- {factor_name}: {value:.2f}\n"
                    report += "\n"
                
                # Add attack vectors
                attack_vectors = matching_impact.get("potential_attack_vectors", [])
                if attack_vectors:
                    report += "**Potential Attack Vectors**:\n"
                    for vector in attack_vectors:
                        report += f"- {vector}\n"
                    report += "\n"
                
                # Add recommended actions
                recommended_actions = matching_impact.get("recommended_actions", [])
                if recommended_actions:
                    report += "**Recommended Actions**:\n"
                    for action in recommended_actions:
                        report += f"- {action}\n"
                    report += "\n"
        else:
            report += "No risk assessment available.\n\n"
        
        # Footer
        report += "---\n"
        report += f"*Report generated on {timestamp} by Cyberattack Threat Characterization System*\n"
        
        return report
    
    def _generate_json_report(self, report_data):
        """Generate JSON report
        
        Args:
            report_data (dict): Report data
        
        Returns:
            str: JSON report
        """
        return json.dumps(report_data, indent=2)
    
    def _generate_text_report(self, report_data):
        """Generate plain text report
        
        Args:
            report_data (dict): Report data
        
        Returns:
            str: Plain text report
        """
        scan_id = report_data.get("scan_id", "unknown")
        timestamp = report_data.get("timestamp", datetime.now().isoformat())
        target = report_data.get("target", "unknown")
        scan_results = report_data.get("scan_results", {})
        threats = report_data.get("threats", [])
        risk_assessment = report_data.get("risk_assessment", [])
        impact_analysis = report_data.get("impact_analysis", [])
        
        # Convert timestamp to readable format
        try:
            dt = datetime.fromisoformat(timestamp)
            timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
        
        # Start building the report
        report = "====== Cyberattack Threat Characterization Report ======\n\n"
        
        # Summary section
        report += "=== Summary ===\n\n"
        report += f"Scan ID: {scan_id}\n"
        report += f"Timestamp: {timestamp}\n"
        report += f"Target: {target}\n"
        report += f"Open Ports: {len(scan_results.get('open_ports', []))}\n"
        report += f"Threats Identified: {len(threats)}\n\n"
        
        # Calculate risk distribution
        risk_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for risk in risk_assessment:
            risk_level = risk.get("risk_level", "INFO")
            risk_distribution[risk_level] += 1
        
        # Add risk distribution
        report += "Risk Distribution:\n"
        for level, count in risk_distribution.items():
            report += f"  {level}: {count}\n"
        
        report += "\n"
        
        # System Information
        report += "=== System Information ===\n\n"
        
        system_info = report_data.get("system_info", {})
        if system_info:
            report += "Scanner System:\n"
            report += f"  Hostname: {system_info.get('hostname', 'unknown')}\n"
            
            os_info = system_info.get("os", {})
            report += f"  Operating System: {os_info.get('name', 'unknown')} {os_info.get('version', '')}\n"
            
            network_info = system_info.get("network", {})
            report += f"  IP Address: {network_info.get('default_ip', 'unknown')}\n\n"
        
        # Open Ports
        report += "=== Open Ports ===\n\n"
        
        open_ports = scan_results.get("open_ports", [])
        if open_ports:
            # Create table
            table_data = []
            headers = ["Port", "State", "Service", "Version"]
            
            for port_info in open_ports:
                row = [
                    port_info.get("port", ""),
                    port_info.get("state", ""),
                    port_info.get("service", ""),
                    port_info.get("version", "")
                ]
                table_data.append(row)
            
            report += tabulate(table_data, headers=headers) + "\n\n"
        else:
            report += "No open ports found.\n\n"
        
        # Threats
        report += "=== Identified Threats ===\n\n"
        
        if threats:
            # Sort threats by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_threats = sorted(threats, key=lambda x: severity_order.get(x.get("severity", "INFO"), 5))
            
            for i, threat in enumerate(sorted_threats):
                threat_id = threat.get("threat_id", "unknown")
                name = threat.get("name", "Unknown Threat")
                description = threat.get("description", "")
                severity = threat.get("severity", "INFO")
                confidence = threat.get("confidence", 0.0)
                
                report += f"--- {name} ({threat_id}) ---\n"
                report += f"Severity: {severity}\n"
                report += f"Confidence: {confidence:.2f}\n\n"
                
                if description:
                    report += f"Description:\n{description}\n\n"
                
                # Add matched ports
                matched_ports = threat.get("matched_ports", [])
                if matched_ports:
                    report += f"Affected Ports: {', '.join(map(str, matched_ports))}\n\n"
                
                # Add matched services
                matched_services = threat.get("matched_services", [])
                if matched_services:
                    service_names = []
                    for service in matched_services:
                        if isinstance(service, dict):
                            service_name = service.get("service", "")
                            service_version = service.get("version", "")
                            if service_name and service_version:
                                service_names.append(f"{service_name} {service_version}")
                            elif service_name:
                                service_names.append(service_name)
                    
                    if service_names:
                        report += f"Affected Services: {', '.join(service_names)}\n\n"
                
                # Add remediation if available
                if "remediation" in threat and threat["remediation"]:
                    report += f"Remediation:\n{threat['remediation']}\n\n"
        else:
            report += "No threats identified.\n\n"
        
        # Risk Assessment
        report += "=== Risk Assessment ===\n\n"
        
        if risk_assessment:
            # Sort by risk score (descending)
            sorted_risks = sorted(risk_assessment, key=lambda x: x.get("risk_score", 0.0), reverse=True)
            
            for i, risk in enumerate(sorted_risks):
                threat_id = risk.get("threat_id", "unknown")
                name = risk.get("name", "Unknown Threat")
                risk_level = risk.get("risk_level", "INFO")
                risk_score = risk.get("risk_score", 0.0)
                
                # Find matching impact analysis
                matching_impact = next(
                    (impact for impact in impact_analysis if impact.get("threat_id") == threat_id),
                    {}
                )
                
                impact_level = matching_impact.get("impact_level", "UNKNOWN")
                mitigation_priority = matching_impact.get("mitigation_priority", "UNKNOWN")
                
                report += f"--- {name} ({threat_id}) ---\n"
                report += f"Risk Level: {risk_level}\n"
                report += f"Risk Score: {risk_score:.2f}\n"
                report += f"Impact Level: {impact_level}\n"
                report += f"Mitigation Priority: {mitigation_priority}\n\n"
                
                # Add risk factors
                risk_factors = risk.get("risk_factors", {})
                if risk_factors:
                    report += "Risk Factors:\n"
                    for factor, value in risk_factors.items():
                        factor_name = factor.replace("_", " ").title()
                        report += f"  {factor_name}: {value:.2f}\n"
                    report += "\n"
                
                # Add attack vectors
                attack_vectors = matching_impact.get("potential_attack_vectors", [])
                if attack_vectors:
                    report += "Potential Attack Vectors:\n"
                    for vector in attack_vectors:
                        report += f"  - {vector}\n"
                    report += "\n"
                
                # Add recommended actions
                recommended_actions = matching_impact.get("recommended_actions", [])
                if recommended_actions:
                    report += "Recommended Actions:\n"
                    for action in recommended_actions:
                        report += f"  - {action}\n"
                    report += "\n"
        else:
            report += "No risk assessment available.\n\n"
        
        # Footer
        report += "-----\n"
        report += f"Report generated on {timestamp} by Cyberattack Threat Characterization System\n"
        
        return report