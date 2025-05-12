#!/usr/bin/env python3

import logging
from datetime import datetime

class RiskAssessor:
    """Class to assess risks of identified threats"""
    
    # Risk assessment metrics
    SEVERITY_SCORES = {
        "CRITICAL": 1.0,
        "HIGH": 0.8,
        "MEDIUM": 0.5,
        "LOW": 0.3,
        "INFO": 0.1
    }
    
    # Risk level thresholds
    RISK_THRESHOLDS = {
        "CRITICAL": 0.8,
        "HIGH": 0.6,
        "MEDIUM": 0.4,
        "LOW": 0.2
    }
    
    def __init__(self):
        """Initialize RiskAssessor"""
        self.logger = logging.getLogger("threat_analyzer.risk_assessor")
    
    def assess_risks(self, identified_threats, scan_results):
        """Assess risks of identified threats
        
        Args:
            identified_threats (list): List of identified threats
            scan_results (dict): Scan results from the port scanner
        
        Returns:
            list: Risk assessment results
        """
        self.logger.info(f"Assessing risks for {len(identified_threats)} identified threats")
        
        risk_assessments = []
        
        for threat in identified_threats:
            risk_assessment = self._assess_threat_risk(threat, scan_results)
            risk_assessments.append(risk_assessment)
            
            self.logger.info(f"Assessed risk for threat {threat['threat_id']} as {risk_assessment['risk_level']}")
        
        # Sort by risk score (descending)
        risk_assessments.sort(key=lambda x: x["risk_score"], reverse=True)
        
        return risk_assessments
    
    def _assess_threat_risk(self, threat, scan_results):
        """Assess risk of a specific threat
        
        Args:
            threat (dict): Identified threat
            scan_results (dict): Scan results from the port scanner
        
        Returns:
            dict: Risk assessment result
        """
        # Start with base risk score from threat severity
        severity = threat.get("severity", "MEDIUM").upper()
        base_score = self.SEVERITY_SCORES.get(severity, 0.5)
        
        # Adjust based on confidence score
        confidence_score = threat.get("confidence", 0.0)
        
        # Adjust based on port exposure
        port_exposure_score = self._calculate_port_exposure(threat, scan_results)
        
        # Calculate exploitability based on service versions
        exploitability_score = self._calculate_exploitability(threat)
        
        # Calculate exposure score based on network context
        exposure_score = self._calculate_exposure(threat, scan_results)
        
        # Calculate final risk score
        risk_score = (
            base_score * 0.3 +
            confidence_score * 0.2 +
            port_exposure_score * 0.2 +
            exploitability_score * 0.2 +
            exposure_score * 0.1
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(risk_score)
        
        return {
            "threat_id": threat["threat_id"],
            "name": threat["name"],
            "severity": severity,
            "confidence": confidence_score,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": {
                "base_severity": base_score,
                "confidence": confidence_score,
                "port_exposure": port_exposure_score,
                "exploitability": exploitability_score,
                "network_exposure": exposure_score
            },
            "timestamp": datetime.now().isoformat()
        }
    
    def _calculate_port_exposure(self, threat, scan_results):
        """Calculate port exposure score
        
        Args:
            threat (dict): Identified threat
            scan_results (dict): Scan results from the port scanner
        
        Returns:
            float: Port exposure score
        """
        matched_ports = threat.get("matched_ports", [])
        
        if not matched_ports:
            return 0.0
        
        # Calculate exposure based on port numbers
        # Lower port numbers are often more critical services
        port_scores = []
        
        for port in matched_ports:
            # Ports under 1024 are considered more critical
            if port < 1024:
                port_scores.append(0.8)
            # Ports from 1024 to 10000 are moderate
            elif port < 10000:
                port_scores.append(0.5)
            # Higher ports are less critical
            else:
                port_scores.append(0.3)
        
        # Average of port scores
        return sum(port_scores) / len(port_scores) if port_scores else 0.0
    
    def _calculate_exploitability(self, threat):
        """Calculate exploitability score
        
        Args:
            threat (dict): Identified threat
        
        Returns:
            float: Exploitability score
        """
        # Extract matched services
        matched_services = threat.get("matched_services", [])
        
        if not matched_services:
            return 0.5  # Default exploitability if no service matches
        
        # Assign exploitability score to each matched service
        service_scores = []
        
        for service_match in matched_services:
            service = service_match.get("service", "").lower()
            
            # Assign base score based on service type
            if service in ["http", "https", "ftp", "telnet", "ssh"]:
                # Public-facing services are more exploitable
                base_score = 0.8
            elif service in ["smtp", "dns", "pop3", "imap"]:
                # Email and domain services are moderately exploitable
                base_score = 0.6
            elif service in ["mysql", "postgresql", "mongodb", "redis"]:
                # Database services
                base_score = 0.7
            else:
                # Other services
                base_score = 0.5
            
            service_scores.append(base_score)
        
        # Average of service scores
        return sum(service_scores) / len(service_scores) if service_scores else 0.5
    
    def _calculate_exposure(self, threat, scan_results):
        """Calculate network exposure score
        
        Args:
            threat (dict): Identified threat
            scan_results (dict): Scan results from the port scanner
        
        Returns:
            float: Network exposure score
        """
        # For this implementation, we'll use a simplified approach
        # In a real implementation, this would consider network context, firewall rules, etc.
        
        # Count the number of open ports as a simple exposure metric
        open_ports = scan_results.get("open_ports", [])
        num_open_ports = len(open_ports)
        
        # More open ports indicate higher exposure
        if num_open_ports > 10:
            return 0.9
        elif num_open_ports > 5:
            return 0.7
        elif num_open_ports > 3:
            return 0.5
        elif num_open_ports > 0:
            return 0.3
        else:
            return 0.1
    
    def _determine_risk_level(self, risk_score):
        """Determine risk level based on risk score
        
        Args:
            risk_score (float): Risk score
        
        Returns:
            str: Risk level
        """
        if risk_score >= self.RISK_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        elif risk_score >= self.RISK_THRESHOLDS["HIGH"]:
            return "HIGH"
        elif risk_score >= self.RISK_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        elif risk_score >= self.RISK_THRESHOLDS["LOW"]:
            return "LOW"
        else:
            return "INFO"
    
    def get_overall_risk_assessment(self, risk_assessments):
        """Get overall risk assessment based on individual assessments
        
        Args:
            risk_assessments (list): List of risk assessment results
        
        Returns:
            dict: Overall risk assessment
        """
        if not risk_assessments:
            return {
                "overall_risk_level": "INFO",
                "overall_risk_score": 0.0,
                "risk_distribution": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0
                }
            }
        
        # Count threats by risk level
        risk_distribution = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for assessment in risk_assessments:
            risk_level = assessment["risk_level"]
            risk_distribution[risk_level] += 1
        
        # Calculate overall risk score
        # Weighted average of risk scores, with higher weight for higher-risk threats
        total_score = 0.0
        total_weight = 0.0
        
        for assessment in risk_assessments:
            weight = self.SEVERITY_SCORES.get(assessment["risk_level"], 0.5)
            total_score += assessment["risk_score"] * weight
            total_weight += weight
        
        overall_risk_score = total_score / total_weight if total_weight > 0 else 0.0
        
        # Determine overall risk level
        overall_risk_level = self._determine_risk_level(overall_risk_score)
        
        return {
            "overall_risk_level": overall_risk_level,
            "overall_risk_score": overall_risk_score,
            "risk_distribution": risk_distribution
        }