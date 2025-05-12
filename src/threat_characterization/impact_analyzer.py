#!/usr/bin/env python3

import logging
from datetime import datetime

class ImpactAnalyzer:
    """Class to analyze the potential impact of identified threats"""
    
    def __init__(self, impact_factors):
        """Initialize ImpactAnalyzer
        
        Args:
            impact_factors (dict): Impact factors configuration
        """
        self.logger = logging.getLogger("threat_analyzer.impact_analyzer")
        self.impact_factors = impact_factors
    
    def analyze_impact(self, risk_assessments, scan_results):
        """Analyze the potential impact of identified threats
        
        Args:
            risk_assessments (list): List of risk assessment results
            scan_results (dict): Scan results from the port scanner
        
        Returns:
            list: Impact analysis results
        """
        self.logger.info(f"Analyzing impact for {len(risk_assessments)} threats")
        
        impact_analyses = []
        
        for risk_assessment in risk_assessments:
            impact_analysis = self._analyze_threat_impact(risk_assessment, scan_results)
            impact_analyses.append(impact_analysis)
            
            self.logger.info(f"Analyzed impact for threat {risk_assessment['threat_id']}: {impact_analysis['impact_level']}")
        
        # Sort by impact score (descending)
        impact_analyses.sort(key=lambda x: x["impact_score"], reverse=True)
        
        return impact_analyses
    
    def _analyze_threat_impact(self, risk_assessment, scan_results):
        """Analyze the potential impact of a specific threat
        
        Args:
            risk_assessment (dict): Risk assessment result
            scan_results (dict): Scan results from the port scanner
        
        Returns:
            dict: Impact analysis result
        """
        threat_id = risk_assessment["threat_id"]
        risk_level = risk_assessment["risk_level"]
        risk_score = risk_assessment["risk_score"]
        
        # Gather impact factors
        data_breach_impact = self._assess_data_breach_impact(risk_assessment)
        service_disruption_impact = self._assess_service_disruption_impact(risk_assessment, scan_results)
        lateral_movement_impact = self._assess_lateral_movement_impact(risk_assessment, scan_results)
        
        # Calculate impact score
        impact_score = (
            data_breach_impact * self.impact_factors.get("data_breach", 0.8) +
            service_disruption_impact * self.impact_factors.get("service_disruption", 0.6) +
            lateral_movement_impact * 0.7  # Default weight for lateral movement
        ) / (
            self.impact_factors.get("data_breach", 0.8) +
            self.impact_factors.get("service_disruption", 0.6) +
            0.7  # Default weight for lateral movement
        )
        
        # Determine impact level
        impact_level = self._determine_impact_level(impact_score)
        
        # Determine potential attack vectors
        attack_vectors = self._determine_attack_vectors(risk_assessment, scan_results)
        
        # Determine recommended actions
        recommended_actions = self._determine_recommended_actions(risk_assessment, impact_level)
        
        return {
            "threat_id": threat_id,
            "risk_level": risk_level,
            "impact_score": impact_score,
            "impact_level": impact_level,
            "impact_factors": {
                "data_breach": data_breach_impact,
                "service_disruption": service_disruption_impact,
                "lateral_movement": lateral_movement_impact
            },
            "potential_attack_vectors": attack_vectors,
            "recommended_actions": recommended_actions,
            "mitigation_priority": self._determine_mitigation_priority(risk_level, impact_level),
            "timestamp": datetime.now().isoformat()
        }
    
    def _assess_data_breach_impact(self, risk_assessment):
        """Assess the potential impact of data breach
        
        Args:
            risk_assessment (dict): Risk assessment result
        
        Returns:
            float: Data breach impact score
        """
        # Extract threat name and risk factors
        threat_name = risk_assessment.get("name", "").lower()
        risk_factors = risk_assessment.get("risk_factors", {})
        
        # Check for data breach related keywords
        data_breach_keywords = [
            "injection", "sql", "data leak", "information disclosure",
            "sensitive data", "credentials", "password", "authentication"
        ]
        
        keyword_score = 0.0
        for keyword in data_breach_keywords:
            if keyword in threat_name:
                keyword_score += 0.15  # Increase score for each matching keyword
        
        # Cap keyword score at 0.8
        keyword_score = min(0.8, keyword_score)
        
        # Base score from risk level
        base_score = 0.0
        if risk_assessment["risk_level"] == "CRITICAL":
            base_score = 0.9
        elif risk_assessment["risk_level"] == "HIGH":
            base_score = 0.7
        elif risk_assessment["risk_level"] == "MEDIUM":
            base_score = 0.5
        elif risk_assessment["risk_level"] == "LOW":
            base_score = 0.3
        else:
            base_score = 0.1
        
        # Combine scores (higher of keyword score or base score, plus a small amount from the other)
        return max(keyword_score, base_score) + min(keyword_score, base_score) * 0.2
    
    def _assess_service_disruption_impact(self, risk_assessment, scan_results):
        """Assess the potential impact of service disruption
        
        Args:
            risk_assessment (dict): Risk assessment result
            scan_results (dict): Scan results from the port scanner
        
        Returns:
            float: Service disruption impact score
        """
        # Extract threat name and matched ports
        threat_name = risk_assessment.get("name", "").lower()
        matched_ports = []
        
        # Extract matched ports from risk assessment
        if "matched_ports" in risk_assessment:
            matched_ports = risk_assessment["matched_ports"]
        
        # Check for service disruption related keywords
        disruption_keywords = [
            "denial of service", "dos", "crash", "availability", "buffer overflow",
            "memory corruption", "resource consumption", "exhaustion"
        ]
        
        keyword_score = 0.0
        for keyword in disruption_keywords:
            if keyword in threat_name:
                keyword_score += 0.15  # Increase score for each matching keyword
        
        # Cap keyword score at 0.8
        keyword_score = min(0.8, keyword_score)
        
        # Check if matched ports are critical services
        port_score = 0.0
        critical_ports = [22, 25, 53, 80, 443, 3306, 5432]
        
        for port in matched_ports:
            if port in critical_ports:
                port_score += 0.1  # Increase score for each critical port
        
        # Cap port score at 0.7
        port_score = min(0.7, port_score)
        
        # Combine scores
        return max(keyword_score, port_score) + min(keyword_score, port_score) * 0.3
    
    def _assess_lateral_movement_impact(self, risk_assessment, scan_results):
        """Assess the potential impact of lateral movement
        
        Args:
            risk_assessment (dict): Risk assessment result
            scan_results (dict): Scan results from the port scanner
        
        Returns:
            float: Lateral movement impact score
        """
        # Extract threat name and risk level
        threat_name = risk_assessment.get("name", "").lower()
        risk_level = risk_assessment.get("risk_level", "MEDIUM")
        
        # Check for lateral movement related keywords
        lateral_keywords = [
            "privilege escalation", "remote code execution", "rce", "command injection",
            "backdoor", "arbitrary code", "shell", "root", "admin", "credentials"
        ]
        
        keyword_score = 0.0
        for keyword in lateral_keywords:
            if keyword in threat_name:
                keyword_score += 0.15  # Increase score for each matching keyword
        
        # Cap keyword score at 0.8
        keyword_score = min(0.8, keyword_score)
        
        # Base score from risk level
        base_score = 0.0
        if risk_level == "CRITICAL":
            base_score = 0.9
        elif risk_level == "HIGH":
            base_score = 0.7
        elif risk_level == "MEDIUM":
            base_score = 0.5
        elif risk_level == "LOW":
            base_score = 0.3
        else:
            base_score = 0.1
        
        # Combine scores
        return max(keyword_score, base_score) + min(keyword_score, base_score) * 0.2
    
    def _determine_impact_level(self, impact_score):
        """Determine impact level based on impact score
        
        Args:
            impact_score (float): Impact score
        
        Returns:
            str: Impact level
        """
        if impact_score >= 0.8:
            return "CRITICAL"
        elif impact_score >= 0.6:
            return "HIGH"
        elif impact_score >= 0.4:
            return "MEDIUM"
        elif impact_score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _determine_attack_vectors(self, risk_assessment, scan_results):
        """Determine potential attack vectors
        
        Args:
            risk_assessment (dict): Risk assessment result
            scan_results (dict): Scan results from the port scanner
        
        Returns:
            list: Potential attack vectors
        """
        # Extract threat name and matched services
        threat_name = risk_assessment.get("name", "").lower()
        matched_services = []
        
        # Extract matched services from risk assessment
        if "matched_services" in risk_assessment:
            matched_services = risk_assessment["matched_services"]
        
        attack_vectors = []
        
        # Check for common attack vectors
        if any(keyword in threat_name for keyword in ["sql", "injection", "query"]):
            attack_vectors.append("SQL Injection")
        
        if any(keyword in threat_name for keyword in ["xss", "cross site", "script"]):
            attack_vectors.append("Cross-Site Scripting (XSS)")
        
        if any(keyword in threat_name for keyword in ["csrf", "request forgery"]):
            attack_vectors.append("Cross-Site Request Forgery (CSRF)")
        
        if any(keyword in threat_name for keyword in ["rce", "remote code", "execution"]):
            attack_vectors.append("Remote Code Execution")
        
        if any(keyword in threat_name for keyword in ["overflow", "buffer"]):
            attack_vectors.append("Buffer Overflow")
        
        if any(keyword in threat_name for keyword in ["dos", "denial", "service"]):
            attack_vectors.append("Denial of Service")
        
        if any(keyword in threat_name for keyword in ["auth", "authentication", "bypass"]):
            attack_vectors.append("Authentication Bypass")
        
        # Add specific service-based attack vectors
        for service_match in matched_services:
            service = service_match.get("service", "").lower()
            
            if service == "ssh":
                attack_vectors.append("SSH Brute Force")
            
            elif service in ["http", "https"]:
                attack_vectors.append("Web Application Attack")
            
            elif service in ["mysql", "postgresql", "mongodb"]:
                attack_vectors.append("Database Attack")
            
            elif service in ["ftp", "sftp"]:
                attack_vectors.append("File Transfer Attack")
        
        # If no specific attack vectors found, add generic ones
        if not attack_vectors:
            if risk_assessment["risk_level"] in ["CRITICAL", "HIGH"]:
                attack_vectors.append("Exploitation of Vulnerability")
            else:
                attack_vectors.append("Potential Vulnerability Exploitation")
        
        return list(set(attack_vectors))  # Remove duplicates
    
    def _determine_recommended_actions(self, risk_assessment, impact_level):
        """Determine recommended actions based on risk assessment and impact level
        
        Args:
            risk_assessment (dict): Risk assessment result
            impact_level (str): Impact level
        
        Returns:
            list: Recommended actions
        """
        recommended_actions = []
        
        # Add remediation if available
        if "remediation" in risk_assessment and risk_assessment["remediation"]:
            recommended_actions.append(risk_assessment["remediation"])
        
        # Add general recommendations based on risk and impact level
        if impact_level in ["CRITICAL", "HIGH"]:
            if risk_assessment["risk_level"] in ["CRITICAL", "HIGH"]:
                recommended_actions.append("Apply security patches immediately")
                recommended_actions.append("Temporarily disable affected services until patched")
                recommended_actions.append("Implement network-level filtering or isolation")
            else:
                recommended_actions.append("Apply security patches as soon as possible")
                recommended_actions.append("Monitor affected services for suspicious activity")
        elif impact_level == "MEDIUM":
            if risk_assessment["risk_level"] in ["CRITICAL", "HIGH"]:
                recommended_actions.append("Apply security patches within 24-48 hours")
                recommended_actions.append("Increase monitoring on affected services")
            else:
                recommended_actions.append("Schedule patching during next maintenance window")
                recommended_actions.append("Review configurations for hardening opportunities")
        else:  # LOW or MINIMAL
            recommended_actions.append("Apply security patches according to regular schedule")
            recommended_actions.append("Review security baseline for affected services")
        
        return list(set(recommended_actions))  # Remove duplicates
    
    def _determine_mitigation_priority(self, risk_level, impact_level):
        """Determine mitigation priority based on risk and impact levels
        
        Args:
            risk_level (str): Risk level
            impact_level (str): Impact level
        
        Returns:
            str: Mitigation priority
        """
        # Mitigation priority matrix
        priority_matrix = {
            "CRITICAL": {
                "CRITICAL": "IMMEDIATE",
                "HIGH": "IMMEDIATE",
                "MEDIUM": "URGENT",
                "LOW": "HIGH",
                "MINIMAL": "MEDIUM"
            },
            "HIGH": {
                "CRITICAL": "IMMEDIATE",
                "HIGH": "URGENT",
                "MEDIUM": "HIGH",
                "LOW": "MEDIUM",
                "MINIMAL": "LOW"
            },
            "MEDIUM": {
                "CRITICAL": "URGENT",
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "LOW": "LOW",
                "MINIMAL": "PLANNED"
            },
            "LOW": {
                "CRITICAL": "HIGH",
                "HIGH": "MEDIUM",
                "MEDIUM": "LOW",
                "LOW": "PLANNED",
                "MINIMAL": "PLANNED"
            },
            "INFO": {
                "CRITICAL": "MEDIUM",
                "HIGH": "LOW",
                "MEDIUM": "PLANNED",
                "LOW": "PLANNED",
                "MINIMAL": "OPTIONAL"
            }
        }
        
        # Get priority from matrix, default to PLANNED if not found
        return priority_matrix.get(risk_level, {}).get(impact_level, "PLANNED")
    
    def get_overall_impact_assessment(self, impact_analyses):
        """Get overall impact assessment based on individual analyses
        
        Args:
            impact_analyses (list): List of impact analysis results
        
        Returns:
            dict: Overall impact assessment
        """
        if not impact_analyses:
            return {
                "overall_impact_level": "MINIMAL",
                "overall_impact_score": 0.0,
                "impact_distribution": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "MINIMAL": 0
                },
                "priority_distribution": {
                    "IMMEDIATE": 0,
                    "URGENT": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "PLANNED": 0,
                    "OPTIONAL": 0
                }
            }
        
        # Count threats by impact level
        impact_distribution = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "MINIMAL": 0
        }
        
        # Count threats by priority
        priority_distribution = {
            "IMMEDIATE": 0,
            "URGENT": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "PLANNED": 0,
            "OPTIONAL": 0
        }
        
        for analysis in impact_analyses:
            impact_level = analysis["impact_level"]
            impact_distribution[impact_level] += 1
            
            priority = analysis["mitigation_priority"]
            priority_distribution[priority] += 1
        
        # Calculate overall impact score (weighted average)
        level_weights = {
            "CRITICAL": 1.0,
            "HIGH": 0.8,
            "MEDIUM": 0.5,
            "LOW": 0.3,
            "MINIMAL": 0.1
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for analysis in impact_analyses:
            impact_level = analysis["impact_level"]
            weight = level_weights.get(impact_level, 0.5)
            total_score += analysis["impact_score"] * weight
            total_weight += weight
        
        overall_impact_score = total_score / total_weight if total_weight > 0 else 0.0
        
        # Determine overall impact level
        overall_impact_level = self._determine_impact_level(overall_impact_score)
        
        return {
            "overall_impact_level": overall_impact_level,
            "overall_impact_score": overall_impact_score,
            "impact_distribution": impact_distribution,
            "priority_distribution": priority_distribution
        }