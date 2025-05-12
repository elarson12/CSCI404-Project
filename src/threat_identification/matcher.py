#!/usr/bin/env python3

import logging
import re
import json
from datetime import datetime

class ThreatMatcher:
    """Class to match threats with scan results"""
    
    def __init__(self, confidence_threshold=0.65):
        """Initialize ThreatMatcher
        
        Args:
            confidence_threshold (float): Minimum confidence required for a match
        """
        self.logger = logging.getLogger("threat_analyzer.threat_matcher")
        self.confidence_threshold = confidence_threshold
    
    def match_threats(self, scan_results, threat_data):
        """Match threats with scan results
        
        Args:
            scan_results (dict): Scan results from the port scanner
            threat_data (list): List of threats to match against
        
        Returns:
            list: Matched threats with confidence scores
        """
        self.logger.info("Matching threats with scan results")
        
        # Extract open ports and services
        open_ports = scan_results.get("open_ports", [])
        services = scan_results.get("services", [])
        
        # Group services by port for easier lookup
        services_by_port = {}
        for service in services:
            services_by_port[service["port"]] = service
        
        matched_threats = []
        
        for threat in threat_data:
            # Skip threats without necessary information
            if not self._is_threat_valid(threat):
                continue
            
            # Calculate matches and confidence
            port_matches = self._match_ports(threat, open_ports)
            service_matches = self._match_services(threat, services)
            banner_matches = self._match_banners(threat, services)
            pattern_matches = self._match_patterns(threat, services)
            
            # Calculate overall confidence
            confidence = self._calculate_confidence(
                port_matches, service_matches, banner_matches, pattern_matches
            )
            
            # Add threat to matched threats if confidence exceeds threshold
            if confidence >= self.confidence_threshold:
                matched_threat = {
                    "threat_id": threat.get("id"),
                    "name": threat.get("name"),
                    "description": threat.get("description"),
                    "severity": threat.get("severity", "MEDIUM"),
                    "confidence": confidence,
                    "matched_ports": port_matches["matched_ports"],
                    "matched_services": service_matches["matched_services"],
                    "matched_banners": banner_matches["matched_banners"],
                    "matched_patterns": pattern_matches["matched_patterns"],
                    "remediation": threat.get("remediation"),
                    "timestamp": datetime.now().isoformat()
                }
                
                matched_threats.append(matched_threat)
                
                self.logger.info(f"Matched threat {threat.get('id')} with confidence {confidence:.2f}")
        
        # Sort threats by confidence (descending)
        matched_threats.sort(key=lambda x: x["confidence"], reverse=True)
        
        self.logger.info(f"Matched {len(matched_threats)} threats with confidence >= {self.confidence_threshold}")
        return matched_threats
    
    def _is_threat_valid(self, threat):
        """Check if threat has necessary information for matching
        
        Args:
            threat (dict): Threat to check
        
        Returns:
            bool: True if threat is valid, False otherwise
        """
        # Threat must have at least an ID and name
        if not threat.get("id") or not threat.get("name"):
            return False
        
        # Threat must have at least one of: affected_ports, affected_systems, detection_patterns
        if not (threat.get("affected_ports") or 
                threat.get("affected_systems") or 
                threat.get("detection_patterns")):
            return False
        
        return True
    
    def _match_ports(self, threat, open_ports):
        """Match threat affected ports with open ports
        
        Args:
            threat (dict): Threat to match
            open_ports (list): List of open ports
        
        Returns:
            dict: Match information
        """
        affected_ports = threat.get("affected_ports", [])
        if not affected_ports:
            return {"matched": False, "matched_ports": [], "match_ratio": 0.0}
        
        matched_ports = []
        
        for port_info in open_ports:
            port = port_info["port"]
            if port in affected_ports:
                matched_ports.append(port)
        
        # Calculate match ratio (number of matched ports / number of affected ports)
        match_ratio = len(matched_ports) / len(affected_ports) if affected_ports else 0.0
        
        return {
            "matched": len(matched_ports) > 0,
            "matched_ports": matched_ports,
            "match_ratio": match_ratio
        }
    
    def _match_services(self, threat, services):
        """Match threat affected systems with detected services
        
        Args:
            threat (dict): Threat to match
            services (list): List of services
        
        Returns:
            dict: Match information
        """
        affected_systems = threat.get("affected_systems", [])
        if not affected_systems:
            return {"matched": False, "matched_services": [], "match_ratio": 0.0}
        
        matched_services = []
        
        for service in services:
            service_name = service.get("service", "").lower()
            service_version = service.get("version", "").lower()
            
            for system in affected_systems:
                system_lower = system.lower()
                
                # Check if service name is in affected system
                if service_name in system_lower:
                    # Check if version is specified and matches
                    if " " in system_lower:
                        system_name, system_version = system_lower.split(" ", 1)
                        
                        # If version is specified and service version is known
                        if system_version and service_version != "unknown":
                            # Check if service version matches or is vulnerable
                            if self._is_version_vulnerable(service_version, system_version):
                                matched_services.append({
                                    "port": service["port"],
                                    "service": service_name,
                                    "version": service_version,
                                    "affected_system": system
                                })
                        else:
                            # No version specified or service version unknown, match by name only
                            matched_services.append({
                                "port": service["port"],
                                "service": service_name,
                                "version": service_version,
                                "affected_system": system
                            })
                    else:
                        # No version specified in affected system, match by name only
                        matched_services.append({
                            "port": service["port"],
                            "service": service_name,
                            "version": service_version,
                            "affected_system": system
                        })
        
        # Calculate match ratio (number of matched services / number of affected systems)
        match_ratio = min(1.0, len(matched_services) / len(affected_systems)) if affected_systems else 0.0
        
        return {
            "matched": len(matched_services) > 0,
            "matched_services": matched_services,
            "match_ratio": match_ratio
        }
    
    def _is_version_vulnerable(self, service_version, affected_version):
        """Check if service version is vulnerable according to affected version
        
        Args:
            service_version (str): Detected service version
            affected_version (str): Affected version from threat
        
        Returns:
            bool: True if service version is vulnerable, False otherwise
        """
        # Parse versions
        service_parts = self._parse_version(service_version)
        
        # Handle different version specifications
        if "before" in affected_version:
            # Format: "X.Y.Z before X.Y.W"
            parts = affected_version.split("before")
            if len(parts) != 2:
                return False
            
            base_version = parts[0].strip()
            max_version = parts[1].strip()
            
            # Check if service version matches base version
            if not service_version.startswith(base_version):
                return False
            
            # Check if service version is less than max version
            max_parts = self._parse_version(max_version)
            return self._compare_versions(service_parts, max_parts) < 0
            
        elif "-" in affected_version:
            # Format: "X.Y.Z-X.Y.W" (range)
            parts = affected_version.split("-")
            if len(parts) != 2:
                return False
            
            min_version = parts[0].strip()
            max_version = parts[1].strip()
            
            min_parts = self._parse_version(min_version)
            max_parts = self._parse_version(max_version)
            
            # Check if service version is within range
            return (self._compare_versions(service_parts, min_parts) >= 0 and
                   self._compare_versions(service_parts, max_parts) <= 0)
        
        else:
            # Format: "X.Y.Z" (exact match)
            affected_parts = self._parse_version(affected_version)
            return self._compare_versions(service_parts, affected_parts) == 0
    
    def _parse_version(self, version_str):
        """Parse version string into components
        
        Args:
            version_str (str): Version string
        
        Returns:
            list: List of version components
        """
        # Extract version numbers
        components = []
        for part in re.findall(r'\d+', version_str):
            components.append(int(part))
        
        return components
    
    def _compare_versions(self, version1, version2):
        """Compare two version lists
        
        Args:
            version1 (list): First version list
            version2 (list): Second version list
        
        Returns:
            int: -1 if version1 < version2, 0 if version1 == version2, 1 if version1 > version2
        """
        # Compare components
        for i in range(min(len(version1), len(version2))):
            if version1[i] < version2[i]:
                return -1
            elif version1[i] > version2[i]:
                return 1
        
        # If all compared components are equal, compare lengths
        if len(version1) < len(version2):
            return -1
        elif len(version1) > len(version2):
            return 1
        else:
            return 0
    
    def _match_banners(self, threat, services):
        """Match threat detection patterns with service banners
        
        Args:
            threat (dict): Threat to match
            services (list): List of services
        
        Returns:
            dict: Match information
        """
        detection_patterns = threat.get("detection_patterns", [])
        if not detection_patterns:
            return {"matched": False, "matched_banners": [], "match_ratio": 0.0}
        
        matched_banners = []
        
        for service in services:
            banner = service.get("banner", "")
            if not banner:
                continue
            
            for pattern in detection_patterns:
                if pattern.lower() in banner.lower():
                    matched_banners.append({
                        "port": service["port"],
                        "service": service.get("service", "unknown"),
                        "pattern": pattern,
                        "banner": banner
                    })
                    break
        
        # Calculate match ratio (number of services with matching banners / total number of services with banners)
        services_with_banners = sum(1 for s in services if s.get("banner"))
        match_ratio = len(matched_banners) / services_with_banners if services_with_banners else 0.0
        
        return {
            "matched": len(matched_banners) > 0,
            "matched_banners": matched_banners,
            "match_ratio": match_ratio
        }
    
    def _match_patterns(self, threat, services):
        """Match threat detection patterns with service information
        
        Args:
            threat (dict): Threat to match
            services (list): List of services
        
        Returns:
            dict: Match information
        """
        detection_patterns = threat.get("detection_patterns", [])
        if not detection_patterns:
            return {"matched": False, "matched_patterns": [], "match_ratio": 0.0}
        
        matched_patterns = []
        
        for service in services:
            service_name = service.get("service", "").lower()
            service_version = service.get("version", "").lower()
            
            # Combine service information
            service_info = f"{service_name} {service_version}".lower()
            
            for pattern in detection_patterns:
                pattern_lower = pattern.lower()
                if pattern_lower in service_info:
                    matched_patterns.append({
                        "port": service["port"],
                        "service": service_name,
                        "version": service_version,
                        "pattern": pattern
                    })
        
        # Calculate match ratio (number of matched patterns / number of detection patterns)
        match_ratio = min(1.0, len(matched_patterns) / len(detection_patterns)) if detection_patterns else 0.0
        
        return {
            "matched": len(matched_patterns) > 0,
            "matched_patterns": matched_patterns,
            "match_ratio": match_ratio
        }
    
    def _calculate_confidence(self, port_matches, service_matches, banner_matches, pattern_matches):
        """Calculate overall confidence based on individual matches
        
        Args:
            port_matches (dict): Port match information
            service_matches (dict): Service match information
            banner_matches (dict): Banner match information
            pattern_matches (dict): Pattern match information
        
        Returns:
            float: Overall confidence score
        """
        # Define match type weights
        weights = {
            "port": 0.2,
            "service": 0.3,
            "banner": 0.3,
            "pattern": 0.2
        }
        
        # Calculate weighted score
        score = 0.0
        
        if port_matches["matched"]:
            score += weights["port"] * port_matches["match_ratio"]
        
        if service_matches["matched"]:
            score += weights["service"] * service_matches["match_ratio"]
        
        if banner_matches["matched"]:
            score += weights["banner"] * banner_matches["match_ratio"]
        
        if pattern_matches["matched"]:
            score += weights["pattern"] * pattern_matches["match_ratio"]
        
        return score