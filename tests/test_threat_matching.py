#!/usr/bin/env python3

import unittest
import json
import sys
import os

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.threat_identification.matcher import ThreatMatcher

class TestThreatMatcher(unittest.TestCase):
    """Test the ThreatMatcher class"""
    
    def setUp(self):
        """Set up test environment"""
        self.matcher = ThreatMatcher(confidence_threshold=0.5)
        
        # Sample scan results
        self.scan_results = {
            "target": "192.168.1.100",
            "open_ports": [
                {"port": 22, "state": "open", "service": "ssh"},
                {"port": 80, "state": "open", "service": "http"},
                {"port": 443, "state": "open", "service": "https"},
                {"port": 3306, "state": "open", "service": "mysql"}
            ],
            "services": [
                {
                    "port": 22,
                    "service": "ssh",
                    "version": "OpenSSH 8.2p1",
                    "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
                },
                {
                    "port": 80,
                    "service": "http",
                    "version": "Apache 2.4.41",
                    "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n"
                },
                {
                    "port": 443,
                    "service": "https",
                    "version": "Apache 2.4.41",
                    "banner": ""
                },
                {
                    "port": 3306,
                    "service": "mysql",
                    "version": "MySQL 8.0.27",
                    "banner": ""
                }
            ]
        }
        
        # Sample threat data
        self.threat_data = [
            {
                "id": "CVE-2021-44228",
                "name": "Log4j Remote Code Execution Vulnerability",
                "description": "A critical vulnerability in Apache Log4j...",
                "severity": "CRITICAL",
                "affected_systems": ["Apache Log4j 2.0-2.14.1"],
                "affected_ports": [80, 443],
                "detection_patterns": ["log4j", "jndi:ldap"],
                "remediation": "Update to Log4j 2.15.0 or higher"
            },
            {
                "id": "CVE-2022-22965",
                "name": "Spring Framework RCE Vulnerability",
                "description": "A vulnerability in Spring Framework...",
                "severity": "HIGH",
                "affected_systems": ["Spring Framework 5.3.0-5.3.17"],
                "affected_ports": [8080, 8443],
                "detection_patterns": ["spring"],
                "remediation": "Update to Spring Framework 5.3.18 or higher"
            },
            {
                "id": "CVE-2020-14145",
                "name": "OpenSSH Client Information Disclosure",
                "description": "An information disclosure vulnerability in OpenSSH client...",
                "severity": "MEDIUM",
                "affected_systems": ["OpenSSH 8.1p1-8.3p1"],
                "affected_ports": [22],
                "detection_patterns": ["OpenSSH_8"],
                "remediation": "Update to OpenSSH 8.4p1 or higher"
            },
            {
                "id": "CVE-2021-3156",
                "name": "Sudo Heap-Based Buffer Overflow",
                "description": "A heap-based buffer overflow in Sudo...",
                "severity": "CRITICAL",
                "affected_systems": ["Sudo before 1.9.5p2"],
                "affected_ports": [],
                "detection_patterns": ["sudo"],
                "remediation": "Update to Sudo 1.9.5p2 or higher"
            },
            {
                "id": "CVE-2022-33099",
                "name": "MySQL Information Disclosure",
                "description": "An information disclosure vulnerability in MySQL...",
                "severity": "MEDIUM",
                "affected_systems": ["MySQL 8.0.0-8.0.26"],
                "affected_ports": [3306],
                "detection_patterns": ["MySQL 8.0"],
                "remediation": "Update to MySQL 8.0.28 or higher"
            }
        ]
    
    def test_match_threats(self):
        """Test matching threats with scan results"""
        matched_threats = self.matcher.match_threats(self.scan_results, self.threat_data)
        
        # Check if the matcher found the expected threats
        self.assertGreater(len(matched_threats), 0)
        
        # Check if the OpenSSH vulnerability was matched
        ssh_threats = [t for t in matched_threats if t["threat_id"] == "CVE-2020-14145"]
        self.assertEqual(len(ssh_threats), 1)
        
        # Check if the MySQL vulnerability was matched
        mysql_threats = [t for t in matched_threats if t["threat_id"] == "CVE-2022-33099"]
        self.assertEqual(len(mysql_threats), 1)
        
        # Check if the Spring vulnerability was NOT matched (wrong ports)
        spring_threats = [t for t in matched_threats if t["threat_id"] == "CVE-2022-22965"]
        self.assertEqual(len(spring_threats), 0)
        
        # Check if the Sudo vulnerability was NOT matched (no pattern match)
        sudo_threats = [t for t in matched_threats if t["threat_id"] == "CVE-2021-3156"]
        self.assertEqual(len(sudo_threats), 0)
    
    def test_confidence_threshold(self):
        """Test confidence threshold filtering"""
        # Create a matcher with a very high threshold
        high_threshold_matcher = ThreatMatcher(confidence_threshold=0.9)
        high_matches = high_threshold_matcher.match_threats(self.scan_results, self.threat_data)
        
        # Create a matcher with a very low threshold
        low_threshold_matcher = ThreatMatcher(confidence_threshold=0.1)
        low_matches = low_threshold_matcher.match_threats(self.scan_results, self.threat_data)
        
        # Check if high threshold results in fewer matches
        self.assertLessEqual(len(high_matches), len(low_matches))
    
    def test_version_vulnerability_check(self):
        """Test version vulnerability checking"""
        # Test exact match
        self.assertTrue(self.matcher._is_version_vulnerable("8.2p1", "8.2p1"))
        
        # Test version range
        self.assertTrue(self.matcher._is_version_vulnerable("8.2", "8.0-8.3"))
        self.assertFalse(self.matcher._is_version_vulnerable("8.4", "8.0-8.3"))
        
        # Test "before" format
        self.assertTrue(self.matcher._is_version_vulnerable("8.2", "8.0 before 8.3"))
        self.assertFalse(self.matcher._is_version_vulnerable("8.3", "8.0 before 8.3"))


if __name__ == '__main__':
    unittest.main()