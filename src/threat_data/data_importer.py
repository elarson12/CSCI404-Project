#!/usr/bin/env python3

import os
import json
import logging
import requests
from datetime import datetime, timedelta
import time
from tqdm import tqdm

class ThreatDataImporter:
    """Class to import threat data from various sources"""
    
    def __init__(self, threat_sources):
        """Initialize ThreatDataImporter with threat sources configuration"""
        self.logger = logging.getLogger("threat_analyzer.data_importer")
        self.sources = threat_sources["sources"]
        self.keywords = threat_sources["keywords"]
        self.vulnerable_services = threat_sources["common_vulnerable_services"]
        
        # Create threat feeds directory if it doesn't exist
        os.makedirs("data/threat_feeds", exist_ok=True)
        
        # Initialize local threat database if it doesn't exist
        local_db_path = "data/threat_feeds/local_threats.json"
        if not os.path.exists(local_db_path):
            with open(local_db_path, "w") as f:
                json.dump({"threats": []}, f)
    
    def update_threat_data(self):
        """Update threat data from all sources"""
        self.logger.info("Updating threat data from all sources")
        
        for source in self.sources:
            try:
                if source["type"] == "api":
                    self._update_from_api(source)
                elif source["type"] == "download":
                    self._update_from_download(source)
                # Local sources don't need updating
            except Exception as e:
                self.logger.error(f"Error updating threat data from {source['name']}: {str(e)}")
    
    def _update_from_api(self, source):
        """Update threat data from API source"""
        self.logger.info(f"Updating threat data from API: {source['name']}")
        
        try:
            response = requests.get(
                source["url"],
                params=source.get("parameters", {}),
                headers=source.get("headers", {})
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Process and save data
                output_file = f"data/threat_feeds/{source['name'].lower().replace(' ', '_')}.json"
                
                with open(output_file, "w") as f:
                    json.dump(data, f, indent=2)
                
                self.logger.info(f"Updated threat data from {source['name']} saved to {output_file}")
            else:
                self.logger.error(f"Failed to fetch data from {source['name']}: HTTP {response.status_code}")
        
        except requests.RequestException as e:
            self.logger.error(f"Request error for {source['name']}: {str(e)}")
    
    def _update_from_download(self, source):
        """Update threat data from download source"""
        self.logger.info(f"Updating threat data from download: {source['name']}")
        
        # For demonstration purposes, we're creating sample data
        # In a real implementation, this would download data from the source URL
        
        if source["name"] == "Common Vulnerabilities and Exposures":
            sample_data = self._generate_sample_cve_data()
            
            with open(source["file"], "w") as f:
                json.dump(sample_data, f, indent=2)
            
            self.logger.info(f"Generated sample CVE data saved to {source['file']}")
    
    def _generate_sample_cve_data(self):
        """Generate sample CVE data for demonstration purposes"""
        cve_data = {"vulnerabilities": []}
        
        # Create sample vulnerabilities
        sample_vulns = [
            {
                "id": "CVE-2023-12345",
                "name": "Apache Log4j Remote Code Execution Vulnerability",
                "description": "Remote code execution vulnerability in Apache Log4j.",
                "severity": "CRITICAL",
                "affected_systems": ["Apache Log4j 2.0-2.14.1"],
                "affected_ports": [8080, 443],
                "detection_patterns": ["jndi:ldap", "JndiLookup.class"],
                "remediation": "Update to Log4j 2.15.0 or higher"
            },
            {
                "id": "CVE-2023-23456",
                "name": "OpenSSH Authentication Bypass",
                "description": "Authentication bypass vulnerability in OpenSSH.",
                "severity": "HIGH",
                "affected_systems": ["OpenSSH 8.x before 8.9"],
                "affected_ports": [22],
                "detection_patterns": ["OpenSSH_8"],
                "remediation": "Update to OpenSSH 8.9 or higher"
            },
            {
                "id": "CVE-2023-34567",
                "name": "MySQL Server SQL Injection",
                "description": "SQL injection vulnerability in MySQL Server.",
                "severity": "HIGH",
                "affected_systems": ["MySQL 8.0.x before 8.0.32"],
                "affected_ports": [3306],
                "detection_patterns": ["MySQL 8.0"],
                "remediation": "Update to MySQL 8.0.32 or higher"
            },
            {
                "id": "CVE-2023-45678",
                "name": "Nginx HTTP/2 Denial of Service",
                "description": "Denial of service vulnerability in Nginx HTTP/2 implementation.",
                "severity": "MEDIUM",
                "affected_systems": ["Nginx 1.20.x before 1.20.2"],
                "affected_ports": [80, 443],
                "detection_patterns": ["nginx/1.20"],
                "remediation": "Update to Nginx 1.20.2 or higher"
            },
            {
                "id": "CVE-2023-56789",
                "name": "Redis Command Injection",
                "description": "Command injection vulnerability in Redis.",
                "severity": "CRITICAL",
                "affected_systems": ["Redis 6.x before 6.2.7"],
                "affected_ports": [6379],
                "detection_patterns": ["Redis 6."],
                "remediation": "Update to Redis 6.2.7 or higher"
            }
        ]
        
        # Add more sample vulnerabilities for common services
        for service in self.vulnerable_services:
            cve_id = f"CVE-2023-{service['name'].lower()}"
            
            vuln = {
                "id": cve_id,
                "name": f"{service['name']} Vulnerability",
                "description": f"Sample vulnerability affecting {service['name']} services.",
                "severity": "MEDIUM",
                "affected_systems": [f"{service['name']} Server"],
                "affected_ports": service['ports'],
                "detection_patterns": [service['name'].lower()],
                "remediation": f"Update {service['name']} to latest version"
            }
            
            sample_vulns.append(vuln)
        
        cve_data["vulnerabilities"] = sample_vulns
        return cve_data
    
    def load_threat_data(self):
        """Load threat data from all sources"""
        self.logger.info("Loading threat data from all sources")
        
        all_threats = []
        
        for source in self.sources:
            try:
                if source.get("file"):
                    if os.path.exists(source["file"]):
                        with open(source["file"], "r") as f:
                            data = json.load(f)
                            
                            # Extract threats based on source format
                            if source["name"] == "Common Vulnerabilities and Exposures":
                                threats = data.get("vulnerabilities", [])
                            elif source["name"] == "Local Threat Database":
                                threats = data.get("threats", [])
                            else:
                                # Generic extraction
                                if "vulnerabilities" in data:
                                    threats = data["vulnerabilities"]
                                elif "threats" in data:
                                    threats = data["threats"]
                                else:
                                    threats = data
                            
                            self.logger.info(f"Loaded {len(threats)} threats from {source['name']}")
                            all_threats.extend(threats)
                    else:
                        self.logger.warning(f"Threat data file not found: {source['file']}")
            except Exception as e:
                self.logger.error(f"Error loading threat data from {source['name']}: {str(e)}")
        
        self.logger.info(f"Loaded a total of {len(all_threats)} threats from all sources")
        return all_threats
    
    def add_local_threat(self, threat):
        """Add a threat to the local threat database"""
        local_db_path = "data/threat_feeds/local_threats.json"
        
        try:
            with open(local_db_path, "r") as f:
                data = json.load(f)
            
            # Add or update threat
            existing_threats = data.get("threats", [])
            
            # Check if threat already exists (by ID)
            for i, existing_threat in enumerate(existing_threats):
                if existing_threat.get("id") == threat.get("id"):
                    # Update existing threat
                    existing_threats[i] = threat
                    break
            else:
                # Add new threat
                existing_threats.append(threat)
            
            data["threats"] = existing_threats
            
            with open(local_db_path, "w") as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"Added/updated threat {threat.get('id')} in local database")
            return True
        
        except Exception as e:
            self.logger.error(f"Error adding threat to local database: {str(e)}")
            return False