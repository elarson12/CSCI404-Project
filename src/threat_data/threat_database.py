#!/usr/bin/env python3

import os
import json
import logging
from datetime import datetime

class ThreatDatabase:
    """Class to manage the local threat database"""
    
    def __init__(self):
        """Initialize ThreatDatabase"""
        self.logger = logging.getLogger("threat_analyzer.threat_database")
        self.db_path = "data/threat_feeds/local_threats.json"
        
        # Create database file if it doesn't exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        if not os.path.exists(self.db_path):
            with open(self.db_path, "w") as f:
                json.dump({"threats": [], "last_updated": datetime.now().isoformat()}, f)
    
    def get_all_threats(self):
        """Get all threats from the database"""
        try:
            with open(self.db_path, "r") as f:
                data = json.load(f)
            return data.get("threats", [])
        except Exception as e:
            self.logger.error(f"Error reading threat database: {str(e)}")
            return []
    
    def get_threat_by_id(self, threat_id):
        """Get a specific threat by ID"""
        threats = self.get_all_threats()
        
        for threat in threats:
            if threat.get("id") == threat_id:
                return threat
        
        return None
    
    def add_threat(self, threat):
        """Add a new threat to the database"""
        if not threat.get("id"):
            threat["id"] = f"LOCAL-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        try:
            with open(self.db_path, "r") as f:
                data = json.load(f)
            
            threats = data.get("threats", [])
            
            # Check if threat already exists
            for i, existing_threat in enumerate(threats):
                if existing_threat.get("id") == threat.get("id"):
                    # Update existing threat
                    threats[i] = threat
                    break
            else:
                # Add new threat
                threats.append(threat)
            
            data["threats"] = threats
            data["last_updated"] = datetime.now().isoformat()
            
            with open(self.db_path, "w") as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"Added/updated threat {threat.get('id')} in database")
            return True
        
        except Exception as e:
            self.logger.error(f"Error adding threat to database: {str(e)}")
            return False
    
    def delete_threat(self, threat_id):
        """Delete a threat from the database"""
        try:
            with open(self.db_path, "r") as f:
                data = json.load(f)
            
            threats = data.get("threats", [])
            
            # Find and remove threat
            for i, threat in enumerate(threats):
                if threat.get("id") == threat_id:
                    del threats[i]
                    data["threats"] = threats
                    data["last_updated"] = datetime.now().isoformat()
                    
                    with open(self.db_path, "w") as f:
                        json.dump(data, f, indent=2)
                    
                    self.logger.info(f"Deleted threat {threat_id} from database")
                    return True
            
            self.logger.warning(f"Threat {threat_id} not found in database")
            return False
        
        except Exception as e:
            self.logger.error(f"Error deleting threat from database: {str(e)}")
            return False
    
    def search_threats(self, query):
        """Search threats by keyword"""
        threats = self.get_all_threats()
        results = []
        
        query = query.lower()
        
        for threat in threats:
            # Search in ID, name, and description
            if (query in threat.get("id", "").lower() or
                query in threat.get("name", "").lower() or
                query in threat.get("description", "").lower()):
                results.append(threat)
        
        return results
    
    def filter_threats_by_severity(self, severity):
        """Filter threats by severity level"""
        threats = self.get_all_threats()
        return [t for t in threats if t.get("severity", "").upper() == severity.upper()]
    
    def get_threat_stats(self):
        """Get statistics about the threat database"""
        threats = self.get_all_threats()
        
        # Count threats by severity
        severity_counts = {}
        for threat in threats:
            severity = threat.get("severity", "UNKNOWN").upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Get last updated timestamp
        try:
            with open(self.db_path, "r") as f:
                data = json.load(f)
            last_updated = data.get("last_updated", "Unknown")
        except:
            last_updated = "Unknown"
        
        return {
            "total_threats": len(threats),
            "severity_distribution": severity_counts,
            "last_updated": last_updated
        }