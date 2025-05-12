#!/usr/bin/env python3

import unittest
import json
import os
import sys
import shutil
from datetime import datetime

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.threat_data.data_importer import ThreatDataImporter
from src.threat_identification.matcher import ThreatMatcher
from src.threat_identification.risk_assessor import RiskAssessor
from src.threat_characterization.impact_analyzer import ImpactAnalyzer
from src.threat_characterization.report_generator import ReportGenerator

class IntegrationTests(unittest.TestCase):
    """Integration tests for the Cyberattack Threat Characterization System"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        # Create necessary directories
        os.makedirs("data/threat_feeds", exist_ok=True)
        os.makedirs("data/scan_results", exist_ok=True)
        os.makedirs("data/reports", exist_ok=True)
        
        # Load configuration
        cls.config_dir = "config"
        
        # Load mock data
        cls.mock_dir = os.path.join(os.path.dirname(__file__), "mock_data")
        
        with open(os.path.join(cls.mock_dir, "mock_threats.json"), "r") as f:
            cls.mock_threats = json.load(f)
        
        with open(os.path.join(cls.mock_dir, "mock_scan.json"), "r") as f:
            cls.mock_scan = json.load(f)
        
        # Copy mock threats to threat feeds directory
        with open("data/threat_feeds/mock_threats.json", "w") as f:
            json.dump(cls.mock_threats, f)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        # Clean up test data
        if os.path.exists("data/threat_feeds/mock_threats.json"):
            os.remove("data/threat_feeds/mock_threats.json")
    
    def test_full_pipeline(self):
        """Test the full pipeline from data import to report generation"""
        # Load threat sources configuration
        with open(os.path.join(self.config_dir, "threat_sources.json"), "r") as f:
            threat_sources = json.load(f)
        
        # Load settings configuration
        with open(os.path.join(self.config_dir, "settings.json"), "r") as f:
            settings = json.load(f)
        
        # 1. Import threat data
        importer = ThreatDataImporter(threat_sources)
        threat_data = importer.load_threat_data()
        
        # Check if threat data was loaded
        self.assertGreater(len(threat_data), 0)
        
        # 2. Identify threats
        matcher = ThreatMatcher(settings["threat_identification"]["confidence_threshold"])
        matched_threats = matcher.match_threats(self.mock_scan, threat_data)
        
        # Check if threats were identified
        self.assertGreater(len(matched_threats), 0)
        
        # 3. Assess risks
        risk_assessor = RiskAssessor()
        risk_assessment = risk_assessor.assess_risks(matched_threats, self.mock_scan)
        
        # Check if risks were assessed
        self.assertEqual(len(risk_assessment), len(matched_threats))
        
        # 4. Analyze impact
        impact_analyzer = ImpactAnalyzer(settings["threat_characterization"]["impact_factors"])
        impact_analysis = impact_analyzer.analyze_impact(risk_assessment, self.mock_scan)
        
        # Check if impact was analyzed
        self.assertEqual(len(impact_analysis), len(risk_assessment))
        
        # 5. Generate report
        report_generator = ReportGenerator()
        report_file = f"data/reports/test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        report_data = {
            "scan_id": "test_scan",
            "timestamp": datetime.now().isoformat(),
            "target": self.mock_scan["target"],
            "system_info": self.mock_scan["system_info"],
            "scan_results": self.mock_scan,
            "threats": matched_threats,
            "risk_assessment": risk_assessment,
            "impact_analysis": impact_analysis
        }
        
        report_content = report_generator.generate_report(report_data, report_file)
        
        # Check if report was generated
        self.assertTrue(os.path.exists(report_file))
        self.assertGreater(os.path.getsize(report_file), 0)
        
        # Clean up
        os.remove(report_file)
    
    def test_report_formats(self):
        """Test different report formats"""
        # Prepare sample report data
        report_data = {
            "scan_id": "test_scan",
            "timestamp": datetime.now().isoformat(),
            "target": self.mock_scan["target"],
            "system_info": self.mock_scan["system_info"],
            "scan_results": self.mock_scan,
            "threats": [],
            "risk_assessment": [],
            "impact_analysis": []
        }
        
        # Test markdown format
        markdown_generator = ReportGenerator(format="markdown")
        markdown_file = "data/reports/test_markdown.md"
        markdown_content = markdown_generator.generate_report(report_data, markdown_file)
        
        self.assertTrue(os.path.exists(markdown_file))
        self.assertIn("# Cyberattack Threat Characterization Report", markdown_content)
        
        # Test JSON format
        json_generator = ReportGenerator(format="json")
        json_file = "data/reports/test_json.json"
        json_content = json_generator.generate_report(report_data, json_file)
        
        self.assertTrue(os.path.exists(json_file))
        # Verify it's valid JSON
        json_data = json.loads(json_content)
        self.assertEqual(json_data["scan_id"], "test_scan")
        
        # Test text format
        text_generator = ReportGenerator(format="text")
        text_file = "data/reports/test_text.txt"
        text_content = text_generator.generate_report(report_data, text_file)
        
        self.assertTrue(os.path.exists(text_file))
        self.assertIn("Cyberattack Threat Characterization Report", text_content)
        
        # Clean up
        os.remove(markdown_file)
        os.remove(json_file)
        os.remove(text_file)
    
    def test_risk_levels(self):
        """Test different risk levels"""
        # Create a sample threat with different severity levels
        sample_threats = []
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sample_threats.append({
                "threat_id": f"TEST-{severity}",
                "name": f"Test {severity} Threat",
                "description": f"Test threat with {severity} severity",
                "severity": severity,
                "confidence": 0.8,
                "matched_ports": [80],
                "matched_services": [{"service": "http", "version": "Apache 2.4.41"}]
            })
        
        # Assess risks
        risk_assessor = RiskAssessor()
        risk_assessment = risk_assessor.assess_risks(sample_threats, self.mock_scan)
        
        # Check if risks were assessed correctly
        self.assertEqual(len(risk_assessment), len(sample_threats))
        
        # Verify risk levels
        risk_levels = [risk["risk_level"] for risk in risk_assessment]
        
        # Higher severity should result in higher risk level
        risk_order = {risk: i for i, risk in enumerate(risk_levels)}
        self.assertLessEqual(risk_order["CRITICAL"], risk_order["HIGH"])
        self.assertLessEqual(risk_order["HIGH"], risk_order["MEDIUM"])
        self.assertLessEqual(risk_order["MEDIUM"], risk_order["LOW"])
        
        # Get overall risk assessment
        overall_risk = risk_assessor.get_overall_risk_assessment(risk_assessment)
        
        # Check if overall risk distribution is correct
        self.assertEqual(overall_risk["risk_distribution"]["CRITICAL"], 1)
        self.assertEqual(overall_risk["risk_distribution"]["HIGH"], 1)
        self.assertEqual(overall_risk["risk_distribution"]["MEDIUM"], 1)
        self.assertEqual(overall_risk["risk_distribution"]["LOW"], 1)
        self.assertEqual(overall_risk["risk_distribution"]["INFO"], 1)
    
    def test_impact_analysis(self):
        """Test impact analysis"""
        # Create a sample risk assessment
        sample_risks = [
            {
                "threat_id": "TEST-CRITICAL",
                "name": "Critical Test Threat",
                "severity": "CRITICAL",
                "risk_level": "CRITICAL",
                "risk_score": 0.9,
                "risk_factors": {
                    "base_severity": 0.9,
                    "confidence": 0.8,
                    "port_exposure": 0.7,
                    "exploitability": 0.9,
                    "network_exposure": 0.8
                }
            },
            {
                "threat_id": "TEST-MEDIUM",
                "name": "Medium Test Threat",
                "severity": "MEDIUM",
                "risk_level": "MEDIUM",
                "risk_score": 0.5,
                "risk_factors": {
                    "base_severity": 0.5,
                    "confidence": 0.6,
                    "port_exposure": 0.4,
                    "exploitability": 0.5,
                    "network_exposure": 0.3
                }
            }
        ]
        
        # Load impact factors from settings
        with open(os.path.join(self.config_dir, "settings.json"), "r") as f:
            settings = json.load(f)
        
        # Analyze impact
        impact_analyzer = ImpactAnalyzer(settings["threat_characterization"]["impact_factors"])
        impact_analysis = impact_analyzer.analyze_impact(sample_risks, self.mock_scan)
        
        # Check if impact was analyzed correctly
        self.assertEqual(len(impact_analysis), len(sample_risks))
        
        # Verify critical threat has higher impact than medium threat
        critical_impact = next(i for i in impact_analysis if i["threat_id"] == "TEST-CRITICAL")
        medium_impact = next(i for i in impact_analysis if i["threat_id"] == "TEST-MEDIUM")
        
        self.assertGreater(critical_impact["impact_score"], medium_impact["impact_score"])
        
        # Verify mitigation priority is set correctly
        self.assertEqual(critical_impact["mitigation_priority"], "IMMEDIATE")
        self.assertIn(medium_impact["mitigation_priority"], ["MEDIUM", "HIGH"])
        
        # Verify recommended actions are provided
        self.assertGreater(len(critical_impact["recommended_actions"]), 0)
        self.assertGreater(len(medium_impact["recommended_actions"]), 0)


if __name__ == '__main__':
    unittest.main()