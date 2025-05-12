#!/usr/bin/env python3

import socket
import logging
import time
import re

class ServiceDetector:
    """Class to detect services running on open ports"""
    
    # Service detection patterns
    SERVICE_PATTERNS = {
        "http": {
            "pattern": rb"HTTP/\d\.\d",
            "request": b"GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: CyberattackThreatCharacterizationSystem/0.1\r\n\r\n",
            "ports": [80, 8080, 8000, 8888]
        },
        "https": {
            "pattern": None,  # HTTPS requires SSL/TLS handshake
            "request": None,
            "ports": [443, 8443]
        },
        "ssh": {
            "pattern": rb"SSH-\d\.\d",
            "request": b"",  # SSH will send banner immediately
            "ports": [22]
        },
        "ftp": {
            "pattern": rb"^220.*FTP",
            "request": b"",  # FTP will send banner immediately
            "ports": [21]
        },
        "smtp": {
            "pattern": rb"^220.*SMTP",
            "request": b"",  # SMTP will send banner immediately
            "ports": [25, 587]
        },
        "pop3": {
            "pattern": rb"^\+OK",
            "request": b"",  # POP3 will send banner immediately
            "ports": [110]
        },
        "imap": {
            "pattern": rb"^\* OK",
            "request": b"",  # IMAP will send banner immediately
            "ports": [143]
        },
        "mysql": {
            "pattern": rb"^\x5b\x00\x00\x00\x0a\x35\x2e",  # MySQL protocol
            "request": b"",  # MySQL will send banner immediately
            "ports": [3306]
        },
        "redis": {
            "pattern": rb"-ERR unknown command",
            "request": b"PING\r\n",
            "ports": [6379]
        },
        "mongodb": {
            "pattern": None,  # MongoDB uses a binary protocol
            "request": None,
            "ports": [27017]
        },
        "rdp": {
            "pattern": None,  # RDP uses a complex protocol
            "request": None,
            "ports": [3389]
        }
    }
    
    def __init__(self, timeout=2):
        """Initialize ServiceDetector
        
        Args:
            timeout (float): Timeout for connection attempts in seconds
        """
        self.logger = logging.getLogger("threat_analyzer.service_detector")
        self.timeout = timeout
    
    def detect_services(self, target, open_ports):
        """Detect services running on open ports
        
        Args:
            target (str): Target IP address or hostname
            open_ports (list): List of open ports dict objects from port scanner
        
        Returns:
            list: List of services detected
        """
        self.logger.info(f"Detecting services on {len(open_ports)} open ports")
        services = []
        
        for port_info in open_ports:
            port = port_info["port"]
            service_info = self._detect_service(target, port)
            
            if service_info:
                self.logger.info(f"Detected service {service_info['service']} on port {port}")
                services.append(service_info)
            else:
                self.logger.debug(f"Could not identify service on port {port}")
                # Add generic info if service detection failed
                services.append({
                    "port": port,
                    "service": port_info.get("service", "unknown"),
                    "version": "unknown",
                    "banner": ""
                })
        
        return services
    
    def _detect_service(self, target, port):
        """Detect service on a specific port
        
        Args:
            target (str): Target IP address or hostname
            port (int): Port to check
        
        Returns:
            dict: Service information or None if detection failed
        """
        # First, try to identify common services by port
        for service_name, service_data in self.SERVICE_PATTERNS.items():
            if port in service_data["ports"]:
                # Try to get banner for this service
                banner = self._get_banner(target, port, service_data.get("request"))
                
                if banner:
                    # Check if banner matches expected pattern
                    if service_data["pattern"] and re.search(service_data["pattern"], banner):
                        version = self._extract_version(service_name, banner)
                        return {
                            "port": port,
                            "service": service_name,
                            "version": version,
                            "banner": banner.decode('utf-8', errors='ignore').strip()
                        }
                    else:
                        # Banner doesn't match expected pattern, but port matches
                        return {
                            "port": port,
                            "service": service_name,
                            "version": "unknown",
                            "banner": banner.decode('utf-8', errors='ignore').strip()
                        }
        
        # If no match by port, try generic banner grabbing
        banner = self._get_banner(target, port)
        if banner:
            # Try to identify service from banner
            for service_name, service_data in self.SERVICE_PATTERNS.items():
                if service_data["pattern"] and re.search(service_data["pattern"], banner):
                    version = self._extract_version(service_name, banner)
                    return {
                        "port": port,
                        "service": service_name,
                        "version": version,
                        "banner": banner.decode('utf-8', errors='ignore').strip()
                    }
        
        # No service identified
        return None
    
    def _get_banner(self, target, port, request=None):
        """Get banner from a service
        
        Args:
            target (str): Target IP address or hostname
            port (int): Port to connect to
            request (bytes): Request to send to service
        
        Returns:
            bytes: Banner received or None if connection failed
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((target, port))
            
            # Send request if provided
            if request:
                try:
                    # Format request with target if it contains {}
                    if b"{}" in request:
                        request = request.replace(b"{}", target.encode())
                    sock.send(request)
                except:
                    pass
            
            # Receive banner
            try:
                banner = sock.recv(1024)
                return banner
            except socket.timeout:
                return None
        
        except (socket.timeout, socket.error):
            return None
        
        finally:
            sock.close()
    
    def _extract_version(self, service_name, banner):
        """Extract version from banner
        
        Args:
            service_name (str): Service name
            banner (bytes): Banner received from service
        
        Returns:
            str: Extracted version or "unknown"
        """
        banner_str = banner.decode('utf-8', errors='ignore')
        
        version_patterns = {
            "http": r"Server: ([^\r\n]+)",
            "ssh": r"SSH-\d\.\d-([^\r\n]+)",
            "ftp": r"220[- ]([^\r\n]+)",
            "smtp": r"220[- ]([^\r\n]+)",
            "pop3": r"\+OK ([^\r\n]+)",
            "imap": r"\* OK ([^\r\n]+)",
        }
        
        if service_name in version_patterns:
            match = re.search(version_patterns[service_name], banner_str)
            if match:
                return match.group(1).strip()
        
        return "unknown"