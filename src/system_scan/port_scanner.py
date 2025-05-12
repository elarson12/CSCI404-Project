#!/usr/bin/env python3

import socket
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import ipaddress
import nmap

class PortScanner:
    """Class to scan ports on a target system"""
    
    def __init__(self, timeout=1, threads=10, use_nmap=True):
        """Initialize PortScanner
        
        Args:
            timeout (float): Timeout for connection attempts in seconds
            threads (int): Number of threads to use for scanning
            use_nmap (bool): Whether to use nmap if available
        """
        self.logger = logging.getLogger("threat_analyzer.port_scanner")
        self.timeout = timeout
        self.threads = threads
        self.use_nmap = use_nmap
        self.nm = None
        
        # Initialize nmap if available and requested
        if self.use_nmap:
            try:
                self.nm = nmap.PortScanner()
                self.logger.info("Nmap scanner initialized")
            except:
                self.logger.warning("Nmap not available, falling back to socket scanner")
                self.use_nmap = False
    
    def scan(self, target, ports=None):
        """Scan ports on target
        
        Args:
            target (str): Target IP address or hostname
            ports (list): List of ports to scan
        
        Returns:
            dict: Scan results
        """
        self.logger.info(f"Starting port scan on {target}")
        start_time = time.time()
        
        # Validate target
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            self.logger.error(f"Invalid target: {target}")
            return {"error": f"Invalid target: {target}"}
        
        # Set default port range if not specified
        if ports is None:
            ports = list(range(1, 1025))
        
        if self.use_nmap and self.nm:
            scan_results = self._scan_with_nmap(target, ports)
        else:
            scan_results = self._scan_with_sockets(target, ports)
        
        # Add metadata
        scan_results.update({
            "target": target,
            "ports_scanned": len(ports),
            "scan_time": time.time() - start_time,
            "timestamp": datetime.now().isoformat()
        })
            
        self.logger.info(f"Port scan completed in {scan_results['scan_time']:.2f} seconds")
        return scan_results
    
    def _scan_with_sockets(self, target, ports):
        """Scan ports using sockets
        
        Args:
            target (str): Target IP address or hostname
            ports (list): List of ports to scan
        
        Returns:
            dict: Scan results
        """
        self.logger.info("Using socket-based port scanner")
        open_ports = []
        closed_ports = []
        
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((target, port))
            is_open = result == 0
            
            if is_open:
                service = self._get_service_name(port)
                open_ports.append({
                    "port": port,
                    "state": "open",
                    "service": service
                })
                self.logger.debug(f"Port {port} is open on {target}")
            else:
                closed_ports.append({
                    "port": port,
                    "state": "closed"
                })
            
            sock.close()
        
        # Use thread pool for parallel scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_port, ports)
        
        return {
            "open_ports": sorted(open_ports, key=lambda x: x["port"]),
            "closed_ports": len(closed_ports)
        }
    
    def _scan_with_nmap(self, target, ports):
        """Scan ports using nmap
        
        Args:
            target (str): Target IP address or hostname
            ports (list): List of ports to scan
        
        Returns:
            dict: Scan results
        """
        self.logger.info("Using nmap-based port scanner")
        
        # Convert ports list to nmap format
        port_str = ",".join(map(str, ports))
        
        try:
            self.nm.scan(target, arguments=f"-p {port_str} -sV -T4")
            
            open_ports = []
            
            # Check if target is in scan results
            if target in self.nm.all_hosts():
                for port in self.nm[target]['tcp']:
                    if self.nm[target]['tcp'][port]['state'] == 'open':
                        open_ports.append({
                            "port": port,
                            "state": "open",
                            "service": self.nm[target]['tcp'][port]['name'],
                            "version": self.nm[target]['tcp'][port]['product'] + " " + 
                                       self.nm[target]['tcp'][port]['version'],
                            "banner": self.nm[target]['tcp'][port]['extrainfo']
                        })
            
            return {
                "open_ports": sorted(open_ports, key=lambda x: x["port"]),
                "closed_ports": len(ports) - len(open_ports)
            }
        
        except Exception as e:
            self.logger.error(f"Nmap scan failed: {str(e)}")
            self.logger.info("Falling back to socket-based scanner")
            return self._scan_with_sockets(target, ports)
    
    def _get_service_name(self, port):
        """Get service name for a port number
        
        Args:
            port (int): Port number
        
        Returns:
            str: Service name
        """
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"
    
    def scan_port_range(self, target, start_port, end_port):
        """Scan a range of ports
        
        Args:
            target (str): Target IP address or hostname
            start_port (int): Start of port range
            end_port (int): End of port range
        
        Returns:
            dict: Scan results
        """
        ports = list(range(start_port, end_port + 1))
        return self.scan(target, ports)
    
    def is_port_open(self, target, port):
        """Check if a specific port is open
        
        Args:
            target (str): Target IP address or hostname
            port (int): Port to check
        
        Returns:
            bool: True if port is open, False otherwise
        """
        result = self.scan(target, [port])
        return len(result.get("open_ports", [])) > 0