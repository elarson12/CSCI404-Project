#!/usr/bin/env python3

import logging
import socket
import platform
import os
import sys
import re
import subprocess
import json
from datetime import datetime

class SystemInfo:
    """Class to gather system information"""
    
    def __init__(self):
        """Initialize SystemInfo"""
        self.logger = logging.getLogger("threat_analyzer.system_info")
    
    def get_system_info(self):
        """Get information about the system running the scanner
        
        Returns:
            dict: System information
        """
        self.logger.info("Collecting system information")
        
        info = {
            "hostname": self._get_hostname(),
            "os": self._get_os_info(),
            "python_version": self._get_python_version(),
            "network": self._get_network_info(),
            "timestamp": datetime.now().isoformat()
        }
        
        return info
    
    def _get_hostname(self):
        """Get hostname
        
        Returns:
            str: Hostname
        """
        return socket.gethostname()
    
    def _get_os_info(self):
        """Get operating system information
        
        Returns:
            dict: OS information
        """
        os_info = {
            "name": platform.system(),
            "version": platform.version(),
            "release": platform.release(),
            "platform": platform.platform()
        }
        
        # Add more detailed information for specific OSes
        if os_info["name"] == "Linux":
            try:
                # Try to get Linux distribution
                if hasattr(platform, 'freedesktop_os_release'):
                    os_info["distribution"] = platform.freedesktop_os_release()
                else:
                    # Fallback for older Python versions
                    try:
                        with open('/etc/os-release', 'r') as f:
                            lines = f.readlines()
                            for line in lines:
                                if line.startswith('PRETTY_NAME='):
                                    os_info["distribution"] = line.split('=')[1].strip('"\'\n')
                                    break
                    except:
                        pass
            except:
                pass
        
        return os_info
    
    def _get_python_version(self):
        """Get Python version
        
        Returns:
            dict: Python version information
        """
        return {
            "version": sys.version,
            "implementation": platform.python_implementation(),
            "compiler": platform.python_compiler()
        }
    
    def _get_network_info(self):
        """Get network information
        
        Returns:
            dict: Network information
        """
        network_info = {
            "interfaces": self._get_network_interfaces(),
            "default_ip": self._get_default_ip()
        }
        
        return network_info
    
    def _get_network_interfaces(self):
        """Get network interfaces
        
        Returns:
            list: Network interfaces
        """
        interfaces = []
        
        try:
            if platform.system() == "Windows":
                # Use ipconfig on Windows
                output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8')
                # Parse output (simplified)
                sections = re.split(r'\r?\n\r?\n', output)
                for section in sections:
                    if "adapter" in section.lower():
                        interface = {
                            "name": re.search(r'adapter (.*?):', section, re.IGNORECASE).group(1).strip() if re.search(r'adapter (.*?):', section, re.IGNORECASE) else "Unknown",
                            "ip": re.search(r'IPv4 Address[.\s]+: ([^\r\n]+)', section).group(1).strip() if re.search(r'IPv4 Address[.\s]+: ([^\r\n]+)', section) else "",
                            "mac": re.search(r'Physical Address[.\s]+: ([^\r\n]+)', section).group(1).strip() if re.search(r'Physical Address[.\s]+: ([^\r\n]+)', section) else ""
                        }
                        if interface["ip"]:  # Only add interfaces with IP addresses
                            interfaces.append(interface)
            else:
                # Use ifconfig/ip on Unix-like systems
                try:
                    output = subprocess.check_output("ifconfig", shell=True).decode('utf-8')
                except:
                    try:
                        output = subprocess.check_output("ip addr", shell=True).decode('utf-8')
                    except:
                        return []
                
                # Parse output (simplified)
                sections = re.split(r'\n\n', output)
                for section in sections:
                    if not section.strip():
                        continue
                    
                    name_match = re.search(r'^([^\s:]+)', section)
                    ip_match = re.search(r'inet (?:addr:)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', section)
                    mac_match = re.search(r'(?:ether|HWaddr) ([0-9a-fA-F:]+)', section)
                    
                    if name_match:
                        interface = {
                            "name": name_match.group(1),
                            "ip": ip_match.group(1) if ip_match else "",
                            "mac": mac_match.group(1) if mac_match else ""
                        }
                        if interface["ip"]:  # Only add interfaces with IP addresses
                            interfaces.append(interface)
        except Exception as e:
            self.logger.warning(f"Error getting network interfaces: {str(e)}")
        
        return interfaces
    
    def _get_default_ip(self):
        """Get default IP address
        
        Returns:
            str: Default IP address
        """
        try:
            # Create a temporary socket to determine the default IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"  # Fallback to localhost
    
    def get_target_info(self, target):
        """Get information about a target
        
        Args:
            target (str): Target IP address or hostname
        
        Returns:
            dict: Target information
        """
        self.logger.info(f"Collecting information about target {target}")
        
        info = {
            "target": target,
            "resolved_ip": self._resolve_hostname(target),
            "hostname": self._reverse_lookup(target),
            "timestamp": datetime.now().isoformat()
        }
        
        return info
    
    def _resolve_hostname(self, hostname):
        """Resolve hostname to IP address
        
        Args:
            hostname (str): Hostname to resolve
        
        Returns:
            str: IP address or None if resolution failed
        """
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    def _reverse_lookup(self, ip):
        """Perform reverse DNS lookup
        
        Args:
            ip (str): IP address to look up
        
        Returns:
            str: Hostname or None if lookup failed
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None