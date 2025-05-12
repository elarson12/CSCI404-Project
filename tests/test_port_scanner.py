#!/usr/bin/env python3

import unittest
import socket
import threading
import time
import sys
import os

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.system_scan.port_scanner import PortScanner

class MockServer(threading.Thread):
    """Simple mock server for testing the port scanner"""
    
    def __init__(self, port, banner=None):
        """Initialize the mock server
        
        Args:
            port (int): Port to listen on
            banner (bytes): Banner to send when a client connects
        """
        super().__init__()
        self.port = port
        self.banner = banner or b"MOCK-SERVER-1.0"
        self.server_socket = None
        self.running = False
        self.daemon = True
    
    def run(self):
        """Run the server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind(('127.0.0.1', self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(0.5)
            self.running = True
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    client_socket.send(self.banner)
                    client_socket.close()
                except socket.timeout:
                    continue
                except:
                    break
        
        except:
            pass
        
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()


class TestPortScanner(unittest.TestCase):
    """Test the PortScanner class"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        # Start mock servers
        cls.mock_servers = []
        
        # HTTP server on port 8080
        http_server = MockServer(8080, b"HTTP/1.1 200 OK\r\nServer: MockHTTP/1.0\r\n\r\n")
        http_server.start()
        cls.mock_servers.append(http_server)
        
        # SSH server on port 2222
        ssh_server = MockServer(2222, b"SSH-2.0-MockSSH_1.0\r\n")
        ssh_server.start()
        cls.mock_servers.append(ssh_server)
        
        # Wait for servers to start
        time.sleep(1)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        # Stop mock servers
        for server in cls.mock_servers:
            server.stop()
    
    def test_scan_with_open_ports(self):
        """Test scanning with open ports"""
        scanner = PortScanner(timeout=0.5, use_nmap=False)
        results = scanner.scan('127.0.0.1', [8080, 2222, 9999])
        
        # Check if scan results contain expected data
        self.assertIn('open_ports', results)
        self.assertIn('closed_ports', results)
        self.assertIn('target', results)
        self.assertIn('ports_scanned', results)
        self.assertIn('scan_time', results)
        self.assertIn('timestamp', results)
        
        # Check if open ports are correctly identified
        open_ports = results['open_ports']
        open_port_numbers = [p['port'] for p in open_ports]
        
        self.assertIn(8080, open_port_numbers)
        self.assertIn(2222, open_port_numbers)
        self.assertNotIn(9999, open_port_numbers)
        
        # Check if number of closed ports is correct
        self.assertEqual(results['closed_ports'], 1)
    
    def test_scan_port_range(self):
        """Test scanning a range of ports"""
        scanner = PortScanner(timeout=0.5, use_nmap=False)
        results = scanner.scan_port_range('127.0.0.1', 2220, 2230)
        
        # Check if scan results contain expected data
        self.assertIn('open_ports', results)
        
        # Check if open ports are correctly identified
        open_ports = results['open_ports']
        open_port_numbers = [p['port'] for p in open_ports]
        
        self.assertIn(2222, open_port_numbers)
        
        # Check if number of scanned ports is correct
        self.assertEqual(results['ports_scanned'], 11)  # 2220 to 2230 inclusive
    
    def test_is_port_open(self):
        """Test checking if a specific port is open"""
        scanner = PortScanner(timeout=0.5, use_nmap=False)
        
        # Test with open port
        self.assertTrue(scanner.is_port_open('127.0.0.1', 8080))
        
        # Test with closed port
        self.assertFalse(scanner.is_port_open('127.0.0.1', 9999))


if __name__ == '__main__':
    unittest.main()