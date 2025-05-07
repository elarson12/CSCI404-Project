import socket

def scan_port(host, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        sock.connect((host, port))
        print(f"Port {port} is OPEN on {host}")
    except (socket.timeout, socket.error):
        print(f"Port {port} is CLOSED on {host}")
    finally:
        sock.close()

def listen_on_port(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))  # Listen on all interfaces
    server_socket.listen(1)  # Allow 1 connection in the queue
    print(f"Listening on port {port}... (Ctrl+C to stop)")

    try:
        while True:
            try:
                client_socket, addr = server_socket.accept()
                print(f"Connection from {addr[0]}:{addr[1]}")
                client_socket.close()
            except socket.timeout:
                # No connection received in timeout — loop again
                continue
    except KeyboardInterrupt:
        print("\nStopped listening.")
    finally:
        server_socket.close()


#TEST
host = "127.0.0.1" 
ports_to_scan = [22, 80, 443, 8080]

for port in ports_to_scan:
    scan_port(host, port)

listen_on_port(8080)