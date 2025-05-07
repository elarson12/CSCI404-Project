import socket


def search_logfile(filename, keywords):
    with open(filename, "r") as file:
        for line in file:
            for keyword in keywords:
                if keyword in line:
                    print(f"DETECTED '{keyword}'")


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
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(1) 
    server_socket.settimeout(1)
    print(f"Listening on port {port}... (Ctrl+C to stop)")

    try:
        while True:
            try:
                client_socket, addr = server_socket.accept()
                print(f"Connection from {addr[0]}:{addr[1]}")
                client_socket.close()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\nStopped listening.")
    finally:
        server_socket.close()


#TEST

#log file scan
keywords = ["test", "127", "word"]
filename = "logfile.txt"

search_logfile(filename, keywords)

#port scan
host = "127.0.0.1" 
ports_to_scan = [22, 80, 443, 8080]

for port in ports_to_scan:
    scan_port(host, port)

#listen to port
listen_on_port(8080)