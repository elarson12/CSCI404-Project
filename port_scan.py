import socket
import logging


#example of a blacklisted IP address 
keywords = ["172.25.202.169", "172.25.222.231"] 

#proof of concept for a database that stores recorded threats for a IP address
keyword_info = {
    "172.25.222.231": {
        "TYPE": "DDOS",
        "DATE_LISTED": "2025-01-01",
        "LEVEL": "HIGH"
    },
    "172.25.202.169": {
        "TYPE": "SCAM",
        "DATE_LISTED": "2024-12-01",
        "LEVEL": "LOW"
    }
}

#log warnings
logging.basicConfig(filename = "warnings.txt",
                    format="%(asctime)s %(message)s",
                    filemode="w")
log_warning = logging.getLogger()
log_warning.setLevel(logging.WARNING)

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
                check_ip = addr[0]
                check_port = addr[1]

                if check_ip in keywords:
                    print(f"WARNING: Blacklisted IP {check_ip} attempted to connect. Check warnings.txt")
                    #list recorded threat data from IP

                    print(check_ip, ":", keyword_info[check_ip])
                    #record connection to log
                    log_warning.warning(f"Blacklisted IP {check_ip}:{check_port} attempted to connect.")
                

                client_socket.close()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\nStopped listening.")
    finally:
        server_socket.close()


#TEST

#listen to port and check against keywords for blacklisted IP address
listen_on_port(8080)
