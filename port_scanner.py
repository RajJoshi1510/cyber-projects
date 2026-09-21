"""
Simple TCP Port Scanner
------------------------
Scans a target host for open ports in a given range using Python sockets.
Educational / authorized-use only: only scan hosts you own or have explicit
permission to test (e.g. your own machine at 127.0.0.1, or a lab VM).

Usage:
    python port_scanner.py 127.0.0.1 --start 1 --end 1024
"""

import socket
import argparse
import threading
from datetime import datetime

# Common ports mapped to the service that usually runs on them.
# This makes the output more useful than just a bare port number.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy",
}

open_ports = []
lock = threading.Lock()


def scan_port(target_ip: str, port: int, timeout: float = 0.5):
    """Try to open a TCP connection to a single port. If it succeeds,
    the port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            with lock:
                open_ports.append((port, service))
    except socket.error:
        pass
    finally:
        sock.close()


def scan_range(target_ip: str, start_port: int, end_port: int):
    print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
    print(f"Started at: {datetime.now()}\n")

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target_ip, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    open_ports.sort()
    if open_ports:
        print("Open ports found:")
        for port, service in open_ports:
            print(f"  Port {port:5d}  -  {service}")
    else:
        print("No open ports found in this range.")


def main():
    parser = argparse.ArgumentParser(description="Simple multithreaded TCP port scanner.")
    parser.add_argument("target", help="Target IP address or hostname (e.g. 127.0.0.1)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("Invalid hostname or IP address.")
        return

    scan_range(target_ip, args.start, args.end)


if __name__ == "__main__":
    main()
