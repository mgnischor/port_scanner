#!/usr/bin/env python3

#
# File: port_scanner.py
#
# Copyright (C) 2025 Miguel Nischor <miguel@nischor.com.br>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

"""
A fast and comprehensive TCP/UDP port scanner written in Python.

Description:
    This script performs port scanning on a target host to identify open
    or filtered ports for both TCP and UDP protocols. It utilizes threading
    to significantly speed up the scanning process.

Features:
    - Scans both TCP and UDP ports within the range of 1 to 1000.
    - Provides descriptions for well-known services associated with each port.
    - Uses a multi-threaded approach for high-performance scanning.
    - Accepts command-line arguments for target host and thread count.
    - Cleanly separates and displays the results for each protocol.

Usage:
    python3 port_scanner.py <target_host> [-t <threads>]

Example:
    python3 port_scanner.py 192.168.1.1
    python3 port_scanner.py scanme.nmap.org -t 200

Author:
    Miguel Nischor <miguel@nischor.com.br>
"""

import socket
import threading
from queue import Queue
import argparse
import sys
from datetime import datetime

# Dictionary with descriptions for common ports (1-1000)
PORT_DESCRIPTIONS = {
    1: "TCP Port Service Multiplexer (TCPMUX)",
    5: "Remote Job Entry (RJE)",
    7: "ECHO",
    18: "Message Send Protocol (MSP)",
    20: "FTP (File Transfer Protocol) - Data",
    21: "FTP (File Transfer Protocol) - Control",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer Protocol)",
    29: "MSG ICP",
    37: "TIME",
    42: "Host Name Server (NAMESERV)",
    43: "WHOIS",
    49: "Login Host Protocol (LOGIN)",
    53: "DNS (Domain Name System)",
    67: "BOOTP (Bootstrap Protocol) - Server",
    68: "BOOTP (Bootstrap Protocol) - Client",
    69: "TFTP (Trivial File Transfer Protocol)",
    70: "Gopher",
    79: "Finger",
    80: "HTTP (Hypertext Transfer Protocol)",
    88: "Kerberos",
    102: "ISO-TSAP",
    109: "POP2 (Post Office Protocol v2)",
    110: "POP3 (Post Office Protocol v3)",
    111: "RPC (Remote Procedure Call)",
    113: "Ident",
    115: "SFTP (Simple File Transfer Protocol)",
    118: "SQL Services",
    119: "NNTP (Network News Transfer Protocol)",
    123: "NTP (Network Time Protocol)",
    135: "Microsoft RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access Protocol)",
    156: "SQL Service",
    161: "SNMP (Simple Network Management Protocol)",
    162: "SNMPTRAP",
    179: "BGP (Border Gateway Protocol)",
    194: "IRC (Internet Relay Chat)",
    389: "LDAP (Lightweight Directory Access Protocol)",
    396: "Novell Netware over IP",
    443: "HTTPS (HTTP Secure)",
    444: "SNPP (Simple Network Paging Protocol)",
    445: "Microsoft-DS (SMB)",
    458: "Apple QuickTime",
    500: "ISAKMP / IKE",
    512: "rexec",
    513: "rlogin",
    514: "Syslog",
    515: "LPD/LPR (Line Printer Daemon)",
    520: "RIP (Routing Information Protocol)",
    523: "IBM-DB2",
    543: "Kerberos Login",
    544: "Kerberos Remote Shell",
    546: "DHCPv6 Client",
    547: "DHCPv6 Server",
    548: "AFP (Apple Filing Protocol)",
    554: "RTSP (Real Time Streaming Protocol)",
    563: "SNEWS, NNTPS",
    587: "SMTP (Mail Submission)",
    631: "CUPS (Common UNIX Printing System)",
    636: "LDAPS (LDAP over SSL)",
    873: "rsync",
    902: "VMware Server",
    989: "FTPS-DATA",
    990: "FTPS-CTRL",
    993: "IMAPS (IMAP over SSL)",
    995: "POP3S (POP3 over SSL)",
}

# Lists to store the results
open_tcp_ports = []
open_udp_ports = []
lock = threading.Lock()

def scan_port(proto, target_ip, port):
    """
    Scans a single port on a specific target.
    """
    try:
        if proto == 'tcp':
            # Create a TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            # Try to connect
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                with lock:
                    open_tcp_ports.append(port)
            sock.close()
        elif proto == 'udp':
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2) # UDP might need more time
            # Send an empty packet
            sock.sendto(b'', (target_ip, port))
            try:
                # Wait for a response (which shouldn't come if it's open)
                sock.recvfrom(1024)
            except socket.timeout:
                # If an ICMP Port Unreachable error is not received, the port is considered open/filtered.
                # This is an inference method, not a direct confirmation.
                 with lock:
                    open_udp_ports.append(port)
            except ConnectionResetError:
                # This error indicates the port is closed.
                pass
            sock.close()

    except (socket.gaierror, socket.error):
        # Ignore name resolution or other socket errors.
        pass

def worker(q, proto, target_ip):
    """
    Takes ports from the queue and scans them.
    """
    while not q.empty():
        port = q.get()
        scan_port(proto, target_ip, port)
        q.task_done()

def main():
    # Set up command-line arguments
    parser = argparse.ArgumentParser(description="Python Port Scanner with port descriptions.")
    parser.add_argument("host", help="Host or IP address to be scanned.")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads to use (default: 100).")
    args = parser.parse_args()

    target = args.host
    num_threads = args.threads

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Error: Unknown host '{target}'")
        sys.exit(1)

    print("-" * 60)
    print(f"Starting scan on: {target} ({target_ip})")
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Using {num_threads} threads.")
    print("-" * 60)

    # --- TCP Scan ---
    print("\n[+] Scanning TCP ports...")
    tcp_queue = Queue()
    for port in range(1, 1001):
        tcp_queue.put(port)

    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(tcp_queue, 'tcp', target_ip))
        thread.daemon = True
        thread.start()

    tcp_queue.join()

    # --- UDP Scan ---
    print("[+] Scanning UDP ports (this may be slower)...")
    udp_queue = Queue()
    for port in range(1, 1001):
        udp_queue.put(port)

    # Reduce the number of threads for UDP to avoid network overload
    udp_threads = max(1, num_threads // 2)

    for _ in range(udp_threads):
        thread = threading.Thread(target=worker, args=(udp_queue, 'udp', target_ip))
        thread.daemon = True
        thread.start()
    
    udp_queue.join()

    # --- Display Results ---
    # FIX: Simplifying the print statement to avoid syntax errors.
    print("\n========================= RESULTS =========================")

    # TCP Ports
    if open_tcp_ports:
        print("\n## Open TCP Ports:\n")
        for port in sorted(open_tcp_ports):
            description = PORT_DESCRIPTIONS.get(port, "Unknown Service")
            print(f"  {port:<5} ({description})")
    else:
        print("\n## No open TCP ports found (1-1000).")

    print("\n" + ("-" * 60))

    # UDP Ports
    if open_udp_ports:
        print("\n## Open/Filtered UDP Ports:\n")
        for port in sorted(open_udp_ports):
            description = PORT_DESCRIPTIONS.get(port, "Unknown Service")
            print(f"  {port:<5} ({description})")
    else:
        print("\n## No open/filtered UDP ports found (1-1000).")
        
    print("\n" + ("-" * 60))
    print(f"Scan finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
