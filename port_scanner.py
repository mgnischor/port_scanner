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
A feature-rich, multi-threaded TCP/UDP port scanner written in Python.

Description:
    This script is a command-line tool designed to perform network reconnaissance
    by identifying open or filtered ports on a target host. It is built to be
    both fast and flexible, using threading for performance and offering a
    wide range of options to customize the scan.

Features:
    - Scans for both TCP and UDP ports.
    - Customizable port selection (e.g., 80, 443, 1000-2000).
    - Multi-threaded scanning with adjustable thread count and timeouts.
    - Verbose mode for real-time progress monitoring.
    - Exports scan results to structured formats like JSON or CSV.
    - Identifies common services based on well-known port numbers.
    - Self-contained with no external dependencies required.

Usage:
    python3 port_scanner.py <host> [options]

Examples:
    # 1. Scan the most common ports on a host
    python3 port_scanner.py scanme.nmap.org

    # 2. Scan specific ports with verbose output
    python3 port_scanner.py 192.168.1.1 -p 21,22,25,80,443 -v

    # 3. Scan a range, increase timeout, and save results to a JSON file
    python3 port_scanner.py example.com -p 1-1024 --timeout 1.5 -o results.json

Author:
    Miguel Nischor <miguel@nischor.com.br>
"""

import socket
import threading
from queue import Queue
import argparse
import sys
from datetime import datetime
import json
import csv

# --- Port Descriptions Dictionary ---
PORT_DESCRIPTIONS = {
    1: "TCP Port Service Multiplexer (TCPMUX)", 5: "Remote Job Entry (RJE)", 7: "ECHO", 18: "Message Send Protocol (MSP)",
    20: "FTP (File Transfer Protocol) - Data", 21: "FTP (File Transfer Protocol) - Control", 22: "SSH (Secure Shell)",
    23: "Telnet", 25: "SMTP (Simple Mail Transfer Protocol)", 29: "MSG ICP", 37: "TIME", 42: "Host Name Server (NAMESERV)",
    43: "WHOIS", 49: "Login Host Protocol (LOGIN)", 53: "DNS (Domain Name System)", 67: "BOOTP (Bootstrap Protocol) - Server",
    68: "BOOTP (Bootstrap Protocol) - Client", 69: "TFTP (Trivial File Transfer Protocol)", 70: "Gopher", 79: "Finger",
    80: "HTTP (Hypertext Transfer Protocol)", 88: "Kerberos", 102: "ISO-TSAP", 109: "POP2 (Post Office Protocol v2)",
    110: "POP3 (Post Office Protocol v3)", 111: "RPC (Remote Procedure Call)", 113: "Ident", 115: "SFTP (Simple File Transfer Protocol)",
    118: "SQL Services", 119: "NNTP (Network News Transfer Protocol)", 123: "NTP (Network Time Protocol)", 135: "Microsoft RPC",
    137: "NetBIOS Name Service", 138: "NetBIOS Datagram Service", 139: "NetBIOS Session Service", 143: "IMAP (Internet Message Access Protocol)",
    156: "SQL Service", 161: "SNMP (Simple Network Management Protocol)", 162: "SNMPTRAP", 179: "BGP (Border Gateway Protocol)",
    194: "IRC (Internet Relay Chat)", 389: "LDAP (Lightweight Directory Access Protocol)", 396: "Novell Netware over IP",
    443: "HTTPS (HTTP Secure)", 444: "SNPP (Simple Network Paging Protocol)", 445: "Microsoft-DS (SMB)", 458: "Apple QuickTime",
    500: "ISAKMP / IKE", 512: "rexec", 513: "rlogin", 514: "Syslog", 515: "LPD/LPR (Line Printer Daemon)",
    520: "RIP (Routing Information Protocol)", 523: "IBM-DB2", 543: "Kerberos Login", 544: "Kerberos Remote Shell",
    546: "DHCPv6 Client", 547: "DHCPv6 Server", 548: "AFP (Apple Filing Protocol)", 554: "RTSP (Real Time Streaming Protocol)",
    563: "SNEWS, NNTPS", 587: "SMTP (Mail Submission)", 631: "CUPS (Common UNIX Printing System)", 636: "LDAPS (LDAP over SSL)",
    873: "rsync", 902: "VMware Server", 989: "FTPS-DATA", 990: "FTPS-CTRL", 993: "IMAPS (IMAP over SSL)", 995: "POP3S (POP3 over SSL)",
}

# --- Global lists for results ---
# They now store dictionaries for structured data
open_ports_tcp = []
open_ports_udp = []
lock = threading.Lock()

def parse_ports(port_string):
    """Parses the port string provided by the user (e.g., '80,100-200')."""
    ports_to_scan = set()
    try:
        parts = port_string.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start > end:
                    start, end = end, start # Ensure correct order
                for port in range(start, end + 1):
                    ports_to_scan.add(port)
            else:
                ports_to_scan.add(int(part))
        return sorted(list(ports_to_scan))
    except ValueError:
        print(f"[-] Error: Invalid port format '{port_string}'. Use formats like '80', '1-1024', or '22,80,443'.")
        sys.exit(1)

def scan_port(proto, target_ip, port, timeout, verbose):
    """Scans a single port on a specific target."""
    if verbose:
        # Use carriage return to keep the output on a single line
        print(f"[DEBUG] Testing {proto.upper()} port {port}...", end='\r')
    
    try:
        if proto == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((target_ip, port)) == 0:
                with lock:
                    if verbose:
                        # Print with padding to overwrite the debug line
                        print(f"\n[+] Open TCP Port: {port}                  ")
                    open_ports_tcp.append({'port': port, 'service': PORT_DESCRIPTIONS.get(port, "Unknown")})
            sock.close()
        elif proto == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b'', (target_ip, port))
            try:
                sock.recvfrom(1024)
            except socket.timeout:
                 with lock:
                    if verbose:
                        print(f"\n[+] Open/Filtered UDP Port: {port}         ")
                    open_ports_udp.append({'port': port, 'service': PORT_DESCRIPTIONS.get(port, "Unknown")})
            except ConnectionResetError:
                pass # This error indicates the port is closed
            sock.close()
    except (socket.gaierror, socket.error):
        pass # Ignore name resolution or other socket errors

def worker(q, proto, target_ip, timeout, verbose):
    """Takes ports from the queue and scans them."""
    while not q.empty():
        port = q.get()
        scan_port(proto, target_ip, port, timeout, verbose)
        q.task_done()

# --- Output Functions ---

def save_as_json(filename, data):
    """Saves the scan results to a JSON file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"\n[+] Results saved to '{filename}'")
    except IOError as e:
        print(f"\n[-] Error saving JSON file: {e}")

def save_as_csv(filename, data):
    """Saves the scan results to a CSV file."""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow(['target', 'ip', 'protocol', 'port', 'service'])
            # Write TCP ports
            for item in data['tcp_ports']:
                writer.writerow([data['target'], data['ip'], 'tcp', item['port'], item['service']])
            # Write UDP ports
            for item in data['udp_ports']:
                writer.writerow([data['target'], data['ip'], 'udp', item['port'], item['service']])
        print(f"\n[+] Results saved to '{filename}'")
    except IOError as e:
        print(f"\n[-] Error saving CSV file: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP/UDP port scanner in Python.",
        epilog="Example: python3 %(prog)s scanme.nmap.org -p 22,80,443 -o scan_results.json"
    )
    parser.add_argument("host", help="Host or IP address to scan.")
    parser.add_argument("-p", "--ports", default="1-1000", help="Ports to scan (e.g., '80,443' or '1-1024'). Default: 1-1000.")
    parser.add_argument("-o", "--output", help="Saves the results to a file (formats: json, csv). Detection is by extension.")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads to use (default: 100).")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout for each port in seconds (default: 1.0).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for real-time progress.")
    args = parser.parse_args()

    # --- Argument processing and setup ---
    target = args.host
    ports_to_scan = parse_ports(args.ports)
    
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Error: Unknown host '{target}'")
        sys.exit(1)

    print("-" * 60)
    print(f"Starting scan on: {target} ({target_ip})")
    print(f"Ports: {args.ports} | Threads: {args.threads} | Timeout: {args.timeout}s")
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    # --- Scanning logic ---
    # TCP Scan
    tcp_queue = Queue()
    for port in ports_to_scan: tcp_queue.put(port)
    if not tcp_queue.empty():
        print("\n[+] Scanning TCP ports...")
        for _ in range(args.threads):
            thread = threading.Thread(target=worker, args=(tcp_queue, 'tcp', target_ip, args.timeout, args.verbose))
            thread.daemon = True
            thread.start()
        tcp_queue.join()

    # UDP Scan
    udp_queue = Queue()
    for port in ports_to_scan: udp_queue.put(port)
    if not udp_queue.empty():
        print("\n[+] Scanning UDP ports (this may be slower)...")
        for _ in range(args.threads):
            thread = threading.Thread(target=worker, args=(udp_queue, 'udp', target_ip, args.timeout, args.verbose))
            thread.daemon = True
            thread.start()
        udp_queue.join()

    if args.verbose: print("\n" + " " * 60) # Clears the debug line

    # --- Prepare results data structure ---
    scan_results = {
        'target': target,
        'ip': target_ip,
        'scan_time': datetime.now().isoformat(),
        'tcp_ports': sorted(open_ports_tcp, key=lambda x: x['port']),
        'udp_ports': sorted(open_ports_udp, key=lambda x: x['port'])
    }

    # --- Save to file if requested ---
    if args.output:
        if args.output.endswith('.json'):
            save_as_json(args.output, scan_results)
        elif args.output.endswith('.csv'):
            save_as_csv(args.output, scan_results)
        else:
            print(f"\n[-] Unsupported output file format: '{args.output}'. Use .json or .csv.")

    # --- Display results on console ---
    print("\n========================= RESULTS =========================")
    if scan_results['tcp_ports']:
        print("\n## Open TCP Ports:\n")
        for p in scan_results['tcp_ports']:
            print(f"  {p['port']:<5} ({p['service']})")
    else:
        print(f"\n## No open TCP ports found in the specified range.")

    print("\n" + ("-" * 60))

    if scan_results['udp_ports']:
        print("\n## Open/Filtered UDP Ports:\n")
        for p in scan_results['udp_ports']:
            print(f"  {p['port']:<5} ({p['service']})")
    else:
        print(f"\n## No open/filtered UDP ports found in the specified range.")
        
    print("\n" + ("-" * 60))
    print(f"Scan finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
