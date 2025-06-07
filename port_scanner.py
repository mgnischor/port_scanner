#!/usr/bin/env python3

import socket
import threading
from queue import Queue
import argparse
import sys
from datetime import datetime
import json
import csv
import ssl

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
    - Banner grabbing for HTTP (80) and HTTPS (443) to identify server software.
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


# --- Port Descriptions Dictionary ---
PORT_DESCRIPTIONS = {
    80: "HTTP (Hypertext Transfer Protocol)", 443: "HTTPS (HTTP Secure)", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    # Other ports...
}

# --- Global lists for results ---
open_ports_tcp = []
open_ports_udp = []
lock = threading.Lock()

def grab_banner(target_ip, port, hostname):
    """
    Connects to an open port (80 or 443) to grab the service banner.
    Returns the banner string or None on failure.
    """
    try:
        if port == 80:
            # Standard HTTP banner grabbing
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((target_ip, port))
                # Send a simple HEAD request to get headers
                request = f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode()
                s.send(request)
                response = s.recv(1024).decode('utf-8', errors='ignore')
        elif port == 443:
            # HTTPS banner grabbing using SSL/TLS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target_ip, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    request = f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode()
                    ssock.send(request)
                    response = ssock.recv(1024).decode('utf-8', errors='ignore')
        else:
            return None

        # Find the 'Server:' header in the response
        for line in response.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()
        return None # Return None if Server header is not found

    except (socket.timeout, socket.error, ssl.SSLError, ConnectionRefusedError):
        return None

def parse_ports(port_string):
    """Parses the port string provided by the user (e.g., '80,100-200')."""
    # (No changes in this function)
    ports_to_scan = set()
    try:
        parts = port_string.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start > end: start, end = end, start
                for port in range(start, end + 1): ports_to_scan.add(port)
            else:
                ports_to_scan.add(int(part))
        return sorted(list(ports_to_scan))
    except ValueError:
        print(f"[-] Error: Invalid port format '{port_string}'. Use formats like '80', '1-1024', or '22,80,443'.")
        sys.exit(1)

def scan_port(proto, target_host, target_ip, port, timeout, verbose):
    """Scans a single port on a specific target."""
    if verbose:
        print(f"[DEBUG] Testing {proto.upper()} port {port}...", end='\r')
    
    try:
        if proto == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((target_ip, port)) == 0:
                # Port is open, prepare result data
                result_data = {'port': port, 'service': PORT_DESCRIPTIONS.get(port, "Unknown")}
                
                # If port is 80 or 443, try to grab the banner
                if port in [80, 443]:
                    banner = grab_banner(target_ip, port, target_host)
                    if banner:
                        result_data['banner'] = banner

                with lock:
                    if verbose:
                        banner_info = f" -> {result_data.get('banner', '')}" if 'banner' in result_data else ""
                        print(f"\n[+] Open TCP Port: {port}{banner_info}                  ")
                    open_ports_tcp.append(result_data)
            sock.close()
        elif proto == 'udp':
            # UDP scan logic remains the same, as banner grabbing is typically a TCP-based process
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
                pass
            sock.close()
    except (socket.gaierror, socket.error):
        pass

def worker(q, proto, target_host, target_ip, timeout, verbose):
    """Takes ports from the queue and scans them."""
    while not q.empty():
        port = q.get()
        scan_port(proto, target_host, target_ip, port, timeout, verbose)
        q.task_done()

# --- Output Functions ---

def save_as_json(filename, data):
    """Saves the scan results to a JSON file."""
    # (No changes in this function)
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
            # Write header with new 'banner' column
            writer.writerow(['target', 'ip', 'protocol', 'port', 'service', 'banner'])
            # Write TCP ports
            for item in data['tcp_ports']:
                writer.writerow([data['target'], data['ip'], 'tcp', item['port'], item['service'], item.get('banner', '')])
            # Write UDP ports (banner will be empty)
            for item in data['udp_ports']:
                writer.writerow([data['target'], data['ip'], 'udp', item['port'], item['service'], ''])
        print(f"\n[+] Results saved to '{filename}'")
    except IOError as e:
        print(f"\n[-] Error saving CSV file: {e}")

def main():
    # (Argument parser remains the same)
    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP/UDP port scanner in Python.",
        epilog="Example: python3 %(prog)s scanme.nmap.org -p 22,80,443,8080 -o scan_results.json"
    )
    parser.add_argument("host", help="Host or IP address to scan.")
    parser.add_argument("-p", "--ports", default="1-1000", help="Ports to scan (e.g., '80,443' or '1-1024'). Default: 1-1000.")
    parser.add_argument("-o", "--output", help="Saves the results to a file (formats: json, csv). Detection is by extension.")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads to use (default: 100).")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout for each port in seconds (default: 1.0).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for real-time progress.")
    args = parser.parse_args()
    
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
    
    # --- Scanning logic updated to pass target_host for banner grabbing ---
    # TCP Scan
    tcp_queue = Queue()
    for port in ports_to_scan: tcp_queue.put(port)
    if not tcp_queue.empty():
        print("\n[+] Scanning TCP ports...")
        for _ in range(args.threads):
            thread = threading.Thread(target=worker, args=(tcp_queue, 'tcp', target, target_ip, args.timeout, args.verbose))
            thread.daemon = True
            thread.start()
        tcp_queue.join()

    # UDP Scan
    udp_queue = Queue()
    for port in ports_to_scan: udp_queue.put(port)
    if not udp_queue.empty():
        print("\n[+] Scanning UDP ports (this may be slower)...")
        for _ in range(args.threads):
            # Pass target_host here as well for consistency, though it's not used for UDP
            thread = threading.Thread(target=worker, args=(udp_queue, 'udp', target, target_ip, args.timeout, args.verbose))
            thread.daemon = True
            thread.start()
        udp_queue.join()

    if args.verbose: print("\n" + " " * 60)

    # --- Prepare and save results ---
    scan_results = {
        'target': target,
        'ip': target_ip,
        'scan_time': datetime.now().isoformat(),
        'tcp_ports': sorted(open_ports_tcp, key=lambda x: x['port']),
        'udp_ports': sorted(open_ports_udp, key=lambda x: x['port'])
    }

    if args.output:
        if args.output.endswith('.json'):
            save_as_json(args.output, scan_results)
        elif args.output.endswith('.csv'):
            save_as_csv(args.output, scan_results)
        else:
            print(f"\n[-] Unsupported output file format: '{args.output}'. Use .json or .csv.")

    # --- Display results with banner info ---
    print("\n========================= RESULTS =========================")
    if scan_results['tcp_ports']:
        print("\n## Open TCP Ports:\n")
        for p in scan_results['tcp_ports']:
            banner_info = f"-> {p['banner']}" if 'banner' in p else ""
            print(f"  {p['port']:<5} ({p['service']}) {banner_info}")
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
