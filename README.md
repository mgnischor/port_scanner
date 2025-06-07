# Python Port Scanner

A fast, multi-threaded TCP/UDP port scanner written in Python. This script is a command-line tool designed for network administrators and security professionals to quickly identify open ports on a target host.

This project is self-contained and uses only standard Python libraries, requiring no external dependencies.

## Features

  - **Dual Protocol Scanning**: Scans for both TCP and UDP ports.
  - **Multi-Threaded**: Utilizes threading to perform scans quickly and efficiently.
  - **Service Description**: Identifies and displays the common service name for ports 1-1000 (e.g., 80 is HTTP, 443 is HTTPS).
  - **User-Friendly CLI**: Simple command-line interface for specifying the target and number of threads.
  - **No Dependencies**: Runs out-of-the-box with a standard Python 3 installation.

## Repository Files

  - `port_scanner.py`: The main Python script.
  - `LICENSE.md`: The full text of the GNU General Public License v3.
  - `README.md`: This file.

## Requirements

  - Python 3.x

## Installation

No special installation is needed. Just clone the repository:

```bash
git clone https://github.com/your-username/your-repository-name.git
cd your-repository-name
```

## Usage

Run the script from your terminal, providing the target host (IP address or domain name) as an argument.

**Basic Syntax:**

```bash
python3 port_scanner.py <target_host>
```

**Options:**

You can specify the number of threads to use for the scan with the `-t` or `--threads` flag. The default is 100.

```bash
python3 port_scanner.py <target_host> -t <number_of_threads>
```

### Examples

**1. Scan a local IP address:**

```bash
python3 port_scanner.py 192.168.1.1
```

**2. Scan a public domain with 200 threads:**

(Note: Only scan hosts you have explicit permission to test.)

```bash
python3 port_scanner.py scanme.nmap.org -t 200
```

## Example Output

```
------------------------------------------------------------
Starting scan on: scanme.nmap.org (45.33.32.156)
Start time: 2025-06-07 18:40:00
Using 200 threads.
------------------------------------------------------------

[+] Scanning TCP ports...
[+] Scanning UDP ports (this may be slower)...

========================= RESULTS =========================

## Open TCP Ports:

  22    (SSH (Secure Shell))
  80    (HTTP (Hypertext Transfer Protocol))

------------------------------------------------------------

## No open/filtered UDP ports found (1-1000).

------------------------------------------------------------
Scan finished at: 2025-06-07 18:40:35
```

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE.md](LICENSE.md) file for the full license text.

-----

### **Disclaimer**

This tool is intended for educational purposes and for use on networks and systems where you have explicit, written authorization. Unauthorized port scanning can be considered a hostile act and may be illegal in your jurisdiction. The author is not responsible for any misuse or damage caused by this program.
