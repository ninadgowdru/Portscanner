import socket
import threading
from queue import Queue
import json
import csv
import ipaddress
import os
import time
from datetime import datetime
from colorama import Fore, init
import nmap

# Init colorama
init(autoreset=True)

print_lock = threading.Lock()
open_ports = []
q = Queue()


def log(msg, color=Fore.WHITE):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"{color}[{now}] {msg}")


def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except:
        log(f"Unable to resolve {target}", Fore.RED)
        return None


def banner_grab(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((ip, port))
        try:
            banner = sock.recv(1024).decode(errors='ignore').strip()
        except:
            banner = "No banner"
        sock.close()
        return banner
    except:
        return None


def scan_tcp(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = banner_grab(ip, port)
            with print_lock:
                log(f"{ip}:{port} OPEN - {banner}", Fore.GREEN)
                open_ports.append({'ip': ip, 'port': port, 'protocol': 'TCP', 'banner': banner})
        s.close()
    except:
        pass


def scan_udp(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b'', (ip, port))
        try:
            data, _ = s.recvfrom(1024)
            banner = data.decode(errors='ignore')
        except:
            banner = "No banner or no response"
        with print_lock:
            log(f"{ip}:{port} (UDP) Possibly OPEN - {banner}", Fore.BLUE)
            open_ports.append({'ip': ip, 'port': port, 'protocol': 'UDP', 'banner': banner})
        s.close()
    except:
        pass


def threader(ip, scan_type):
    while True:
        port = q.get()
        if scan_type == 'tcp':
            scan_tcp(ip, port)
        elif scan_type == 'udp':
            scan_udp(ip, port)
        q.task_done()


def scan_host(ip, port_range, scan_type='tcp', threads=100):
    for _ in range(threads):
        t = threading.Thread(target=threader, args=(ip, scan_type))
        t.daemon = True
        t.start()

    for port in range(port_range[0], port_range[1] + 1):
        q.put(port)

    q.join()


def os_fingerprint(ip):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments="-O")
        osmatch = scanner[ip]['osmatch']
        if osmatch:
            return osmatch[0]['name']
        return "OS Unknown"
    except Exception as e:
        return f"Error: {e}"


def save_results_csv(filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "port", "protocol", "banner", "os"])
        writer.writeheader()
        writer.writerows(open_ports)


def save_results_json(filename):
    with open(filename, 'w') as f:
        json.dump(open_ports, f, indent=4)


def load_targets_from_file(filename):
    targets = []
    with open(filename, 'r') as f:
        for line in f:
            target = line.strip()
            if target:
                ip = resolve_target(target)
                if ip:
                    targets.append((target, ip))
    return targets


def main():
    global open_ports
    log("--- Advanced CLI Port Scanner (Domain/IP Support) ---", Fore.YELLOW)

    input_type = input("Scan a (1) Single target, (2) Subnet, or (3) Load targets from file? [1/2/3]: ").strip()
    targets = []

    if input_type == '1':
        raw_target = input("Enter domain or IP: ").strip()
        ip = resolve_target(raw_target)
        if not ip:
            return
        targets.append((raw_target, ip))
    elif input_type == '2':
        subnet = input("Enter subnet (e.g. 192.168.1.0/24): ").strip()
        try:
            targets = [(str(ip), str(ip)) for ip in ipaddress.IPv4Network(subnet, strict=False)]
        except ValueError:
            log("Invalid subnet format!", Fore.RED)
            return
    elif input_type == '3':
        filepath = input("Enter file path: ").strip()
        if not os.path.exists(filepath):
            log("File not found!", Fore.RED)
            return
        targets = load_targets_from_file(filepath)
    else:
        log("Invalid option!", Fore.RED)
        return

    try:
        start_port = int(input("Start port: "))
        end_port = int(input("End port: "))
    except ValueError:
        log("Invalid port input.", Fore.RED)
        return

    scan_type = input("Scan type: (tcp/udp): ").strip().lower()
    if scan_type not in ['tcp', 'udp']:
        log("Invalid scan type. Use 'tcp' or 'udp'.", Fore.RED)
        return

    threads = int(input("Number of threads (default 100): ") or 100)
    do_os = input("Do OS fingerprinting? (y/n): ").strip().lower() == 'y'

    open_ports.clear()

    for host, ip in targets:
        log(f"Scanning {host} ({ip})", Fore.CYAN)
        scan_host(ip, (start_port, end_port), scan_type, threads)
        if do_os and scan_type == 'tcp':
            os_info = os_fingerprint(ip)
            log(f"[OS] {ip} - {os_info}", Fore.MAGENTA)
            for entry in open_ports:
                if entry['ip'] == ip:
                    entry['os'] = os_info

    log(f"Scan finished. {len(open_ports)} open ports found.", Fore.GREEN)

    if open_ports:
        if input("Save results? (y/n): ").strip().lower() == 'y':
            fmt = input("Format (json/csv): ").strip().lower()
            filename = input("Filename (without extension): ").strip()
            if fmt == 'json':
                save_results_json(filename + ".json")
                log(f"Saved to {filename}.json", Fore.GREEN)
            elif fmt == 'csv':
                save_results_csv(filename + ".csv")
                log(f"Saved to {filename}.csv", Fore.GREEN)


if __name__ == "__main__":
    main()
