#!/usr/bin/env python3
"""
Simple network scanner:
1) Ping every address in a CIDR (concurrently).
2) For hosts that respond, run a TCP port scan on specified ports (concurrently).
3) Log results to CSV.

Usage example:
    python net_scan.py --network 192.168.1.0/24 --ports 22,80,443,8000-8010 --workers 200 --outfile results.csv
"""
import argparse
import csv
import ipaddress
import platform
import subprocess
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Tuple

# ---------- Utilities ----------
SYSTEM = platform.system()

def ping_host(ip: str, timeout_ms: int = 1000) -> bool:
    """
    Ping an IP once. Cross-platform best-effort using the system ping command.
    Returns True if ping succeeds (returncode == 0).
    """
    if SYSTEM == "Windows":
        args = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif SYSTEM == "Darwin":
        # macOS (BSD ping) uses -W in milliseconds for timeout (available on modern macOS)
        args = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        # Linux: -c 1 (count), -W timeout in seconds (integer), convert ms to seconds rounding up
        w_seconds = max(1, int((timeout_ms + 999) // 1000))
        args = ["ping", "-c", "1", "-W", str(w_seconds), ip]

    try:
        # suppress output
        completed = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return completed.returncode == 0
    except Exception:
        return False

def parse_ports(port_arg: str) -> List[int]:
    """
    Parse a port argument like "22,80,443,8000-8010" into a sorted list of ints.
    """
    ports = set()
    for piece in port_arg.split(","):
        piece = piece.strip()
        if not piece:
            continue
        if "-" in piece:
            start, end = piece.split("-", 1)
            start, end = int(start), int(end)
            for p in range(start, end + 1):
                ports.add(p)
        else:
            ports.add(int(piece))
    return sorted(p for p in ports if 1 <= p <= 65535)

def scan_port(ip: str, port: int, timeout: float = 0.5) -> Tuple[int, bool]:
    """
    Try to connect to ip:port. Returns (port, True/False).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((ip, port))
            return (port, res == 0)
    except Exception:
        return (port, False)

# ---------- Main scanning logic ----------
def ping_sweep(network_cidr: str, workers: int = 200, timeout_ms: int = 1000) -> List[str]:
    """
    Ping every address in the CIDR (skips network & broadcast for IPv4).
    Returns list of responsive IP strings.
    """
    net = ipaddress.ip_network(network_cidr, strict=False)
    ips = [str(ip) for ip in net.hosts()]  # hosts() skips network & broadcast
    responsive = []

    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {exe.submit(ping_host, ip, timeout_ms): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                ok = fut.result()
            except Exception:
                ok = False
            if ok:
                responsive.append(ip)
                print(f"[PING] {ip} is up")
    return responsive

def port_scan_hosts(hosts: List[str], ports: List[int], workers: int = 200, timeout: float = 0.5) -> dict:
    """
    For each host, scan the provided ports. Returns mapping host -> list of open ports.
    """
    results = {host: [] for host in hosts}
    # We'll create a pool and submit tasks for host/port pairs.
    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {}
        for host in hosts:
            for port in ports:
                futures[exe.submit(scan_port, host, port, timeout)] = (host, port)

        for fut in as_completed(futures):
            host, port = futures[fut]
            try:
                p, is_open = fut.result()
            except Exception:
                is_open = False
            if is_open:
                results[host].append(port)
                print(f"[PORT] {host}:{port} OPEN")
    return results

def write_csv(outfile: str, scan_map: dict):
    """
    Writes: ip, open_ports(comma-separated), scanned_at
    """
    scanned_at = datetime.utcnow().isoformat() + "Z"
    with open(outfile, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "open_ports", "scanned_at"])
        for ip, ports in scan_map.items():
            writer.writerow([ip, ",".join(map(str, sorted(ports))), scanned_at])

# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser(description="Ping sweep + mini nmap port scanner (simple)")
    p.add_argument("--network", "-n", required=True, help="Network in CIDR form, e.g. 192.168.1.0/24")
    p.add_argument("--ports", "-p", default="22,80,443", help="Ports (csv and ranges): 22,80,8000-8010")
    p.add_argument("--workers", "-w", type=int, default=200, help="Concurrent worker threads")
    p.add_argument("--timeout-ms", type=int, default=1000, help="Ping timeout in milliseconds")
    p.add_argument("--port-timeout", type=float, default=0.5, help="Socket timeout per port in seconds")
    p.add_argument("--outfile", "-o", default="scan_results.csv", help="CSV output file")
    args = p.parse_args()

    ports = parse_ports(args.ports)
    print(f"Scanning network {args.network} with {args.workers} workers.")
    print(f"Ports to scan (per responsive host): {ports}")

    responsive = ping_sweep(args.network, workers=args.workers, timeout_ms=args.timeout_ms)
    print(f"\nPing sweep complete. {len(responsive)} hosts responded.\n")

    if not responsive:
        print("No hosts up — exiting.")
        return

    scan_map = port_scan_hosts(responsive, ports, workers=args.workers, timeout=args.port_timeout)
    write_csv(args.outfile, scan_map)
    print(f"\nScan complete. Results written to {args.outfile}")

if __name__ == "__main__":
    main()
