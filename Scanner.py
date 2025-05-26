#!/usr/bin/env python3

import socket
import argparse
import sys
import os

TIMEOUT = 5

def parse_args():
    parser = argparse.ArgumentParser(
        description='Passive + semi-active OpenSSH 7.4p2 vulnerability scanner (no credentials required).'
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-H', '--host', help='Target host (IP or domain)')
    group.add_argument('-f', '--file', help='File containing list of target hosts (one per line)')
    return parser.parse_args()

def read_hosts_from_file(filepath):
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        sys.exit(1)
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def check_ssh_banner(host):
    try:
        with socket.create_connection((host, 22), timeout=TIMEOUT) as sock:
            banner = sock.recv(1024).decode(errors='ignore').strip()
            if banner:
                if "OpenSSH_7.4p2" in banner and "protocol 2.0" in banner.lower():
                    status = "VULNERABLE (Banner Match)"
                elif "OpenSSH" in banner:
                    status = "Non-target OpenSSH version"
                else:
                    status = "Unknown or non-OpenSSH SSH server"
            else:
                status = "No SSH banner received"
            return host, banner, status
    except Exception as e:
        return host, "N/A", f"Connection failed: {e}"

def main():
    args = parse_args()
    targets = []

    if args.host:
        targets.append(args.host)
    elif args.file:
        targets.extend(read_hosts_from_file(args.file))

    print("[*] Starting SSH vulnerability detection...")
    for target in targets:
        host, banner, result = check_ssh_banner(target)
        print(f"[+] Host: {host}")
        print(f"    Banner: {banner}")
        print(f"    Result: {result}")
        print("-" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(0)
