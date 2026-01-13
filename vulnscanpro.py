#!/usr/bin/env python3
"""
vulnscanpro -  Vulnerability Scanner
Saran
"""

import requests
import sys
import argparse
import json
import time
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

class SaranVulnScanPro:
    def __init__(self, target_url, threads=10, timeout=5):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.threads = threads
        self.timeout = timeout
        self.findings = []
        self.host = urlparse(target_url).netloc

    def print_banner(self):
        print(f"""
{Colors.BOLD}{Colors.CYAN}
   _____ _           _ _____ _____  _    _ 
  / ____| |         | |  __ \\_   _\\| |  | |
 | |  __| |__   __ _| | |__) | | | | |  | |
 | | |_ | '_ \\ / _` | |  ___/  | | | |  | |
 | |__| | | | | (_| | | |      | | | |__| |
  \\_____|_| |_|\\__,_|_|_|      |_|  \\____/ 
{Colors.END}
{Colors.YELLOW}Web Vulnerability Scanner{Colors.END}
{Colors.PURPLE}Saran{Colors.END}
        """)

    def get_service_name(self, port):
        services = {
            80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 3389: "RDP",
            445: "SMB", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL"
        }
        return services.get(port, f"TCP-{port}")

    def port_scan(self):
        ports = [80, 443, 8080, 8443, 3389, 445, 22, 21, 3306, 1433, 8000, 3000]
        print(f"{Colors.CYAN}[*] Scanning ports on {self.host}...{Colors.END}")
        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((self.host, port)) == 0:
                    open_ports.append(port)
                    service = self.get_service_name(port)
                    print(f"{Colors.GREEN}[+] PORT {port:>5} OPEN | {service}{Colors.END}")
                sock.close()
            except:
                pass

        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(scan_port, ports)

        if open_ports:
            self.findings.append({
                "type": "Open Ports",
                "ports": open_ports,
                "severity": "HIGH"
            })

    def fetch_xss_payloads(self):
        try:
            url = "https://raw.githubusercontent.com/coffinxp/loxs/main/payloads/xss.txt"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                payloads = [line.strip() for line in resp.text.splitlines() if line.strip()][:10]
                print(f"{Colors.GREEN}[+] Loaded coffinxp/loxs XSS payloads{Colors.END}")
                return payloads
        except:
            pass
        return ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]

    def test_xss(self, url):
        xss_payloads = self.fetch_xss_payloads()
        parsed = urlparse(url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)
        print(f"{Colors.CYAN}[*] Testing XSS on {len(params)} parameters...{Colors.END}")

        for param in params:
            original = params[param][0]
            for payload in xss_payloads:
                test_url = url.replace(f"{param}={original}", f"{param}={urllib.parse.quote(payload)}")
                try:
                    resp = self.session.get(test_url, timeout=self.timeout)
                    if payload in resp.text or 'alert' in resp.text:
                        self.findings.append({
                            "type": "XSS (coffinxp/loxs)",
                            "url": test_url,
                            "parameter": param,
                            "severity": "HIGH"
                        })
                        print(f"{Colors.RED}[!] XSS FOUND: {param}{Colors.END}")
                        return
                except:
                    pass

    def fetch_coffinxp_directories(self):
        try:
            url = "https://raw.githubusercontent.com/coffinxp/payloads/main/onelistforallmicro.txt"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                dirs = [line.strip() for line in resp.text.splitlines() if line.strip()][:50]
                print(f"{Colors.GREEN}[+] Loaded coffinxp directories{Colors.END}")
                return dirs
        except:
            pass
        return ["admin", "wp-admin", "login", "api", "config", "backup"]

    def directory_scan(self):
        directories = self.fetch_coffinxp_directories()
        print(f"{Colors.CYAN}[*] Scanning {len(directories)} directories...{Colors.END}")

        def test_dir(directory):
            test_url = urljoin(self.target_url.rstrip('/') + '/', directory)
            try:
                resp = self.session.get(test_url, timeout=self.timeout)
                if resp.status_code == 200 and len(resp.content) > 200:
                    print(f"{Colors.GREEN}[+] DIR FOUND: {test_url}{Colors.END}")
                    self.findings.append({
                        "type": "Directory (coffinxp)",
                        "url": test_url,
                        "severity": "MEDIUM"
                    })
            except:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test_dir, directories)

    def sensitive_files(self):
        files = ["/robots.txt", "/.env", "/config.php", "/wp-config.php"]
        print(f"{Colors.CYAN}[*] Checking sensitive files...{Colors.END}")
        for file_path in files:
            test_url = urljoin(self.target_url, file_path)
            try:
                resp = self.session.get(test_url, timeout=self.timeout)
                if resp.status_code == 200:
                    print(f"{Colors.RED}[!] SENSITIVE FILE: {test_url}{Colors.END}")
                    self.findings.append({
                        "type": "Sensitive File",
                        "url": test_url,
                        "severity": "HIGH"
                    })
            except:
                pass

    def security_headers(self):
        print(f"{Colors.CYAN}[*] Checking security headers...{Colors.END}")
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            missing = []
            required = ['X-Frame-Options', 'Strict-Transport-Security']
            for header in required:
                if header not in resp.headers:
                    missing.append(header)
            if missing:
                print(f"{Colors.YELLOW}[!] Missing headers: {', '.join(missing)}{Colors.END}")
                self.findings.append({
                    "type": "Missing Headers",
                    "headers": missing,
                    "severity": "MEDIUM"
                })
        except:
            pass

    def generate_report(self):
        report = {
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "scanner": "vulnscanpro",
            "findings": self.findings,
            "total_findings": len(self.findings)
        }
        print(f"\n{Colors.BOLD}{Colors.GREEN}SCAN COMPLETE: {len(self.findings)} findings{Colors.END}")
        
        filename = f"scan_report_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"{Colors.GREEN}[+] Report saved: {filename}{Colors.END}")
        return report

    def run(self):
        self.print_banner()
        print(f"{Colors.BLUE}[*] Target: {self.target_url}{Colors.END}\n")
        self.port_scan()
        self.security_headers()
        self.test_xss(self.target_url)
        self.directory_scan()
        self.sensitive_files()
        return self.generate_report()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vulnscanpro -  Web Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout")
    args = parser.parse_args()
    
    scanner = SaranVulnScanPro(args.url, args.threads, args.timeout)
    scanner.run()

