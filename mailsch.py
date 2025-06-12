import dns.resolver
import socket
import smtplib
import concurrent.futures
import json
import platform
from typing import List, Dict, Optional
from datetime import datetime
from flask import Flask, request, jsonify
import threading
import asyncio

app = Flask(__name__)

class MXChecker:
    def __init__(self, domain: str):
        self.domain = domain.lower().strip()
        self.mx_records = []
        self.results = {
            "domain": self.domain,
            "mx_records": [],
            "dns_records": {},
            "diagnostics": {},
            "timestamp": datetime.utcnow().isoformat()
        }
        self.blacklists = [
            "zen.spamhaus.org",
            "b.barracudacentral.org",
            "dnsbl.sorbs.net",
            "bl.spamcop.net",
            "dnsbl-1.uceprotect.net",
            "cbl.abuseat.org",
            "dnsbl.dronebl.org",
            "psbl.surriel.com",
            "rbl.efnetrbl.org"
        ]

    def get_mx_records(self) -> List[Dict]:
        """Retrieve MX records for the domain."""
        try:
            answers = dns.resolver.resolve(self.domain, 'MX')
            self.mx_records = sorted(
                [(str(record.exchange).strip().rstrip('.'), record.preference) for record in answers if str(record.exchange).strip()],
                key=lambda x: x[1]
            )
            unique_names = list(dict.fromkeys([record[0] for record in self.mx_records if record[0]]))
            self.results["mx_records"] = [{"host": host, "priority": pref} for host, pref in self.mx_records]
            return [{"host": host, "priority": self.mx_records[[r[0] for r in self.mx_records].index(host)][1]} for host in unique_names]
        except dns.resolver.NXDOMAIN:
            self.results["diagnostics"]["mx_error"] = f"No MX records found for {self.domain}"
            return []
        except Exception as e:
            self.results["diagnostics"]["mx_error"] = str(e)
            return []

    def check_reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for an IP."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return None

    def check_smtp(self, mx_host: str) -> Dict:
        """Test SMTP connectivity for an MX host."""
        result = {"status": "failed", "banner": None, "error": None}
        try:
            with smtplib.SMTP(mx_host, timeout=10) as smtp:
                smtp.helo("test.client")
                banner = smtp.ehlo()[1]
                if isinstance(banner, bytes):
                    banner = banner.decode('utf-8', errors='replace')
                result.update({"status": "success", "banner": banner, "error": None})
        except Exception as e:
            result["error"] = str(e)
        return result

    def check_blacklist(self, ip: str, blacklist: str) -> Dict:
        """Check if an IP is listed in a DNSBL."""
        result = {"blacklist": blacklist, "listed": False}
        try:
            query = '.'.join(reversed(ip.split('.'))) + '.' + blacklist
            dns.resolver.resolve(query, 'A')
            result["listed"] = True
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            result["error"] = str(e)
        return result

    def get_spf_record(self) -> Optional[str]:
        """Retrieve SPF record for the domain."""
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            for record in answers:
                if str(record).startswith('v=spf1'):
                    return str(record)
            return None
        except Exception:
            return None

    def get_dmarc_record(self) -> Optional[str]:
        """Retrieve DMARC record for the domain."""
        try:
            answers = dns.resolver.resolve(f'_dmarc.{self.domain}', 'TXT')
            for record in answers:
                if str(record).startswith('v=DMARC1'):
                    return str(record)
            return None
        except Exception:
            return None

    def get_dns_records(self, record_type: str) -> List[str]:
        """Retrieve DNS records of specified type (A, CNAME, TXT)."""
        try:
            answers = dns.resolver.resolve(self.domain, record_type)
            return [str(record) for record in answers]
        except Exception:
            return []

    def resolve_ip(self, host: str) -> Optional[str]:
        """Resolve hostname to IP address."""
        if not host or not isinstance(host, str):
            return None
        host = host.strip().rstrip('.')
        if len(host) > 253 or not host:
            return None
        try:
            return socket.gethostbyname(host)
        except (socket.gaierror, UnicodeError):
            return None

    def run_diagnostics(self, max_workers: int = 5) -> Dict:
        """Run all diagnostics concurrently for MX hosts and additional DNS checks."""
        unique_hosts = list(dict.fromkeys([record["host"] for record in self.results["mx_records"]]))
        self.results["diagnostics"]["unique_hosts"] = unique_hosts

        self.results["dns_records"]["A"] = self.get_dns_records("A")
        self.results["dns_records"]["CNAME"] = self.get_dns_records("CNAME")
        self.results["dns_records"]["TXT"] = self.get_dns_records("TXT")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            ip_futures = {executor.submit(self.resolve_ip, host): host for host in unique_hosts}
            for future in concurrent.futures.as_completed(ip_futures):
                host = ip_futures[future]
                ip = future.result()
                self.results["diagnostics"].setdefault(host, {})["ip"] = ip or "unresolved"

            for host in unique_hosts:
                ip = self.results["diagnostics"][host].get("ip")
                if ip and ip != "unresolved":
                    reverse_dns_future = executor.submit(self.check_reverse_dns, ip)
                    smtp_future = executor.submit(self.check_smtp, host)
                    blacklist_futures = [executor.submit(self.check_blacklist, ip, bl) for bl in self.blacklists]
                    futures = [reverse_dns_future, smtp_future] + blacklist_futures
                    results = [future.result() for future in concurrent.futures.as_completed(futures)]
                    self.results["diagnostics"][host]["reverse_dns"] = reverse_dns_future.result()
                    self.results["diagnostics"][host]["smtp"] = smtp_future.result()
                    self.results["diagnostics"][host]["blacklists"] = [f.result() for f in blacklist_futures]

        self.results["diagnostics"]["spf"] = self.get_spf_record()
        self.results["diagnostics"]["dmarc"] = self.get_dmarc_record()
        return self.results

    def display_results(self):
        """Display results in a formatted manner."""
        print(f"\nMX Server Check for {self.domain} ({self.results['timestamp']} UTC)")
        print("=" * 50)
        print("\nUnique MX Hosts (by priority):")
        for record in self.results["mx_records"]:
            print(f"Host: {record['host']}, Priority: {record['priority']}")

        print("\nDNS Records:")
        print(f"  A: {self.results['dns_records'].get('A', ['None'])}")
        print(f"  CNAME: {self.results['dns_records'].get('CNAME', ['None'])}")
        print(f"  TXT: {self.results['dns_records'].get('TXT', ['None'])}")

        print("\nDiagnostics:")
        for host in self.results["diagnostics"].get("unique_hosts", []):
            diag = self.results["diagnostics"].get(host, {})
            print(f"\n- {host}")
            print(f"  IP: {diag.get('ip', 'N/A')}")
            print(f"  Reverse DNS: {diag.get('reverse_dns', 'N/A')}")
            print(f"  SMTP Check: {diag.get('smtp', {}).get('status', 'N/A')}")
            if "smtp" in diag and diag["smtp"].get("error"):
                print(f"    SMTP Error: {diag['smtp']['error']}")
            print(f"  Blacklists:")
            for bl in diag.get("blacklists", []):
                if isinstance(bl, dict):
                    bl_name = bl.get('blacklist', 'Unknown')
                    bl_listed = bl.get('listed', False)
                    print(f"    {bl_name}: {bl_listed}")
                    if "error" in bl:
                        print(f"      Error: {bl['error']}")
                else:
                    print(f"    Invalid entry: {bl}")

        print("\nSPF Record:", self.results["diagnostics"].get("spf", "None"))
        print("DMARC Record:", self.results["diagnostics"].get("dmarc", "None"))
        print("=" * 50)

@app.route('/api/check', methods=['POST'])
def api_check_domain():
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required in JSON payload"}), 400
        domain = data['domain'].strip()
        if not domain:
            return jsonify({"error": "Domain cannot be empty"}), 400
        checker = MXChecker(domain)
        checker.get_mx_records()
        results = checker.run_diagnostics()
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({"status": "MailSentry API is running", "version": "1.0.0"})

def run_flask():
    """Run Flask server in the main thread."""
    app.run(host='0.0.0.0', port=5001, debug=True)

async def main():
    """Main function for terminal usage."""
    while True:
        domain = input("Enter domain to check (e.g., example.com): ").strip().lower()
        if domain and '.' in domain:
            break
        print("Error: Please enter a valid domain (e.g., example.com)")
    checker = MXChecker(domain)
    checker.get_mx_records()
    checker.run_diagnostics()
    checker.display_results()

def run_terminal():
    """Run the terminal interface in a separate thread."""
    if platform.system() == "Emscripten":
        asyncio.run(main())
    else:
        asyncio.run(main())

if __name__ == "__main__":
    # Start terminal interface in a separate thread
    terminal_thread = threading.Thread(target=run_terminal, daemon=True)
    terminal_thread.start()
    # Run Flask in the main thread
    try:
        run_flask()
    except KeyboardInterrupt:
        print("\nShutting down MailSentry...")
        exit(0)