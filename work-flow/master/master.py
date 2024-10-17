import dns.resolver
import dns.zone
import dns.query
import dns.reversename
import requests
from bs4 import BeautifulSoup
import threading
import argparse
import os
import socket

# Testing purpose
key = "mongodb+srv://admin:admin@nivash.nrt23.mongodb.net/?retryWrites=true&w=majority&appName=nivash"

subdomains_list = [
    "www", "mail", "ftp", "dev", "test", "staging", "api", "blog", "shop",
    "app", "dashboard", "support", "portal", "vpn", "images", "static",
    "files", "community", "forum", "store", "docs", "secure", "m", "data",
    "news", "feedback", "my", "checkout", "search", "admin", "beta",
    "status", "video", "download", "events", "jobs", "signup", "register",
    "analytics", "play", "cdn", "assets", "mailing", "tickets", "profile",
    "help", "wiki", "sandbox", "testbed", "resources", "partner", "secure",
    "mobile", "blogger", "oauth", "api2", "legacy"
]

# Perform a basic DNS query to get the A record from the DNS Server
def dns_lookup(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ip in result:
            print(f"[+] IP Address of {domain}: {ip}")
    except dns.resolver.NoAnswer:
        print(f"[-] No answer for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"[-] {domain} does not exist.")
    except Exception as e:
        print(f"[!] Error querying {domain}: {e}")

# Perform a reverse DNS lookup
def reverse_dns(ip_address):
    try:
        reversed_ip = dns.reversename.from_address(ip_address)
        result = dns.resolver.resolve(reversed_ip, 'PTR')
        for domain in result:
            print(f"[+] Domain for IP {ip_address}: {domain}")
    except Exception as e:
        print(f"[!] Reverse lookup failed for {ip_address}: {e}")

# Perform a DNS Zone Transfer attempt
def zone_transfer(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns = str(ns)
            print(f"[*] Trying zone transfer on {ns}...")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, lifetime=5))
                if zone:
                    print(f"[+] Zone transfer successful on {ns}!")
                    for name, node in zone.nodes.items():
                        print(f"  {name}.{domain}")
            except Exception as e:
                print(f"[-] Zone transfer failed on {ns}: {e}")
    except Exception as e:
        print(f"[!] Error during zone transfer attempt: {e}")

# Query for specific DNS record types
def query_records(domain, record_type):
    try:
        result = dns.resolver.resolve(domain, record_type)
        for record in result:
            print(f"[+] {record_type} Record for {domain}: {record}")
    except Exception as e:
        print(f"[!] Failed to get {record_type} record for {domain}: {e}")

# Detect wildcard DNS configurations
def wildcard_dns_detection(domain):
    try:
        wildcard_test = f"nonexistent-{os.urandom(4).hex()}.{domain}"
        result = dns.resolver.resolve(wildcard_test, 'A')
        if result:
            print(f"[+] Wildcard DNS detected for {domain}")
    except dns.resolver.NoAnswer:
        print(f"[-] No wildcard DNS for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"[-] {domain} does not have wildcard DNS.")
    except Exception as e:
        print(f"[!] Wildcard detection error: {e}")

def subdomain_enum(domain):
    print(f"[*] Starting subdomain enumeration on {domain}...")
    found_subdomains = []

    def query_subdomain(subd):
        subdomain = f"{subd}.{domain}"
        try:
            dns.resolver.resolve(subdomain, 'A')
            print(f"[+] Found subdomain: {subdomain}")
            found_subdomains.append(subdomain)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            print(f"[!] Error checking {subdomain}: {e}")

    threads = []
    for subd in subdomains_list:
        t = threading.Thread(target=query_subdomain, args=(subd,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if found_subdomains:
        print("\n[+] Subdomains found:")
        for subd in found_subdomains:
            print(f" - {subd}")
    else:
        print("[-] No subdomains found.")

def spider_url(url):
    print(f"[*] Crawling URLs from {url}...")
    try:
        res = requests.get(url)
    except Exception as e:
        print(f"[!] Request failed for {url}: {e}")
        return

    if res.status_code == 200:
        soup = BeautifulSoup(res.content, 'html.parser')
        a_tags = soup.find_all('a')
        links = set()
        for tag in a_tags:
            href = tag.get("href")  
            if href and href.startswith("http"):
                links.add(href)
        if links:
            print(f"[+] Found {len(links)} URLs:")
            for link in links:
                print(f" - {link}")
        else:
            print("[-] No URLs found.")
    else:
        print(f"[-] Received status code {res.status_code} from {url}")

def main():
    parser = argparse.ArgumentParser(description="Integrated InfoGrabber Tool")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-u", "--url", help="Target URL for web crawling")
    parser.add_argument("-r", "--reverse", help="IP address for reverse DNS lookup")
    parser.add_argument("-z", "--zonetransfer", help="Attempt DNS zone transfer", action="store_true")
    parser.add_argument("-t", "--recordtype", help="Query specific DNS record type (e.g., MX, TXT, NS)")
    parser.add_argument("-w", "--wildcard", help="Detect wildcard DNS", action="store_true")
    parser.add_argument("-s", "--subdomains", help="Perform subdomain enumeration", action="store_true")
    args = parser.parse_args()

    if args.domain:
        dns_lookup(args.domain)
        if args.zonetransfer:
            zone_transfer(args.domain)
        if args.recordtype:
            query_records(args.domain, args.recordtype)
        if args.wildcard:
            wildcard_dns_detection(args.domain)
        if args.subdomains:
            subdomain_enum(args.domain)

    if args.reverse:
        reverse_dns(args.reverse)

    if args.url:
        spider_url(args.url)

    if not any([args.domain, args.reverse, args.url]):
        parser.print_help()

if __name__ == "__main__":
    main()
