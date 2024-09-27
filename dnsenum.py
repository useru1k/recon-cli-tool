import dns.resolver
import dns.zone
import dns.query
import dns.reversename
import socket
import argparse
import threading
import os

# Perform a basic DNS query for A record
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
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                for name, node in zone.nodes.items():
                    print(f"[+] Zone Transfer Record: {name}")
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
        wildcard_test = f"nonexistent.{domain}"
        result = dns.resolver.resolve(wildcard_test, 'A')
        if result:
            print(f"[+] Wildcard DNS detected for {domain}")
    except dns.resolver.NoAnswer:
        print(f"[-] No wildcard DNS for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"[-] {domain} does not have wildcard DNS.")
    except Exception as e:
        print(f"[!] Wildcard detection error: {e}")

# Brute-force subdomain enumeration using a wordlist
def subdomain_enum(domain, wordlist):
    if not os.path.exists(wordlist):
        print(f"[!] Wordlist {wordlist} does not exist!")
        return
    
    with open(wordlist, 'r') as file:
        subdomains = file.readlines()

    def query_subdomain(sub):
        sub = sub.strip()
        try:
            dns_lookup(f"{sub}.{domain}")
        except Exception as e:
            print(f"[-] Failed to resolve {sub}.{domain}")

    threads = []
    for sub in subdomains:
        t = threading.Thread(target=query_subdomain, args=(sub,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

# Main function to parse command-line arguments and trigger the desired action
def main():
    parser = argparse.ArgumentParser(description="DNS Enumeration Tool")
    parser.add_argument("-d", "--domain", help="Target domain", required=True)
    parser.add_argument("-r", "--reverse", help="IP address for reverse DNS lookup")
    parser.add_argument("-z", "--zonetransfer", help="Attempt DNS zone transfer", action="store_true")
    parser.add_argument("-t", "--recordtype", help="Query specific DNS record type (e.g., MX, TXT, NS)")
    parser.add_argument("-s", "--subdomains", help="Subdomain brute-force using a wordlist")
    parser.add_argument("-w", "--wildcard", help="Detect wildcard DNS", action="store_true")

    args = parser.parse_args()

    # Basic DNS Lookup
    dns_lookup(args.domain)

    # Reverse DNS Lookup
    if args.reverse:
        reverse_dns(args.reverse)

    # Zone Transfer
    if args.zonetransfer:
        zone_transfer(args.domain)

    # Query specific DNS record type
    if args.recordtype:
        query_records(args.domain, args.recordtype)

    # Wildcard DNS Detection
    if args.wildcard:
        wildcard_dns_detection(args.domain)

    # Subdomain Enumeration
    if args.subdomains:
        subdomain_enum(args.domain, args.subdomains)

if __name__ == "__main__":
    main()
