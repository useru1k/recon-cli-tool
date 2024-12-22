import os
import argparse
import dns.resolver
import socket
import concurrent.futures
import threading
# import whois
import ssl
import json
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()

sub = [
    "www", "mail", "ftp", "dev", "test", "staging", "api", "blog", "shop",
    "app", "dashboard", "support", "portal", "vpn", "images", "static",
    "files", "community", "forum", "store", "docs", "secure", "m", "data",
    "news", "feedback", "my", "checkout", "search", "admin", "beta",
    "status", "video", "download", "events", "jobs", "signup", "register",
    "analytics", "play", "cdn", "assets", "mailing", "tickets", "profile",
    "help", "wiki", "sandbox", "testbed", "resources", "partner", "secure",
    "mobile", "blogger", "oauth", "legacy"
]

directories_list = [
    "about", "account", "actions", "adapters", "agents", "alerts", "alias",
    "animations", "app", "applications", "archive", "artifacts", "auth",
    "automation", "binaries", "blueprints", "bookmarks", "bootstrap",
    "branding", "caches", "captchas", "certificates", "checks", "client",
    "clusters", "common", "components", "connections", "constants", "contexts",
    "controllers", "core", "crons", "cursors", "custom", "dashboard_assets",
    "db_backups", "debug", "deploy", "deployment", "dependencies", "descriptors",
    "devices", "distribution", "docs_assets", "editors", "emails", "encryption",
    "engine", "entries", "entities", "examples", "exports", "extensions",
    "extracts", "factories", "feeds", "filters", "fixtures", "flow", "forms",
    "framework", "functions", "generators", "graphics", "groups", "handlers",
    "hooks", "icons", "identity", "imports", "index", "init", "instances",
    "integrations", "interfaces", "ios", "json", "keys", "labs", "layers",
    "layouts", "licenses", "localization", "macros", "maps", "models",
    "network", "notifications", "objects", "operations", "orders", "outputs",
    "overrides", "packages", "pages", "panels", "patches", "permissions",
    "platform", "policies", "previews", "prototypes", "references", "regions",
    "roles", "routes", "rules", "samples", "seeds", "sessions", "shell",
    "shortcuts", "signatures", "snapshots", "solutions", "sources", "specs",
    "sql", "states", "status", "storage", "subscribers", "support", "tags",
    "tasks", "teams", "temp", "templates", "test_cases", "themes", "tickets",
    "tokens", "triggers", "types", "ui", "upload", "user_data", "utilities",
    "validators", "versions", "virtual", "volumes", "workspaces", "xmls", "zones"
]

def domain_get(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ip in result:
            console.print(f"[bold green][+] IP Address of {domain}:[/bold green] {ip}")
            # print(f"[+] IP Address of {domain}: {ip}")
    except Exception as e:
        console.print(f"[bold red][!] Error in querying {domain}: {e}[/bold red]")
        # print(f"[!] Error in Querying {domain} : {e}")

    record_types = ['A', 'MX', 'NS', 'TXT']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            console.print(f"\n[bold cyan][+] {record_type} Records for {domain}:[/bold cyan]")
            # print(f"\n[+] {record_type} Records for {domain}:")
            for rdata in answers:
                console.print(f"[bold blue] - {rdata}[/bold blue]")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            console.print(f"[bold yellow][!] No {record_type} records found for {domain}[/bold yellow]")
            # print(f"[!] No {record_type} records found for {domain}")
        except Exception as e:
            console.print(f"[bold red][!] Error retrieving {record_type} records: {e}[/bold red]")
            # print(f"[!] Error retrieving {record_type} records: {e}")

def scan_port(ip,port):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip,port))
            if result == 0:
                return port
    except socket.error:
        pass
    return None

# without the table forma
# def geoip_lookup(ip):
#     """Perform GeoIP lookup for an IP address."""
#     try:
#         response = requests.get(f"https://ipinfo.io/{ip}/json")
#         data = response.json()
#         print(f"\n[+] GeoIP Information for {ip}:")
#         print(f" - Location: {data['city']}, {data['region']}, {data['country']}")
#         print(f" - Org: {data['org']}")
#         print(f" - Latitude/Longitude: {data['loc']}")
#     except Exception as e:
#         print(f"[!] GeoIP Lookup failed: {e}")

def geoip_lookup(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()

        table = Table(title=f"GeoIP Information for {ip}")
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")

        table.add_row("Location", f"{data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}")
        table.add_row("Org", data.get('org', 'N/A'))
        table.add_row("Latitude/Longitude", data.get('loc', 'N/A'))

        console.print(table)
    except Exception as e:
        console.print(f"[bold red][!] GeoIP Lookup failed: {e}[/bold red]")

def portscan(ip,start_port=1,end_port=1024,max_threads=100):
    print(f"[+] Port Scanning on {ip}")
    open_port = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_port , ip , port) for port in range(start_port,end_port+1)]
        for future in concurrent.futures.as_completed(futures):
            port = future.result()
            if port is not None:
                print(f" [!] Port {port} is Open")
                open_port.append(port)
    if open_port:
        print("\n[+] Open ports: ",open_port)
    else:
        print("\n[!] No Open Ports Found")

def reverse_dns_lookup(ip):
    """Resolve an IP address back to a domain name."""
    try:
        hostname = socket.gethostbyaddr(ip)
        print(f"[+] Reverse DNS Lookup for {ip}: {hostname[0]}")
    except socket.herror:
        print(f"[!] No reverse DNS found for {ip}")
    except Exception as e:
        print(f"[!] Error performing reverse DNS lookup: {e}")

subdomains_list = [
    "auth", "auth2", "backup", "calendar", "careers", "catalog", "checkout2",
    "client", "cluster", "cms", "config", "connect", "contact", "crm", "db",
    "delivery", "digital", "directory", "dns", "education", "email", "embed",
    "enterprise", "enrollment", "feedback2", "finance", "forms", "game",
    "gateway", "geo", "git", "global", "go", "health", "host", "id", "identity",
    "internal", "inventory", "intranet", "labs", "legal", "library", "live",
    "location", "manage", "management", "maps", "media", "messages", "metrics",
    "monitor", "music", "myaccount", "node", "notifications", "office", "online",
    "order", "partners", "pay", "payments", "personal", "portal2", "price",
    "pricing", "prod", "products", "project", "proxy", "pub", "purchase",
    "qa", "queue", "read", "register2", "reports", "request", "reviews",
    "robot", "room", "sales", "scheduler", "school", "security", "services",
    "share", "social", "software", "solutions", "source", "stage", "start",
    "store2", "student", "survey", "system", "test2", "tools", "trade", "training",
    "upload", "user", "validate", "verification", "video2", "vpn2", "wallet",
    "weather", "web", "wholesale", "workflow", "zone" ,"www", "mail", "ftp", "dev", "test", "staging", "api", "blog", "shop",
    "app", "dashboard", "support", "portal", "vpn", "images", "static",
    "files", "community", "forum", "store", "docs", "secure", "m", "data",
    "news", "feedback", "my", "checkout", "search", "admin", "beta",
    "status", "video", "download", "events", "jobs", "signup", "register",
    "analytics", "play", "cdn", "assets", "mailing", "tickets", "profile",
    "help", "wiki", "sandbox", "testbed", "resources", "partner", "secure",
    "mobile", "blogger", "oauth", "api2", "legacy"
]

def subdomain_enum(domain):
    found_subdomains = []

    def query_subdomain(subd):
        subdomain = f"{subd}.{domain}"
        try:
            dns.resolver.resolve(subdomain, 'A')
            print(f"[+] Found subdomain: {subdomain}")
            found_subdomains.append(subdomain)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass

    threads = []
    for subd in subdomains_list:
        t = threading.Thread(target=query_subdomain, args=(subd,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    #print("\n[+] Subdomains found:")
    #for subd in found_subdomains:
    #    print(f" - {subd}")

# def ssl_certificate_info(domain):
#     """Retrieve SSL certificate details for a domain."""
#     try:
#         context = ssl.create_default_context()
#         with socket.create_connection((domain, 443)) as sock:
#             with context.wrap_socket(sock, server_hostname=domain) as ssock:
#                 cert = ssock.getpeercert()
#                 print(f"\n[+] SSL Certificate Info for {domain}:")
#                 print(f" - Issuer: {cert['issuer']}")
#                 print(f" - Valid From: {cert['notBefore']}")
#                 print(f" - Valid Until: {cert['notAfter']}")
#                 print(f" - Subject: {cert['subject']}")
#     except Exception as e:
#         print(f"[!] SSL Certificate Retrieval failed: {e}")

def ssl_certificate_info(domain):
    """Retrieve SSL certificate details for a domain."""
    try:
        # Create SSL context
        context = ssl.create_default_context()

        # Create socket connection to the domain
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Create a rich table to display SSL certificate information
                table = Table(title=f"\nSSL Certificate Info for {domain}")
                table.add_column("Field", style="cyan", no_wrap=True)
                table.add_column("Value", style="magenta")

                # Add rows to the table with the certificate information
                table.add_row("Issuer", str(cert.get('issuer', 'N/A')))
                table.add_row("Valid From", str(cert.get('notBefore', 'N/A')))
                table.add_row("Valid Until", str(cert.get('notAfter', 'N/A')))
                table.add_row("Subject", str(cert.get('subject', 'N/A')))

                # Print the table with the certificate details
                console.print(table)
    except Exception as e:
        console.print(f"[bold red][!] SSL Certificate Retrieval failed: {e}[/bold red]")

def directory_enum(target_url):
    """Enumerate directories on the target URL."""
    print(f"[+] Starting directory enumeration on {target_url}")
    found_directories = []

    def check_directory(directory):
        url = f"{target_url}/{directory}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                print(f"[+] Found directory: {url}")
                found_directories.append(url)
        except requests.exceptions.RequestException:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(check_directory, directories_list)

    if found_directories:
        print("\n[+] Directories found:")
        for dir in found_directories:
            print(f" - {dir}")
    else:
        print("\n[!] No directories found")

def whois_lookup(domain):
    """Perform WHOIS lookup for a domain."""
    try:
        w = whois.whois(domain)
        print(f"\n[+] WHOIS Information for {domain}:")
        print(f" - Registrar: {w.registrar}")
        print(f" - Creation Date: {w.creation_date}")
        print(f" - Expiration Date: {w.expiration_date}")
        print(f" - Name Servers: {w.name_servers}")
    except Exception as e:
        print(f"[!] WHOIS Lookup failed: {e}")

def http_headers(url):
    """Retrieve HTTP headers from a URL."""
    try:
        response = requests.head(url, timeout=5)
        print(f"\n[+] HTTP Headers for {url}:")
        for header, value in response.headers.items():
            print(f" - {header}: {value}")
    except Exception as e:
        print(f"[!] HTTP Headers retrieval failed for {url}: {e}")

BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def decode_base64(data):
    data = data.rstrip('=')

    # Convert base64 string to binary
    binary_string = ''.join(format(BASE64_ALPHABET.index(c), '06b') for c in data)

    # Group binary string into 8-bit chunks and convert to characters
    decoded_string = ''.join(
        chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8)
    )

    console.print(f"[bold green][!] Decode String : [/bold green] [bold blue]{decoded_string}[/bold blue]")


#def decode_rot13(data):
    # ROT13 works by shifting each letter 13 positions
    #decoded_string = ''.join(
        
        #chr(((ord(c) - ord('a') + 13) % 26) + ord('a')) if 'a' <= c <= 'z' else
        #chr(((ord(c) - ord('A') + 13) % 26) + ord('A')) if 'A' <= c <= 'Z' else c
        #for c in data
    #)

    #console.print(f"[bold magenta][+] Decoded ROT13 String:[/bold magenta] [bold blue]{decoded_string}[/bold blue]")


def decode_rot13(cipher_text):
    for rot in range(1, 26):
        decoded_text = ""
        # Loop over each character in the cipher text
        for c in cipher_text:
            # Check if the character is a letter
            if c.isalpha():
                # Determine the ASCII offset based on whether the letter is uppercase or lowercase
                if c.isupper():
                    ascii_offset = 65
                else:
                    ascii_offset = 97
                # Convert the character to its ASCII code
                c_code = ord(c)
                # Determine the new ASCII code by applying the ROT value
                new_c_code = (c_code - ascii_offset + rot) % 26 + ascii_offset
                # Convert the new ASCII code back to a character
                new_c = chr(new_c_code)
                decoded_text += new_c
            else:
                # If the character is not a letter, add it to the decoded text as is
                decoded_text += c
        # Print the decoded text for the current ROT value
        print(f"ROT{rot:02d}   : {decoded_text}")

def decode_base32(data):
    data = data.rstrip('=')

    # Convert base32 string to binary
    binary_string = ''.join(format(BASE32_ALPHABET.index(c), '05b') for c in data)

    # Group binary string into 8-bit chunks and convert to characters
    decoded_string = ''.join(
        chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8)
    )
    console.print(f"[bold green][!] Decode String : [/bold green] [bold blue]{decoded_string}[/bold blue]")

# Getting a Subdomain as without direct invlove the 
def passive_sources_shodan(domain, api_key):
    print(f"\n[+] Querying Shodan for subdomains of {domain}")
    subdomains = set()
    url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            for subdomain in data.get('subdomains', []):
                full_subdomain = f"{subdomain}.{domain}"
                subdomains.add(full_subdomain)
                print(f"[+] Found subdomain via Shodan: {full_subdomain}")
        else:
            print(f"[!] Shodan API request failed with status code {response.status_code}")
    except Exception as e:
        print(f"[!] Error querying Shodan API: {e}")
    return list(subdomains)

def main():
    parser = argparse.ArgumentParser(description = "Recon CLI Tool : \n A tool or Script that makes gathering information about targets using Basic Recon Process. ")
    parser.add_argument("-auto","--autoprocess",action = "store_true",help="Under Construction")
    parser.add_argument("-d","--domain",help = "Target Domain", metavar="")
    parser.add_argument("-p","--portscan",help = "Target IP for Port Scan",metavar="")
    parser.add_argument("-sd","--subdomain",help = "Get the Subdomain of the Target System",metavar="")
    parser.add_argument("-dir","--directory",help = "Get the Directory brute-forcing function",metavar="")
    parser.add_argument("-ip", "--ip", help="IP address for reverse DNS lookup", metavar="")
    parser.add_argument("-shodan", "--shodan_api_key", help="Under Construction : API Key for Shodan", metavar="")
    parser.add_argument("-whois", "--whois", help="Perform WHOIS lookup", metavar="")
    parser.add_argument("-ssl", "--ssl", help="Retrieve SSL Certificate Info", metavar="")
    parser.add_argument("-hdr", "--headers", help="Retrieve HTTP headers", metavar="")
    parser.add_argument("-geo", "--geoip", help="Perform GeoIP lookup", metavar="")
    parser.add_argument("-bs64", "--base64", help="Decode the base64 String", metavar="")
    parser.add_argument("-rot13", "--rot_13", help="Decode the ROT13 String", metavar="")
    parser.add_argument("-bs32", "--base32", help="Decode the base322 String", metavar="")


    args = parser.parse_args()

    if len(vars(args)) == 0 or not any(vars(args).values()):
        parser.print_help()

    if args.autoprocess:
        if args.domain:
            domain_get(args.domain)
        if args.portscan:
            portscan(args.portscan)
        if args.subdomain:
            subdomain_enum(args.subdomain)
        if args.directory:
            directory_enum(args.directory)
        if args.ip:
            print(f"\n[+] Performing Reverse DNS Lookup for {args.ip}")
            reverse_dns_lookup(args.ip)
        if args.whois:
            whois_lookup(args.whois)
        if args.ssl:
            ssl_certificate_info(args.ssl)
        if args.headers:
            http_headers(args.headers)
        if args.geoip:
            geoip_lookup(args.geoip)
    else:
        if args.domain:
            domain_get(args.domain)
        if args.portscan:
            portscan(args.portscan)
        if args.subdomain:
            subdomain_enum(args.subdomain)
        if args.directory:
            directory_enum(args.directory)
        if args.ip:
            print(f"\n[+] Performing Reverse DNS Lookup for {args.ip}")
            reverse_dns_lookup(args.ip)
        if args.whois:
            whois_lookup(args.whois)
        if args.ssl:
            ssl_certificate_info(args.ssl)
        if args.headers:
            http_headers(args.headers)
        if args.geoip:
            geoip_lookup(args.geoip)
        if args.base64:
            console.print(f"[bold cyan][+] Performing Base64 Decoding [/bold cyan]: {args.base64}")
            decode_base64(args.base64)
        if args.rot_13:
            decode_rot13(args.rot_13)
        if args.base32:
            console.print(f"[bold cyan][+] Performing Base64 Decoding [/bold cyan]: {args.base32}")
            decode_base32(args.base32)

if __name__ == "__main__":
    main()
