# StreamLine Recon CLI Tool 

  Recon CLI Tool is a versatile reconnaissance tool designed for cybersecurity professionals. It automates common information gathering tasks such as domain lookups, port scanning, subdomain enumeration, reverse DNS, WHOIS lookups, SSL certificate retrieval, GeoIP lookups, and more. The tool is developed in Python and is intended to provide quick, automated reconnaissance during cybersecurity assessments.

## Features

  * Domain Information: Fetch A, MX, NS, and TXT records for a given domain.
  * Port Scanning: Scan for open ports on a given IP address.
  * Subdomain Enumeration: Discover subdomains associated with a domain.
  * Directory Bruteforce: Brute force directories on a web server.
  * Reverse DNS Lookup: Get reverse DNS information for an IP address.
  * Shodan Integration: Perform Shodan lookups using an API key.
  * WHOIS Lookup: Retrieve WHOIS data for domain registration details.
  * SSL Certificate Information: Get detailed SSL certificate info for a domain.
  * HTTP Headers: Retrieve and display HTTP response headers from a server.
  * GeoIP Lookup: Perform a geographical lookup for an IP address.
  * Encoding/Decoding: Decode Base64, Base32, and ROT13 encoded strings.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/useru1k/recon-cli-tool.git
   cd recon-cli-tool
   ```
2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```
   
## Usage

The tool operates via the command line. Below are the available arguments and how to use them:

```
usage: master.py [-h] [-auto] [-d] [-p] [-sd] [-dir] [-ip] [-shodan] [-whois]
                 [-ssl] [-hdr] [-geo] [-bs64] [-rot13] [-bs32]

Recon CLI Tool : A tool or Script that makes gathering information about
targets using Basic Recon Process.

options:
  -h, --help            show this help message and exit
  -auto, --autoprocess  Under Construction
  -d , --domain         Target Domain
  -p , --portscan       Target IP for Port Scan
  -sd , --subdomain     Get the Subdomain of the Target System
  -dir , --directory    Get the Directory brute-forcing function
  -ip , --ip            IP address for reverse DNS lookup
  -shodan , --shodan_api_key 
                        Under Construction : API Key for Shodan
  -whois , --whois      Perform WHOIS lookup
  -ssl , --ssl          Retrieve SSL Certificate Info
  -hdr , --headers      Retrieve HTTP headers
  -geo , --geoip        Perform GeoIP lookup
  -bs64 , --base64      Decode the base64 String
  -rot13 , --rot_13     Decode the ROT13 String
  -bs32 , --base32      Decode the base322 String

```
### 1. **Auto Process Mode (Under Construction)**
   Initiates automatic processing (Currently under development).
   ```bash
   python master.py -auto
```
### 2. **Domain Information**
  Retrieves DNS information (A, MX, NS, TXT records) for a target domain.
   ```bash
  python master.py -d example.com
```
### 3. **Port Scanning**
  Performs a port scan on the provided target IP address.
   ```bash
  python master.py -p example.com
```
### 4. **Subdomain Enumeration**
Finds subdomains for the given domain.
```bash
  python master.py -sd example.com
```
### 5. **Directory Brute-Forcing**
  Performs directory brute-forcing on a given web server.
   ```bash
  python master.py -dir example.com
```
### 6. **SSL Certificate Information**
  Retrieves SSL certificate details for a domain.
   ```bash
  python master.py -ssl example.com
```
### 7. **HTTP Headers**
  Retrieves HTTP headers from a web server.
   ```bash
  python master.py -hdr example.com
```
### 8. **GeoIP Lookup**
  Perform a geographical lookup based on an IP address.
   ```bash
  python master.py -geo example.com
```
### 9. **Base64 Decoding**
  Decodes a Base64 encoded string.
   ```bash
  python master.py -bs64 <Base64_String>
```
### 10. **ROT13 Decoding**
  Decodes a ROT13 encoded string.
   ```bash
  python master.py -rot13 <ROT13_String>
```
### 11. **Base32 Decoding**
  Decodes a Base32 encoded string.
   ```bash
  python master.py -bs32 <Base32_String>
```

### Working and learning on Pre-Commit hooks 
