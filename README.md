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
   git clone https://github.com/yourusername/recon-cli-tool.git
   cd recon-cli-tool
   ```
2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

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

### Working and learning on Pre-Commit hooks 


## Commands
* Get the Domain Records
```
python3 master.py -d example.com
```
* Get the open ports - port scanning.
```
python3 master.py -p example.com
```
* Get the subdomain of the target system.
```
python3 master.py -sd example.com
```
* Get the directory of the target system.
```
python3 master.py -dir example.com
```
* Get the SSL Certificate of the target System.
```
python3 master.py -ssl example.com
```



