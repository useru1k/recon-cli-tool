# StreamLine Recon CLI Tool 

Creating a tool that makes gathering information about targets  and easier by automating the reconnaissance process with a straightforward command-line interface.
- Subdomain , DNS , Port Scanning etc..

* Right Now the Help stream (Need to Update more features)

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



