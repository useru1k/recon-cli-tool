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
```
[bluecapture@bluecapture recon-cli-tool-main]$ python3 master.py -d google.com
[+] IP Address of google.com: 172.217.160.142

[+] A Records for google.com:
 - 172.217.160.142

[+] MX Records for google.com:
 - 10 smtp.google.com.

[+] NS Records for google.com:
 - ns1.google.com.
 - ns3.google.com.
 - ns2.google.com.
 - ns4.google.com.

[+] TXT Records for google.com:
 - "google-site-verification=4ibFUgB-wXLQ_S7vsXVomSTVamuOXBiVAzpR5IZ87D0"
 - "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8="
 - "v=spf1 include:_spf.google.com ~all"
 - "onetrust-domain-verification=de01ed21f2fa4d8781cbc3ffb89cf4ef"
 - "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB"
 - "cisco-ci-domain-verification=479146de172eb01ddee38b1a455ab9e8bb51542ddd7f1fa298557dfa7b22d963"
 - "docusign=1b0a6754-49b1-4db5-8540-d2c12664b289"
 - "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
 - "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ"
 - "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"
 - "apple-domain-verification=30afIBcvSuDV2PLX"
 - "google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o"
```


