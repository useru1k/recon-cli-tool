import dns.resolver

subdomains_list = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
    "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3",
    "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old",
    "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure",
    "demo", "cp", "calendar", "wiki", "web", "media", "email", "images", "img", "www1",
    "intranet", "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4",
    "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my", "svn",
    "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover",
    "info", "apps", "download", "remote", "db", "forums", "store", "relay", "files",
    "newsletter", "app", "live", "owa", "en", "start", "sms", "office", "exchange", "ipv4",
    "mail3", "help", "blogs", "helpdesk", "web1", "home", "library", "ftp2", "ntp", "monitor",
    "login", "service", "correo", "www4", "moodle", "it", "gateway", "gw", "i", "stat",
    "stage", "ldap", "tv", "ssl", "web2", "ns5", "upload", "nagios", "smtp2", "online",
    "ad", "survey", "data", "radio", "extranet", "test2", "mssql", "dns3", "jobs", "services",
    "panel", "irc", "hosting", "cloud", "de", "gmail", "s", "bbs", "cs", "ww", "mrtg",
    "git", "image", "members", "poczta", "s1", "meet", "preview", "fr", "cloudflare-resolve-to",
    "dev2", "photo", "jabber", "legacy", "go", "es", "ssh", "redmine", "partner", "vps",
    "server1", "sv", "ns6", "webmail2", "av", "community", "cacti", "time", "sftp", "lib",
    "facebook", "www5", "smtp1", "feeds", "w", "games", "ts", "alumni", "dl", "s2",
    "phpmyadmin", "archive", "cn", "tools", "stream", "projects", "elearning", "im", "iphone",
    "control", "voip", "test1", "ws", "rss", "sp", "wwww", "vpn2", "jira", "list", "connect",
    "gallery", "billing", "mailer", "update", "pda", "game", "ns0", "testing", "sandbox",
    "job", "events", "dialin", "ml", "fb", "videos", "music", "a", "partners", "mailhost",
    "downloads", "reports", "ca", "router", "speedtest", "local", "training", "edu", "bugs",
    "manage", "s3", "status", "host2", "ww2", "marketing", "conference", "content", "network-ip",
    "broadcast-ip", "english", "catalog", "msoid", "mailadmin", "pay", "access", "streaming",
    "project", "t", "sso", "alpha", "photos", "staff", "e", "auth", "v2", "web5", "web3",
    "mail4", "devel", "post", "us", "images2", "master", "rt", "ftp1", "qa", "wp", "dns4",
    "www6", "ru", "student", "w3", "citrix", "trac", "doc", "img2", "css", "mx3", "adm",
    "web4", "hr", "mailserver", "travel", "sharepoint", "sport", "member", "bb", "agenda",
    "link", "server2", "vod", "uk", "fw", "promo", "vip", "noc", "design", "temp", "gate",
    "ns7", "file", "ms", "map", "cache", "painel", "js", "event", "mailing", "db1", "c",
    "auto", "img1", "vpn1", "business", "mirror", "share", "cdn2", "site", "maps", "tickets",
    "tracker", "domains", "club", "images1", "zimbra", "cvs", "b2b", "oa", "intra", "zabbix",
    "ns8", "assets", "main", "spam", "lms", "social", "faq", "feedback", "loopback", "groups",
    "m2", "cas", "loghost", "xml", "nl", "research", "art", "munin", "dev1", "gis", "sales",
    "images3", "report", "google", "idp", "cisco", "careers", "seo", "dc", "lab", "d", 
    "firewall", "fs", "eng", "ann", "mail01", "mantis", "v", "affiliates", "webconf", "track",
    "ticket", "pm", "db2", "b", "clients", "tech", "erp", "monitoring", "cdn1", "images4", 
    "payment", "origin", "client", "foto", "domain", "pt", "pma", "directory", "cc", "public",
    "finance", "ns11", "test3", "wordpress", "corp", "sslvpn", "cal", "mailman", "book", 
    "ip", "zeus", "ns10", "hermes", "storage", "free", "static1", "pbx", "banner", "mobil",
    "kb", "mail5", "direct", "ipfixe", "wifi", "development", "board", "ns01", "st", "reviews",
    "radius", "pro", "atlas", "links", "in", "oldmail", "register", "s4", "images6", 
    "static2", "id", "shopping", "drupal", "analytics", "m1", "images5", "images7", "img3",
    "mx01", "www7", "redirect", "sitebuilder", "smtp3", "adserver", "net", "user", "forms",
    "outlook", "press", "vc", "health", "work", "mb", "mm", "f", "pgsql", "jp", "sports",
    "preprod", "g", "p", "mdm", "ar", "lync", "market", "dbadmin", "barracuda", "affiliate",
    "mars", "users", "images8", "biblioteca", "mc", "ns12", "math", "ntp1", "web01", 
    "software", "pr", "jupiter", "labs", "linux", "sc", "love", "fax", "php", "lp", "tracking",
    "thumbs", "up", "tw"
]


# subdomains_list = [
#     "www", "mail", "ftp", "dev", "test", "staging", "api", "blog", "shop",
#     "app", "dashboard", "support", "portal", "vpn", "images", "static",
#     "files", "community", "forum", "store", "docs", "secure", "m", "data",
#     "news", "feedback", "my", "checkout", "search", "admin", "beta",
#     "status", "video", "download", "events", "jobs", "signup", "register",
#     "analytics", "play", "cdn", "assets", "mailing", "tickets", "profile",
#     "help", "wiki", "sandbox", "testbed", "resources", "partner", "secure",
#     "mobile", "blogger", "oauth", "api2", "legacy"
# ]


def check(domain):
    found_subdomains = []
    for subd in subdomains_list:
        subdomain = f"{subd}.{domain}"
        try:
            dns.resolver.resolve(subdomain, 'A')  # Specify 'A' to resolve A records address
            found_subdomains.append(subdomain)
            print(f"Found subdomain: {subdomain}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except Exception as e:
            print(f"Error checking {subdomain}: {e}")
    
    return found_subdomains

def main():
    domain = input("Enter the domain (without www or http): ")
    if not domain:
        print("Please enter a valid domain.")
        return
    
    print(f"Searching for subdomains of {domain}...")
    found_subdomains = check(domain)
    
    if not found_subdomains:
        print("No subdomains found.")
    else:
        print("These are the Subdomains found")
        # for subd in found_subdomains:
        #     print(subd)

if __name__ == '__main__':
    main()
