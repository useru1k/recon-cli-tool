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

dom = input("Enter the Domain: ")
domain_get(dom)
