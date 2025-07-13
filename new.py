import dns.resolver
import dns.query
import dns.zone
import dns.exception
import time
import sys
import argparse

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
ENDC = '\033[0m'
BOLD = '\033[1m'
PURPLE = '\033[95m'

def show_banner():
    banner = f"""
{PURPLE}{BOLD}
                                                                                                                       
@@@@@@@@   @@@@@@   @@@  @@@  @@@@@@@@  @@@@@@@  @@@@@@@    @@@@@@   @@@  @@@   @@@@@@   @@@@@@@@  @@@@@@@@  @@@@@@@   
@@@@@@@@  @@@@@@@@  @@@@ @@@  @@@@@@@@  @@@@@@@  @@@@@@@@  @@@@@@@@  @@@@ @@@  @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@@@@@  
     @@!  @@!  @@@  @@!@!@@@  @@!         @@!    @@!  @@@  @@!  @@@  @@!@!@@@  !@@       @@!       @@!       @@!  @@@  
    !@!   !@!  @!@  !@!!@!@!  !@!         !@!    !@!  @!@  !@!  @!@  !@!!@!@!  !@!       !@!       !@!       !@!  @!@  
   @!!    @!@  !@!  @!@ !!@!  @!!!:!      @!!    @!@!!@!   @!@!@!@!  @!@ !!@!  !!@@!!    @!!!:!    @!!!:!    @!@!!@!   
  !!!     !@!  !!!  !@!  !!!  !!!!!:      !!!    !!@!@!    !!!@!!!!  !@!  !!!   !!@!!!   !!!!!:    !!!!!:    !!@!@!    
 !!:      !!:  !!!  !!:  !!!  !!:         !!:    !!: :!!   !!:  !!!  !!:  !!!       !:!  !!:       !!:       !!: :!!   
:!:       :!:  !:!  :!:  !:!  :!:         :!:    :!:  !:!  :!:  !:!  :!:  !:!      !:!   :!:       :!:       :!:  !:!  
 :: ::::  ::::: ::   ::   ::   :: ::::     ::    ::   :::  ::   :::   ::   ::  :::: ::    ::        :: ::::  ::   :::  
: :: : :   : :  :   ::    :   : :: ::      :      :   : :   :   : :  ::    :   :: : :     :        : :: ::    :   : :  
                                                                                                                       
  DNS Zone Transfer Tester (AXFR)
  Author: Sharik Khan (Anon Hunter)
{ENDC}
"""
    print(banner)

def check_zone_transfer(domain):
    vulnerable = False
    try:
        # Get authoritative nameservers
        answers = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(rdata.target).rstrip('.') for rdata in answers]

        print(f"\n{BOLD}[+] Checking domain: {domain}{ENDC}")
        print(f" Found nameservers: {', '.join(nameservers)}")

        for ns in nameservers:
            print(f"\n Trying AXFR on {ns}...")
            try:
                # Resolve nameserver to IP
                ns_ip = str(dns.resolver.resolve(ns, 'A')[0])
                print(f" Nameserver IP: {ns_ip}")
                
                # Try zone transfer
                try:
                    # First try with domain name
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
                except:
                    # Fallback to IP address
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                
                names = zone.nodes.keys()
                vulnerable = True
                print(f"{GREEN}{BOLD} [!] VULNERABLE! Zone transfer successful on {ns}{ENDC}")
                print(f" Records found ({len(names)}):")
                
                # Print only the first 10 records to avoid flooding
                for i, n in enumerate(names):
                    if i < 10:
                        print(f"  {n}.{domain}")
                    else:
                        print(f"  ... and {len(names) - 10} more records")
                        break
                        
            except dns.exception.Timeout:
                print(f"{YELLOW} [-] Timeout occurred while trying {ns}{ENDC}")
            except dns.xfr.TransferError as e:
                print(f"{YELLOW} [-] Zone transfer refused by {ns}: {str(e)}{ENDC}")
            except dns.resolver.NoAnswer:
                print(f"{YELLOW} [-] No answer received from {ns}{ENDC}")
            except Exception as e:
                print(f"{RED} [-] Unexpected error with {ns}: {str(e)}{ENDC}")
            
            # Add small delay between attempts
            time.sleep(0.5)
            
        return vulnerable

    except dns.resolver.NoNameservers:
        print(f"{RED}[-] No nameservers found for {domain}{ENDC}")
    except dns.resolver.NXDOMAIN:
        print(f"{RED}[-] Domain {domain} does not exist{ENDC}")
    except dns.exception.DNSException as e:
        print(f"{RED}[-] DNS error occurred for {domain}: {str(e)}{ENDC}")
    except Exception as e:
        print(f"{RED}[-] General error processing {domain}: {str(e)}{ENDC}")
    
    return False

def read_domains_from_file(filename):
    domains = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                domain = line.strip()
                if domain and not domain.startswith('#'):  # Skip empty lines and comments
                    domains.append(domain)
        return domains
    except FileNotFoundError:
        print(f"{RED}[!] Error: File '{filename}' not found.{ENDC}")
        return []
    except Exception as e:
        print(f"{RED}[!] Error reading file: {str(e)}{ENDC}")
        return []

def save_vulnerable_domains(vulnerable_list, filename="vuln.txt"):
    try:
        with open(filename, 'w') as f:
            for domain in vulnerable_list:
                f.write(domain + '\n')
        print(f"\n{GREEN}{BOLD}[+] Saved {len(vulnerable_list)} vulnerable domains to {filename}{ENDC}")
    except Exception as e:
        print(f"{RED}[!] Failed to save vulnerable domains: {str(e)}{ENDC}")

if __name__ == "__main__":
    show_banner()  # Display author information
    
    parser = argparse.ArgumentParser(description='Check DNS zone transfer vulnerability (AXFR)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Single domain to check')
    group.add_argument('-f', '--file', help='File containing list of domains')
    parser.add_argument('-o', '--output', default='vuln.txt', help='Output file for vulnerable domains (default: vuln.txt)')
    
    args = parser.parse_args()

    domains = []
    if args.domain:
        domains = [args.domain]
    elif args.file:
        domains = read_domains_from_file(args.file)

    if not domains:
        print(f"{RED}No valid domains found.{ENDC}")
        sys.exit(1)

    print(f"{BOLD}Loaded {len(domains)} domains to test{ENDC}")
    
    vulnerable_domains = []
    
    for domain in domains:
        if check_zone_transfer(domain):
            vulnerable_domains.append(domain)
    
    # Print summary
    print(f"\n{BOLD}--- Test Summary ---{ENDC}")
    print(f"Total domains tested: {len(domains)}")
    if vulnerable_domains:
        print(f"{GREEN}{BOLD}Vulnerable domains found ({len(vulnerable_domains)}):{ENDC}")
        for domain in vulnerable_domains:
            print(f"  {GREEN}• {domain}{ENDC}")
    else:
        print(f"{YELLOW}No vulnerable domains found{ENDC}")
    
    # Save vulnerable domains to file
    if vulnerable_domains:
        save_vulnerable_domains(vulnerable_domains, args.output)
