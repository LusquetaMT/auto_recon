# Importing modules

import argparse
import os
import subprocess
import datetime
from colorama import Fore, Style

parser = argparse.ArgumentParser(description='Vuln scan')
parser.add_argument('-d', '--domain', type=str, required=True, help='Domain to perform scan')
parser.add_argument('-p', '--prompt', type=bool, help='Force prompt')

args = parser.parse_args()

ports_scanned = 0

if not args.prompt:
    args.prompt = False

def GetCurrentTime():
    return Fore.RED + f"[{datetime.datetime.now().strftime('%H:%M:%S')}]"

NORMAL_TEXT = GetCurrentTime() + Fore.CYAN + Style.BRIGHT + " [*] " + Fore.RESET + Style.RESET_ALL
ACTIVE_TEXT = GetCurrentTime() +Fore.GREEN + Style.BRIGHT + " [+] " + Fore.RESET + Style.RESET_ALL
WARNING_TEXT = GetCurrentTime() + Fore.YELLOW + Style.BRIGHT + " [!] " + Fore.RESET + Style.RESET_ALL
BAD_TEXT = GetCurrentTime() + Fore.RED + Style.BRIGHT + " [-] " + Fore.RESET + Style.RESET_ALL

DIRECTORIES = ["Ports", "Screenshots"]

def cleanUrl(url):
    return url.replace("https://", "").replace("http://", "")

def extractOpenPorts(path):
    ports = []
    with open(path) as file:
        for line in file:
            line = line.strip()
            if "open" in line:
                port = line.replace("/", " ").split()[0]
                color = getColorByPort(port)
                ports.append(color + Style.BRIGHT + port + Fore.RESET + Style.RESET_ALL)
    if len(ports) == 0:
        return None
    else:
        return ",".join(ports)
    
def getColorByPort(port):
    port = int(port)
    color = Fore.WHITE + Style.BRIGHT
    if port == 22:
        color = Fore.CYAN
    elif port != 80 and port != 443:
        color = Fore.GREEN
    return color

def scan_ports(ports="1-1024", subdomains=args.domain + "/resolved_domains.txt", output_file=args.domain + "/Ports"):
    print(NORMAL_TEXT + "Scanning ports of alive hosts")
    if not prompt(): return
    try:
        with open(subdomains) as file:
            num_lines = sum(1 for _ in file)
            file.seek(0)

            for subdomain in file:
                subdomain = cleanUrl(subdomain).strip()

                os.system(f"nmap {subdomain} -p {ports} | grep 'open' > {output_file}/{subdomain} ")

                global ports_scanned
                ports_scanned += 1

                extracted = extractOpenPorts(f"{output_file}/{subdomain}")
                
                if extracted:
                    print(ACTIVE_TEXT + subdomain + f" | {extracted} | {Style.BRIGHT} {ports_scanned}/{num_lines} {Style.RESET_ALL}")
                else:
                    print(BAD_TEXT + subdomain + f" | {Style.BRIGHT} {ports_scanned}/{num_lines} {Style.RESET_ALL}")
    except KeyboardInterrupt:
        exit(0)

def create_directories(domain=args.domain):
    print(NORMAL_TEXT + "Creating directories")
    if not os.path.exists(domain):
        os.mkdir(domain)

    for folder in DIRECTORIES:
        if not os.path.exists(f"{domain}/{folder}"):
            os.mkdir(f"{domain}/{folder}")

def prompt():
    if args.prompt == True:
        cmd = input(WARNING_TEXT + "Continue? [y/n]").lower()
        if cmd == "n":
            return False
        elif cmd != "y":
            print(WARNING_TEXT + "Command not recognized! Skipping...")
            return False
    return True

def get_subdomains():
    print(NORMAL_TEXT + "Getting subdomains")
    if not prompt(): return

    os.system(f"amass enum -passive -silent -d {args.domain} -o amass.txt")
    os.system(f"subfinder -d {args.domain} -o subfinder.txt")
    os.system(f"assetfinder {args.domain} | anew assetfinder.txt")
    os.system(f"echo {args.domain} | dnsgen - | ~/tools/massdns/bin/massdns -r ~/tools/resolvers.txt -t AAAA -o J > dnsgen.txt")
    os.system("""cat dnsgen.txt | grep "NOERROR" | grep -o '"name":"[^"]*' | sed 's/"name":"//; s/\.$//; s/^-//' | anew resolved.txt""")
    os.system("cat amass.txt subfinder.txt assetfinder.txt resolved.txt | anew all_domains.txt")
    os.system(f"rm -rf amass.txt subfinder.txt assetfinder.txt dnsgen.txt resolved.txt")
    os.system(f"cat all_domains.txt | httprobe -prefer-https -t 2000 | anew {args.domain}/resolved_domains.txt")
    os.system(f"rm all_domains.txt")

def screenshot():
    print(NORMAL_TEXT + "Taking some screenshots for alive hosts")
    if not prompt(): return
    os.system(f"cat {args.domain}/resolved_domains.txt | aquatone -out {args.domain}/Screenshots/results")

create_directories()
get_subdomains()
screenshot()
scan_ports()