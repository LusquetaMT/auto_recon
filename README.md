# auto_recon
Scans a specified domain

- Alive subdomains
- Probe for alive hosts
- Port scanning
- Crawling (gau, waybackmachine, katana)
- Screenshot alive hosts

# Instructions

```ssh
python3 auto_recon.py -d <target_domain> -p <prompt True or False>
```

# Required tools

[nmap](https://nmap.org)
[gau](https://github.com/lc/gau)
[katana](https://github.com/projectdiscovery/katana)
[waybackurls](https://github.com/tomnomnom/waybackurls)
[anew](https://github.com/tomnomnom/anew)
[amass](https://github.com/owasp-amass/amass)
[subfinder](https://github.com/projectdiscovery/subfinder)
[assetfinder](https://github.com/tomnomnom/assetfinder)
[massdns](https://github.com/blechschmidt/massdns)
[dnsgen](https://github.com/ProjectAnte/dnsgen)
[httprobe](https://github.com/tomnomnom/httprobe)
[aquatone](https://github.com/michenriksen/aquatone)
