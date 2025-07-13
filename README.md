# Zone Transfer Vulnerability Scanner

A lightweight Python script to identify DNS zone transfer (AXFR) vulnerabilities in domain names. Quickly test if misconfigured DNS servers expose sensitive network information through unauthorized zone transfers.

## Features
- 🔍 Checks single domains or bulk lists from a file  
- ⚡️ Fast parallel DNS queries using multithreading  
- 📂 Outputs results to terminal or exportable report files  
- 🛠️ Configurable timeout settings and nameserver selection  
- ❌ Simple error handling for invalid domains/timeouts  

## Usage
```bash
# Single domain check
python zone_transfer.py -d example.com
```
```
# Bulk domain check
python zone_transfer.py -f domains.txt
```

```
# Save results to file
python zone_transfer.py -d example.com -o results.txt
```

## Sample Output
```bash
[*] Testing example.com
[!] VULNERABLE: ns1.example.com allows zone transfers!
[✓] Secure: backupns.example.com rejects zone transfers
```
## Installation
```
git clone https://github.com/anonhunter/zonetransfer
```
## Install dependencies:
```
pip install -r requirements.txt
```
## Requirements
Python 3.6+ <br>
dnspython library
