# CruxEnum 
CruxEnum is a quick and simple enumeration script I wrote to automate CTF initial enumeration. The script creates an organized folder structure, then runs nmap, ffuf, wfuz, and nikto. All files are output in markdown.  
The folder structre is designed for use with Obsidian. Create a vault using the folder that ce.py is stored in. When you run the script, it will make a folder for the box you are doing, as well as a subfolder named Enumeration. All scans are output in the Enumeration folder and a markdown file for loot and notes is created in the main box folder. If you refresh Obsidian these will all be added to your vault automaticly when complete.

## Note:  
* Syntax should be: python3 ce.py {Machine IP}
* Will ask for a domain name. Domain name should be entered as {box_name}.htb or {box_name}.thm. Don't use spaces in box names.
* Will ask for sudo password to add domain to /etc/hosts file.
* Test.txt wordlist is important for the wfuzz scan, because its used to calibrate the scan and filter out all of the results that are the same. Its just 30 or so words from a wordlist so it can run quickly, then use re to filter.
* All wordlists I used in the script are included in the assets folder, very easy to switch out to another list.

# Commands being run
#### nmap
```
nmap --min-rate 500 -p- -oN {enumeration_folder/nmap.md} {ip_address}
```
* pulls all open ports and runs:
```
nmap -p {open_ports} -A -oN {enumeration_folder}/nmap.md {ip_address}
```

#### Ffuf
* Pulls any open ports using HTTP from nmap scan, and runs on all of them. If port 80 and 443 are open, it only runs on port 80.
```
ffuf -w wordlists/common.txt:FUZZ -u http://{domain_name}:{port}/FUZZ -ac -e ".txt,.html,.php" -of csv -o {enumeration_folder/port_{port}_ffuf.txt"}
```

#### Wfuzz
* Only runs on port 80 currently.
```
wfuzz -c -f {enumeration_folder}/wfuzz.txt -w {wordlists/subdomains-top1million-5000.txt"} -u "http://{domain_name}" -H "Host: FUZZ.{domain_name}
```

#### Nikto
* Also only runs on port 80 currently.
```
nikto -h {domain_name} -o {enumeration_folder}/nikto.txt
```
