import argparse
import subprocess
import re
import os
import time
import socket
import csv
import getpass  # Import the getpass module

# ANSI escape codes for text colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[31m"
BBLUE = "\033[94m"
DBLUE = "\033[34m"
BCYAN = "\033[96m"
DCYAN = "\033[36m"
RESET = "\033[0m"

# Universal variable to track host seems down
host_seems_down = 0
domain_added = False  # Track whether a domain name was added

# Function to get the domain name associated with an IP address from /etc/hosts
def get_domain_name(ip_address):
    try:
        with open("/etc/hosts", "r") as hosts_file:
            for line in hosts_file:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip_address:
                    return parts[1]
    except FileNotFoundError:
        pass
    return None

def run_nmap_and_extract_open_ports(ip_address, enumeration_folder):
    global host_seems_down, domain_added
    print(f"{BCYAN}[INFO] Running initial nmap scan to discover open ports...{RESET}")
    nmap_command = f'nmap --min-rate 500 -p- -oN {os.path.join(enumeration_folder, "nmap.txt")} {ip_address}'  # Use os.path.join
    nmap_process = None  # Initialize nmap_process variable

    try:
        nmap_process = subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        if "Permission denied" in e.stderr.decode():
            print(f"{RED}[ERROR] Permission denied. Please run with sudo.{RESET}")
            return ""

    # Check if the scan result contains "Host seems down" in stdout
    if nmap_process is not None and "Host seems down" in nmap_process.stdout.decode():
        host_seems_down = 1
        print(f"{BCYAN}[INFO] Nmap scan indicated 'Host seems down'. Rerunning with -Pn...{RESET}")
        nmap_command = f'nmap --min-rate 500 -p- -oN {os.path.join(enumeration_folder, "nmap.md")} -Pn {ip_address}'  # Use os.path.join
        subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Parse the nmap.txt file to extract open ports
    open_ports = []
    with open(os.path.join(enumeration_folder, "nmap.txt"), "r") as nmap_file:  # Use os.path.join
        nmap_output = nmap_file.read()
        port_lines = nmap_output.splitlines()
        for line in port_lines:
            if "open" in line.lower():
                match = re.search(r'(\d+)/tcp', line)
                if match:
                    port_number = match.group(1)
                    open_ports.append(port_number)

    return ",".join(open_ports)


def run_full_nmap_scan(ip_address, open_ports, enumeration_folder):
    global host_seems_down, domain_added
    print(f"{BCYAN}[INFO] Running full nmap scan to gather additional information...{RESET}")
    nmap_command = f'nmap -p {open_ports} -A -oN {enumeration_folder}/nmap.md {ip_address}'
    if host_seems_down == 1:
        nmap_command += ' -Pn'  # Add -Pn if host seems down
    subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Update the run_ffuf function to accept a list of ports
def run_ffuf(domain_name, http_ports, enumeration_folder, sd):
    if http_ports:
        print(f"{BCYAN}[INFO] Running ffuf scans on HTTP ports...{RESET}")
        for port in http_ports:
            ffuf_command = (
                f'ffuf -w {os.path.join(sd, "wordlists/common.txt")}:FUZZ '
                f'-u http://{domain_name}:{port}/FUZZ -ac -e ".txt,.html,.php" -of csv -o {os.path.join(enumeration_folder, f"port_{port}_ffuf.txt")}'
            )
            subprocess.run(ffuf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# Update the find_http_ports function to return a list of ports
def find_http_ports(enumeration_folder):
    http_ports = []
    with open(os.path.join(enumeration_folder, "nmap.txt"), "r", encoding="utf-8") as nmap_file:
        nmap_output = nmap_file.read()
        port_lines = nmap_output.splitlines()
        for line in port_lines:
            if "http" in line.lower() and "open" in line.lower():
                match = re.search(r'(\d+)/tcp', line)
                if match:
                    port_number = match.group(1)
                    http_ports.append(port_number)
    return http_ports

# Function to clean and format URLs
def clean_and_format_urls(enumeration_folder):
    seen_urls = set()
    formatted_urls = []

    ffuf_files = [f for f in os.listdir(enumeration_folder) if f.endswith("_ffuf.txt")]
    
    for ffuf_file_name in ffuf_files:
        with open(os.path.join(enumeration_folder, ffuf_file_name), "r", encoding="utf-8") as ffuf_file:
            ffuf_lines = ffuf_file.readlines()
            for line in ffuf_lines[1:]:  # Skip the first two lines
                parts = line.split(',')
                status_code = parts[5]
                url = parts[2].strip(',')
                url = url.strip()  # Remove leading/trailing whitespaces

                # Normalize the URL to lowercase and remove trailing /
                url = url.lower().rstrip('/')

                # Check if the URL or its lowercase version is already in seen_urls
                if url not in seen_urls and url not in seen_urls:
                    seen_urls.add(url)
                    formatted_urls.append(f"{status_code}  |  {url}")

        # Sort the URLs by status code in ascending order
        formatted_urls.sort(key=lambda x: int(x.split()[0]))

        with open(os.path.join(enumeration_folder, ffuf_file_name), "w", encoding="utf-8") as ffuf_file:
            ffuf_file.write("\n".join(formatted_urls))

# Function to run Nikto and save its output to nikto.txt
def run_nikto(ip_address, domain_name, enumeration_folder):
    print(f"{BCYAN}[INFO] Running Nikto scan...{RESET}")
    nikto_command = f'nikto -h {domain_name} -o {enumeration_folder}/nikto.txt'
    subprocess.run(nikto_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")

# Function to run wfuzz
def run_wfuzz(ip_address, domain_name, enumeration_folder, sd):
    print(f"{BCYAN}[INFO] Testing wfuzz...{RESET}")
    
    # First wfuzz command to extract a number
    wfuzz_command1 = (
        f'wfuzz -c -f {enumeration_folder}/wfuzz.txt -w {os.path.join(sd, "wordlists/test.txt")} '
        f'-u "http://{domain_name}" -H "Host: FUZZ.{domain_name}"'
    )
    subprocess.run(wfuzz_command1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    
    # Extract the number from wfuzz.txt
    with open(os.path.join(enumeration_folder, "wfuzz.txt"), "r", encoding="utf-8") as wfuzz_file:
        wfuzz_output = wfuzz_file.read()
        match = re.search(r'(\d+) W', wfuzz_output)
        if match:
            num_w = match.group(1)
            print(f"{BCYAN}[INFO] Calibrating wfuzz...{RESET}")
        else:
            print(f"{RED}[ERROR] Unable to extract 'W' value from wfuzz output.{RESET}")

    # Second wfuzz command to overwrite wfuzz.txt with the 'W' value
    if num_w:
        print(f"{BCYAN}[INFO] Running wfuzz...{RESET}")
        wfuzz_command2 = (
            f'wfuzz -c -f {enumeration_folder}/wfuzz.txt -w {os.path.join(sd, "wordlists/subdomains-top1million-5000.txt")} '
            f'-u "http://{domain_name}" -H "Host: FUZZ.{domain_name}" --hw {num_w}'
        )
        subprocess.run(wfuzz_command2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")

def create_folder_structure(domain_name):
    try:
        # Split the domain name into parts
        parts = domain_name.split('.')

        if len(parts) < 2:
            print(f"{RED}[ERROR] Invalid domain name format.{RESET}")
            return None

        # Extract the first part as the folder name
        folder_name = parts[0]

        # Determine the subfolder based on the second part of the domain name
        subfolder = ""
        if parts[-1] == "htb":
            subfolder = "HackTheBox"
        elif parts[-1] == "thm":
            subfolder = "TryHackMe"

        # Create the subfolder if it doesn't exist
        if subfolder:
            subfolder_path = os.path.join(os.path.dirname(__file__), subfolder, folder_name)  # Use os.path.dirname(__file__) to get the current script's directory
            if not os.path.exists(subfolder_path):
                os.makedirs(subfolder_path)

        enumeration_folder = os.path.join(os.path.dirname(__file__), subfolder, folder_name, "Enumeration")  # Use os.path.dirname(__file__)
        os.makedirs(enumeration_folder, exist_ok=True)

        # Create notes.md and loot.md files
        notes_file_path = os.path.join(os.path.dirname(__file__), subfolder, folder_name, "notes.md")
        loot_file_path = os.path.join(os.path.dirname(__file__), subfolder, folder_name, "loot.md")

        with open(notes_file_path, "w", encoding="utf-8") as notes_file:
            notes_file.write("* \n\n")

        with open(loot_file_path, "w", encoding="utf-8") as loot_file:
            loot_file.write("## Flags\n* user: \n* root: \n## User:Pass\n* ")

        return enumeration_folder
    except Exception as e:
        print(f"{RED}[ERROR] An error occurred while creating folder structure: {str(e)}{RESET}")
        return None

def remove_txt_files(enumeration_folder):
    try:
        for file_name in os.listdir(enumeration_folder):
            if file_name.endswith(".txt"):
                file_path = os.path.join(enumeration_folder, file_name)
                os.remove(file_path)
                print(f"{BCYAN}[INFO] Removed file: {file_name}{RESET}")
    except Exception as e:
        print(f"{RED}[ERROR] An error occurred while removing .txt files: {str(e)}{RESET}")

def create_markdown_file(file_name, content):
    formatted_content = f"```\n{content}\n```"
    with open(file_name, "w") as md_file:
        md_file.write(formatted_content)
        
def create_markdown_file2(file_name, content):
    with open(file_name, "w", encoding="utf-8") as md_file:
        md_file.write(f"```\n{content}\n```")


def main():
    banner = f"""
{RED}
 ██████╗██████╗ ██╗   ██╗██╗  ██╗     
██╔════╝██╔══██╗██║   ██║╚██╗██╔╝     
██║     ██████╔╝██║   ██║ ╚███╔╝      
██║     ██╔══██╗██║   ██║ ██╔██╗      
╚██████╗██║  ██║╚██████╔╝██╔╝ ██╗     
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝     
                                      
███████╗███╗   ██╗██╗   ██╗███╗   ███╗
██╔════╝████╗  ██║██║   ██║████╗ ████║
█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
{RESET}
"""
    print(banner)
    sd = os.getcwd()
    parser = argparse.ArgumentParser(description="Automate nmap, ffuf, Nikto, and wfuzz scans.")
    parser.add_argument("ip_address", nargs="?", help="The IP address to scan. If not provided, you will be prompted for one.")

    domain_added = False
    args = parser.parse_args()
    ip_address = args.ip_address

    if not ip_address:
        ip_address = input(f"{RED}[INPUT] Enter an IP address to scan: {RESET}")

    # Ask the user for the domain name
    domain_name = input(f"{RED}[INPUT] Enter the domain name: {RESET}")

    # Create the folder structure based on the domain name
    enumeration_folder = create_folder_structure(domain_name)

    if not enumeration_folder:
        return

    # Check if the domain name is in /etc/hosts and add it if not
    if not domain_added:
        try:
            # Prompt for sudo password
            sudo_password = getpass.getpass(prompt=f"{RED}[INPUT] Enter your sudo password to add the domain to /etc/hosts: {RESET}")

            # Use sudo to edit /etc/hosts
            with subprocess.Popen(['sudo', '-S', 'tee', '-a', '/etc/hosts'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8") as proc:
                # Provide the sudo password as input
                proc.communicate(input=f"{sudo_password}\n{ip_address} {domain_name}\n")

            print(f"{GREEN}[SUCCESS] Domain name {domain_name} added to /etc/hosts.{RESET}")
            domain_added = True
        except Exception as e:
            print(f"{RED}[ERROR] An error occurred while adding the domain to /etc/hosts: {str(e)}{RESET}")

    # Change the working directory to the Enumeration folder
    os.chdir(enumeration_folder)

    try:
        open_ports = run_nmap_and_extract_open_ports(ip_address, enumeration_folder)
    except Exception as e:
        print(f"{RED}[ERROR] An error occurred while running the nmap scan: {str(e)}{RESET}")
        return

    if open_ports:
        print(f"{YELLOW}[LOOT] Open Ports on: {open_ports}.{RESET}")
    else:
        print(f"{RED}[ERROR] No open ports found. Exiting...{RESET}")
        return

    # Run the second nmap scan
    try:
        run_full_nmap_scan(ip_address, open_ports, enumeration_folder)
    except Exception as e:
        print(f"{RED}[ERROR] An error occurred while running the full nmap scan: {str(e)}{RESET}")

    # Create Markdown files for nmap outputs
    create_markdown_file("nmap.md", open("nmap.md", "r").read())
    print(f"{GREEN}[SUCCESS] Nmap scan added to Obsidian.{RESET}")
    
    # Find HTTP ports
    try:
        http_ports = find_http_ports(enumeration_folder)
    except Exception as e:
        print(f"{RED}[ERROR] An error occurred while finding HTTP ports: {str(e)}{RESET}")
        http_ports = None  # Set http_ports to None if an error occurs

    # Run ffuf scans on HTTP ports
    try:
        run_ffuf(domain_name, http_ports, enumeration_folder, sd)
    except Exception as e:
        print(f"{RED}[ERROR] An error occurred while running ffuf scans: {str(e)}{RESET}")

    # Clean and format ffuf scan results
    try:
        clean_and_format_urls(enumeration_folder)
    except Exception as e:
        print(f"{RED}[ERROR] An error occurred while cleaning and formatting URLs: {str(e)}{RESET}")

    # Create Markdown files for ffuf outputs
    ffuf_files = [f for f in os.listdir() if f.endswith("_ffuf.txt")]
    for ffuf_file_name in ffuf_files:
        create_markdown_file2(f"{ffuf_file_name.replace('.txt', '.md')}", open(ffuf_file_name, "r").read())
        print(f"{GREEN}[SUCCESS] {ffuf_file_name.replace('.txt', '')} scan added to Obsidian.{RESET}")
    

    # Run wfuzz
    try:
        run_wfuzz(ip_address, domain_name, enumeration_folder, sd)
    except Exception as e:
        print(f"{RED}[ERROR] An error occurred while running wfuzz: {str(e)}{RESET}")
    create_markdown_file2("wfuzz.md", open("wfuzz.txt", "r").read())
    print(f"{GREEN}[SUCCESS] wfuzz scan added to Obsidian.{RESET}")
    
    # Run Nikto scan
    try:
        run_nikto(ip_address, domain_name, enumeration_folder)
    except Exception as e:
        print(f"{RED}[ERROR] An error occurred while running the Nikto scan: {str(e)}{RESET}")
    create_markdown_file2("nikto.md", open("nikto.txt", "r").read())
    print(f"{GREEN}[SUCCESS] Nikto scan added to Obsidian.{RESET}")
    
    remove_txt_files(enumeration_folder)
    
    print(f"{GREEN}[SUCCESS] Enumeration completed successfully. Results saved in {enumeration_folder}.{RESET}")
    
    

if __name__ == "__main__":
    main()

