
import subprocess
import sys

# List of required tools and installation suggestions
REQUIRED_TOOLS = {
    "subfinder": "Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "subjack": "Install with: go install github.com/haccer/subjack@latest",
    "httpx": "Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "Install with: go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "Install with: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
    "aquatone": "Install with: gem install aquatone (optional, for screenshots)",
}

def check_tools():
    print("[*] Checking required tools...")
    missing_tools = []
    
    for tool, install_suggestion in REQUIRED_TOOLS.items():
        result = subprocess.run(f"which {tool}", shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[X] {tool} is missing. {install_suggestion}")
            missing_tools.append(tool)
    
    if missing_tools:
        print("\n[!] Missing tools detected. Please install the tools listed above and re-run the script.")
        sys.exit(1)
    else:
        print("[✓] All required tools are installed.\n")

def run_command(command, description):
    print(f"[+] Running: {description}")
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True, check=True)
        print(f"[✓] Completed: {description}")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[X] Error executing {description}: {e}")
        return None

# Step 1: Subdomain Enumeration with additional flags for maximum output
def find_subdomains(target):
    print("[*] Step 1: Subdomain Enumeration (using Subfinder with -all for comprehensive results)")
    subdomains = set()
    subfinder_result = run_command(f"subfinder -d {target} -all -silent", "Subfinder")
    crtsh_result = run_command(f"crtsh -d {target}", "crt.sh")
    assetfinder_result = run_command(f"assetfinder --subs-only {target}", "Assetfinder")
    
    if subfinder_result:
        subdomains.update(subfinder_result.splitlines())
    if crtsh_result:
        subdomains.update(crtsh_result.splitlines())
    if assetfinder_result:
        subdomains.update(assetfinder_result.splitlines())

    with open("uniqsubs.txt", "w") as f:
        f.write("\n".join(set(subdomains)))
    print("[*] Subdomains saved to uniqsubs.txt")

# Step 2: Subdomain Takeover
def check_takeover():
    print("[*] Step 2: Subdomain Takeover (using Subjack)")
    takeover_result = run_command("subjack -w uniqsubs.txt -t 100 -o takeover_vulnerable.txt -ssl", "Subjack for Subdomain Takeover")
    print("[*] Subdomain takeover results saved to takeover_vulnerable.txt")

# Step 3: URL Filtering (Live Hosts) with enhanced Httpx output
def check_live_hosts():
    print("[*] Step 3: Checking Live Hosts with httpx (including status codes)")
    live_result = run_command("httpx -l uniqsubs.txt -silent -status-code -o alivehost.txt", "httpx for Live Hosts")
    print("[*] Live hosts saved to alivehost.txt")

# Step 4: Content Discovery with Katana for JS files and Endpoints
def discover_content():
    print("[*] Step 4: Discovering Content with Katana (JS files and Endpoints)")
    katana_result = run_command("katana -list alivehost.txt -silent -o katana_output.txt -js", "Katana for JS and Endpoints")
    print("[*] Katana content discovery results saved to katana_output.txt")

# Step 5: Vulnerability Scanning with Nuclei (all available templates)
def scan_vulnerabilities():
    print("[*] Step 5: Scanning for Vulnerabilities with Nuclei (comprehensive scan)")
    nuclei_result = run_command("nuclei -l alivehost.txt -t vulnerabilities/ -severity low,medium,high,critical -o nuclei_vulnerabilities.txt", "Nuclei for Vulnerabilities")
    print("[*] Vulnerability scan results saved to nuclei_vulnerabilities.txt")

# Extra: Screenshot and additional data collection (Optional)
def screenshot_live_hosts():
    print("[*] Taking screenshots of live hosts with Aquatone (Optional)")
    screenshot_result = run_command("cat alivehost.txt | aquatone", "Aquatone for Screenshots")
    print("[*] Screenshots saved by Aquatone.")

# Main Execution
def main():
    # Check if all required tools are installed
    check_tools()
    
    target = input("Enter the target domain: ")
    
    # Execute each function in sequence
    find_subdomains(target)
    check_takeover()
    check_live_hosts()
    discover_content()
    scan_vulnerabilities()
    
    # Optional screenshot function
    if input("Would you like to take screenshots of live hosts? (y/n): ").lower() == 'y':
        screenshot_live_hosts()
    
    print("\n[+] All processes completed. Check output files for results.")

if __name__ == "__main__":
    main()
