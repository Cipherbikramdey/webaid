import os
import subprocess
import datetime
from InquirerPy import prompt
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

# --- Tool Option Dictionaries ---
nmap_options = {
    "-sS": "TCP SYN scan",
    "-sU": "UDP scan",
    "-A": "Enable OS detection, version detection, script scanning, and traceroute",
    "-p": "Port range (e.g., -p 1-1000)",
    "--script": "Run a specific script (e.g., --script=http-title)",
    "-O": "OS detection",
    "-sV": "Service/version detection",
    "-T4": "Set timing template (higher is faster, riskier)",
    "-Pn": "Skip host discovery (treat all hosts as online)"
}

nikto_options = {
    "-h": "Target host (IP, FQDN)",
    "-p": "Port to use (default 80)",
    "-Tuning": "Scan tuning (0-9, x for all)",
    "-Display": "Control output (V for verbose, D for debug)",
    "-evasion": "Evasion technique (1-9)",
    "-useragent": "Set custom User-Agent",
    "-Cgidirs": "Scan these CGI dirs only",
    "-UseProxy": "Use a proxy (format: http://host:port)"
}

dirb_options = {
    "<url>": "Target URL (required)",
    "<wordlist>": "Path to wordlist (required)",
    "-o": "Output file",
    "-r": "Don't recurse",
    "-S": "Silent mode (do not show status codes)",
    "-x": "File extensions to append (e.g., .php,.html)",
    "-z": "Delay between requests (e.g., 1s, 1000ms)"
}

whois_options = {
    "--verbose": "Display detailed output",
    "--help": "Show help message",
    "--host": "Specify whois server",
    "--port": "Specify whois server port"
}

dnsenum_options = {
    "--dnsserver": "Specify a DNS server to use",
    "--enum": "Perform full enumeration",
    "--threads": "Number of threads to use",
    "--noreverse": "Skip reverse lookups",
    "--subfile": "Specify a file containing subdomains",
    "--output": "Output file"
}

nslookup_options = {
    "-type": "Specify query type (e.g., A, MX, NS, TXT)",
    "-debug": "Display detailed debug information",
    "-timeout": "Set query timeout (in seconds)",
    "-retry": "Set number of retries"
}

host_options = {
    "-a": "All information",
    "-t": "Specify query type (A, MX, NS, etc.)",
    "-v": "Verbose output",
    "-W": "Timeout for replies",
    "-R": "Number of retries",
    "-C": "Check consistency of all zone records"
}

theharvester_options = {
    "-d": "Domain to search",
    "-b": "Data source (e.g., google, bing, linkedin)",
    "-l": "Limit the number of results",
    "-s": "Start with result number",
    "-f": "Save output to HTML or XML file",
    "-v": "Verbose mode"
}

dirbuster_options = {
    "-u": "Target URL",
    "-l": "Path to wordlist",
    "-t": "Number of threads",
    "-x": "File extensions",
    "-o": "Output directory",
    "-H": "Use HEAD instead of GET"
}

dig_options = {
    "+short": "Short output",
    "+trace": "Trace entire path to root",
    "+noall": "Turn off all sections",
    "+answer": "Display only the answer section",
    "@<server>": "Specify DNS server",
    "<type>": "Query type (A, MX, NS, etc.)"
}

wafw00f_options = {
    "-a": "Aggressive mode",
    "-v": "Verbose output",
    "-p": "Use a proxy",
    "-H": "Custom header",
    "--timeout": "Timeout value",
    "--findall": "Try to find all WAFs"
}

# --- Shared Functions ---
def get_options(tool_name, options_dict):
    choices = [
        {"name": f"{flag} : {desc}", "value": flag} for flag, desc in options_dict.items() if not flag.startswith("<")
    ]
    answers = prompt([
        {
            "type": "checkbox",
            "message": f"Select {tool_name} options",
            "name": "selected",
            "choices": choices
        }
    ])
    return answers["selected"]

def get_input(message):
    return Prompt.ask(f"[bold magenta]{message}[/bold magenta]")

def build_command(base_cmd, options, extra=None):
    if extra:
        return [base_cmd] + options + extra
    return [base_cmd] + options

def run_tool(tool_name, cmd_list, filename_prefix):
    console.rule(f"[bold cyan]{tool_name} Execution", style="bold blue")
    console.print(f"[bold yellow]Generated Command:[/bold yellow] [italic green]{' '.join(cmd_list)}[/italic green]")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = "recon-results"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{filename_prefix}_{timestamp}.txt")

    with open(output_file, "w") as f:
        process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            console.print(line.rstrip(), style="white")
            f.write(line)

    console.print(f"\n[bold green][+] Scan completed. Output saved to [underline]{output_file}[/underline][/bold green]\n")

# --- Tool Runners ---
def run_nmap():
    options = get_options("Nmap", nmap_options)
    target = get_input("Enter target (IP or domain):")
    final_options = []
    for opt in options:
        if opt in ["-p", "--script"]:
            val = get_input(f"Enter value for {opt}:")
            final_options.extend([opt, val])
        else:
            final_options.append(opt)
    cmd = build_command("nmap", final_options, [target])
    run_tool("Nmap", cmd, "nmap")

def run_nikto():
    options = get_options("Nikto", nikto_options)
    final_options = []
    for opt in options:
        val = get_input(f"Enter value for {opt}:")
        final_options.extend([opt, val])
    cmd = build_command("nikto", final_options)
    run_tool("Nikto", cmd, "nikto")

def run_dirb():
    url = get_input("Enter target URL (e.g., http://example.com):")
    wordlist = get_input("Enter wordlist path:")
    options = get_options("Dirb", dirb_options)
    final_options = []
    for opt in options:
        if opt in ["-o", "-x", "-z"]:
            val = get_input(f"Enter value for {opt}:")
            final_options.extend([opt, val])
        else:
            final_options.append(opt)
    cmd = build_command("dirb", final_options, [url, wordlist])
    run_tool("Dirb", cmd, "dirb")

def run_whois():
    domain = get_input("Enter domain name to query:")
    options = get_options("Whois", whois_options)
    final_options = []
    for opt in options:
        if opt in ["--host", "--port"]:
            val = get_input(f"Enter value for {opt}:")
            final_options.extend([opt, val])
        else:
            final_options.append(opt)
    cmd = build_command("whois", final_options, [domain])
    run_tool("Whois", cmd, "whois")

def run_dnsenum():
    domain = get_input("Enter domain name to enumerate:")
    options = get_options("Dnsenum", dnsenum_options)
    final_options = []
    for opt in options:
        if opt in ["--dnsserver", "--threads", "--subfile", "--output"]:
            val = get_input(f"Enter value for {opt}: ")
            final_options.extend([opt, val])
        else:
            final_options.append(opt)
    cmd = build_command("dnsenum", final_options, [domain])
    run_tool("Dnsenum", cmd, "dnsenum")

def run_nslookup():
    domain = get_input("Enter domain name to query:")
    options = get_options("Nslookup", nslookup_options)
    final_options = []
    for opt in options:
        if opt in ["-type", "-timeout", "-retry"]:
            val = get_input(f"Enter value for {opt}:")
            final_options.extend([opt, val])
        else:
            final_options.append(opt)
    cmd = build_command("nslookup", final_options, [domain])
    run_tool("Nslookup", cmd, "nslookup")

def run_host():
    domain = get_input("Enter domain name:")
    options = get_options("Host", host_options)
    final_options = []
    for opt in options:
        if opt in ["-t", "-W", "-R"]:
            val = get_input(f"Enter value for {opt}:")
            final_options.extend([opt, val])
        else:
            final_options.append(opt)
    cmd = build_command("host", final_options, [domain])
    run_tool("Host", cmd, "host")

def run_theharvester():
    options = get_options("theHarvester", theharvester_options)
    final_options = []
    for opt in options:
        val = get_input(f"Enter value for {opt}:")
        final_options.extend([opt, val])
    cmd = build_command("theHarvester", final_options)
    run_tool("theHarvester", cmd, "theharvester")

def run_dirbuster():
    options = get_options("DirBuster", dirbuster_options)
    final_options = []
    for opt in options:
        val = get_input(f"Enter value for {opt}:")
        final_options.extend([opt, val])
    cmd = build_command("dirbuster", final_options)
    run_tool("DirBuster", cmd, "dirbuster")

def run_dig():
    domain = get_input("Enter domain name to query:")
    options = get_options("Dig", dig_options)
    final_options = []
    for opt in options:
        if "<" in opt:
            val = get_input(f"Enter value for {opt}:")
            final_options.append(val)
        else:
            final_options.append(opt)
    cmd = build_command("dig", final_options, [domain])
    run_tool("Dig", cmd, "dig")

def run_wafw00f():
    url = get_input("Enter URL to test WAF:")
    options = get_options("WafW00f", wafw00f_options)
    final_options = []
    for opt in options:
        if opt in ["-p", "-H", "--timeout"]:
            val = get_input(f"Enter value for {opt}:")
            final_options.extend([opt, val])
        else:
            final_options.append(opt)
    cmd = build_command("wafw00f", final_options, [url])
    run_tool("WafW00f", cmd, "wafw00f")

# --- Main Menu ---
def main():
    console.print(Panel(Text("🌐 WebAid - Info Gathering Toolkit", justify="center", style="bold white"), style="bold blue", box=box.DOUBLE))

    while True:
        answer = prompt([
            {
                "type": "list",
                "name": "tool",
                "message": "Choose a tool to run:",
                "choices": [
                    {"name": "Nmap", "value": "nmap"},
                    {"name": "Nikto", "value": "nikto"},
                    {"name": "Dirb", "value": "dirb"},
                    {"name": "Whois", "value": "whois"},
                    {"name": "Dnsenum", "value": "dnsenum"},
                    {"name": "Nslookup", "value": "nslookup"},
                    {"name": "Host", "value": "host"},
                    {"name": "theHarvester", "value": "theharvester"},
                    {"name": "DirBuster", "value": "dirbuster"},
                    {"name": "Dig", "value": "dig"},
                    {"name": "WafW00f", "value": "wafw00f"},
                    {"name": "Exit", "value": "exit"}
                ]
            }
        ])

        match answer["tool"]:
            case "nmap": run_nmap()
            case "nikto": run_nikto()
            case "dirb": run_dirb()
            case "whois": run_whois()
            case "dnsenum": run_dnsenum()
            case "nslookup": run_nslookup()
            case "host": run_host()
            case "theharvester": run_theharvester()
            case "dirbuster": run_dirbuster()
            case "dig": run_dig()
            case "wafw00f": run_wafw00f()
            case "exit":
                console.print(Panel("Exiting [bold cyan]WebAid[/bold cyan]. Goodbye! 👋", style="bold red", box=box.DOUBLE))
                break

if __name__ == "__main__":
    main()
