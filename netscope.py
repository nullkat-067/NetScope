#!/usr/bin/env python3
"""NetScope CLI: DNS lookup and authorized Nmap scans.

Use only against hosts and networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Sequence


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"


def paint(text: str, color: str) -> str:
    """Apply ANSI color when output is interactive."""
    if sys.stdout.isatty():
        return f"{color}{text}{Color.RESET}"
    return text


def title(text: str) -> None:
    line = "─" * 62
    print(f"\n{paint(line, Color.BLUE)}")
    print(paint(f"  {text}", Color.BOLD + Color.CYAN))
    print(paint(line, Color.BLUE))


def banner() -> None:
    print(paint(r"""
   ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
   ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
   █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
   ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
   ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
   ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
""", Color.CYAN))
    print(paint("  DNS utility + authorized Nmap scanner", Color.DIM))
    print(paint("  by NullKat • safe subprocess execution • v2.0.0", Color.MAGENTA))


@dataclass(frozen=True)
class ScanProfile:
    key: str
    label: str
    flags: tuple[str, ...]
    needs_root: bool = False


SCAN_PROFILES: tuple[ScanProfile, ...] = (
    ScanProfile("1", "Basic scan", ()),
    ScanProfile("2", "TCP connect scan", ("-sT",)),
    ScanProfile("3", "SYN scan", ("-sS",), needs_root=True),
    ScanProfile("4", "UDP top ports", ("-sU", "--top-ports", "100"), needs_root=True),
    ScanProfile("5", "Specific ports", ()),
    ScanProfile("6", "Ports 1–1000", ("-p", "1-1000")),
    ScanProfile("7", "All TCP ports", ("-p", "-")),
    ScanProfile("8", "Fast scan", ("-F",)),
    ScanProfile("9", "Service detection", ("-sV",)),
    ScanProfile("10", "OS detection", ("-O",), needs_root=True),
)


def valid_ports(value: str) -> bool:
    """Allow nmap's common numeric port-list syntax without shell metacharacters."""
    if not value or any(char not in "0123456789,-" for char in value):
        return False
    for part in value.split(","):
        if not part or part.startswith("-") or part.endswith("-"):
            return False
        if part.count("-") > 1:
            return False
        if "-" in part:
            start, end = part.split("-", 1)
            if not start.isdigit() or not end.isdigit() or int(start) > int(end):
                return False
        elif not part.isdigit():
            return False
        if any(int(port) > 65535 for port in part.split("-") if port):
            return False
    return True


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IPv4 address, or return a validated IP."""
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve hostname: {target}") from exc


def build_nmap_command(profile: ScanProfile, target: str, ports: str | None = None) -> list[str]:
    """Build an argument list; never use a shell string for Nmap."""
    if profile.key == "5":
        if not ports or not valid_ports(ports):
            raise ValueError("Invalid port format. Example: 22,80,443 or 1-1024")
        flags = ("-p", ports)
    else:
        flags = profile.flags
    return ["nmap", *flags, target]


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap(command: Sequence[str]) -> int:
    """Run Nmap directly and stream its output to the terminal."""
    print(paint(f"\n$ {' '.join(command)}", Color.DIM))
    print(paint("Starting Nmap... press Ctrl+C to cancel.\n", Color.YELLOW))
    try:
        completed = subprocess.run(list(command), check=False)
        return completed.returncode
    except FileNotFoundError:
        print(paint("Nmap is not installed. Run: sudo apt install nmap", Color.RED))
        return 127
    except KeyboardInterrupt:
        print(paint("\nScan cancelled.", Color.YELLOW))
        return 130
    except OSError as exc:
        print(paint(f"Failed to run Nmap: {exc}", Color.RED))
        return 1


def ask_target() -> tuple[str, str] | None:
    raw = input(paint("Target hostname/IP: ", Color.GREEN))
    try:
        return raw.strip(), resolve_target(raw)
    except ValueError as exc:
        print(paint(f"Error: {exc}", Color.RED))
        return None


def dns_lookup() -> None:
    title("DNS LOOKUP")
    result = ask_target()
    if result:
        hostname, address = result
        print(paint(f"Hostname : {hostname}", Color.GREEN))
        print(paint(f"IPv4     : {address}", Color.GREEN))


def reverse_dns() -> None:
    title("REVERSE DNS")
    raw = input(paint("IP address: ", Color.GREEN)).strip()
    try:
        address = str(ipaddress.ip_address(raw))
        hostname, aliases, _ = socket.gethostbyaddr(address)
        print(paint(f"Address  : {address}", Color.GREEN))
        print(paint(f"Hostname : {hostname}", Color.GREEN))
        if aliases:
            print(paint(f"Aliases  : {', '.join(aliases)}", Color.DIM))
    except (ValueError, socket.herror, socket.gaierror) as exc:
        print(paint(f"Reverse lookup failed: {exc}", Color.RED))


def http_headers() -> None:
    title("HTTP HEADER CHECK")
    url = input(paint("URL (example: https://example.com): ", Color.GREEN)).strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed_url = urllib.parse.urlparse(url)
    try:
        if not parsed_url.hostname:
            raise ValueError("URL does not contain a valid hostname.")
        resolved_ip = resolve_target(parsed_url.hostname)
        print(paint(f"IP address : {resolved_ip}", Color.GREEN))
    except ValueError as exc:
        print(paint(f"Could not resolve URL host: {exc}", Color.RED))
        return
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "NetScope/2.0"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            print(paint(f"Status : {response.status} {response.reason}", Color.GREEN))
            print(paint(f"URL    : {response.url}", Color.DIM))
            for key in ("server", "content-type", "content-length", "location", "strict-transport-security"):
                value = response.headers.get(key)
                if value:
                    print(f"{key.title():26} {value}")
    except urllib.error.HTTPError as exc:
        print(paint(f"HTTP error: {exc.code} {exc.reason}", Color.YELLOW))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(paint(f"Request failed: {exc}", Color.RED))


def tcp_port_check() -> None:
    title("TCP PORT CHECK")
    raw_target = input(paint("Host/IP: ", Color.GREEN)).strip()
    raw_port = input(paint("Single port (1-65535): ", Color.GREEN)).strip()
    try:
        target = resolve_target(raw_target)
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        with socket.create_connection((target, port), timeout=3):
            print(paint(f"OPEN  {raw_target} ({target}):{port}", Color.GREEN))
    except ValueError as exc:
        print(paint(f"Invalid input: {exc}", Color.RED))
    except (socket.timeout, ConnectionRefusedError, OSError):
        print(paint(f"CLOSED or FILTERED  {raw_target}:{raw_port}", Color.YELLOW))


def dns_addresses() -> None:
    """Show every unique IPv4/IPv6 address returned by the local resolver."""
    title("ALL DNS ADDRESSES")
    raw = input(paint("Hostname: ", Color.GREEN)).strip()
    try:
        records = socket.getaddrinfo(raw, None, type=socket.SOCK_STREAM)
        addresses = sorted({item[4][0] for item in records})
        if not addresses:
            raise socket.gaierror("no addresses returned")
        for index, address in enumerate(addresses, 1):
            print(paint(f"{index:2}. {address}", Color.GREEN))
    except socket.gaierror as exc:
        print(paint(f"DNS lookup failed: {exc}", Color.RED))


def http_status() -> None:
    title("HTTP STATUS & REDIRECT")
    url = input(paint("URL: ", Color.GREEN)).strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "NetScope/2.0"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            print(paint(f"Status       : {response.status} {response.reason}", Color.GREEN))
            print(paint(f"Final URL    : {response.url}", Color.GREEN))
            print(paint(f"Redirected   : {'yes' if response.url != url else 'no'}", Color.DIM))
    except urllib.error.HTTPError as exc:
        print(paint(f"HTTP status   : {exc.code} {exc.reason}", Color.YELLOW))
        print(paint(f"Final URL     : {exc.url}", Color.DIM))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(paint(f"Request failed: {exc}", Color.RED))


def common_ports_check() -> None:
    """Check a small, fixed set of common ports; never accepts a port list."""
    title("COMMON PORTS CHECK")
    raw = input(paint("Host/IP: ", Color.GREEN)).strip()
    try:
        target = resolve_target(raw)
    except ValueError as exc:
        print(paint(f"Invalid target: {exc}", Color.RED))
        return
    common = ((21, "FTP"), (22, "SSH"), (25, "SMTP"), (53, "DNS"), (80, "HTTP"), (443, "HTTPS"), (8080, "HTTP-alt"))
    print(paint(f"Checking {raw} ({target}) — authorized hosts only", Color.DIM))
    for port, label in common:
        try:
            with socket.create_connection((target, port), timeout=0.7):
                print(paint(f"OPEN   {port:5}  {label}", Color.GREEN))
        except (socket.timeout, ConnectionRefusedError, OSError):
            print(paint(f"CLOSED {port:5}  {label}", Color.DIM))


def ping_host() -> None:
    title("PING HOST")
    result = ask_target()
    if not result:
        return
    _, target = result
    ping = shutil.which("ping")
    if not ping:
        print(paint("ping was not found on this system.", Color.RED))
        return
    command = [ping, "-c", "4", "-W", "2", target]
    print(paint(f"$ {' '.join(command)}", Color.DIM))
    subprocess.run(command, check=False)


def traceroute_host() -> None:
    title("TRACEROUTE")
    result = ask_target()
    if not result:
        return
    _, target = result
    tool = shutil.which("traceroute") or shutil.which("tracepath")
    if not tool:
        print(paint("Neither traceroute nor tracepath was found.", Color.RED))
        return
    command = [tool, "-m", "8", target] if tool.endswith("traceroute") else [tool, "-m", "8", target]
    print(paint(f"$ {' '.join(command)}", Color.DIM))
    try:
        subprocess.run(command, check=False, timeout=30)
    except subprocess.TimeoutExpired:
        print(paint("Traceroute timed out after 30 seconds.", Color.YELLOW))


def tls_certificate() -> None:
    title("TLS CERTIFICATE")
    host = input(paint("Hostname: ", Color.GREEN)).strip()
    raw_port = input(paint("Port [443]: ", Color.GREEN)).strip() or "443"
    try:
        port = int(raw_port)
        if not host or not 1 <= port <= 65535:
            raise ValueError("Enter a valid hostname and port.")
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
                print(paint(f"TLS version : {tls_socket.version()}", Color.GREEN))
                print(paint(f"Cipher      : {tls_socket.cipher()[0]}", Color.GREEN))
                print(f"Subject     : {certificate.get('subject')}")
                print(f"Issuer      : {certificate.get('issuer')}")
                print(f"Valid from  : {certificate.get('notBefore')}")
                print(f"Valid until : {certificate.get('notAfter')}")
    except (ValueError, socket.timeout, OSError, ssl.SSLError) as exc:
        print(paint(f"TLS check failed: {exc}", Color.RED))


def whois_lookup() -> None:
    title("WHOIS LOOKUP")
    target = input(paint("Domain or IP: ", Color.GREEN)).strip()
    whois = shutil.which("whois")
    if not whois:
        print(paint("whois is not installed. Install it with your OS package manager.", Color.RED))
        return
    if not target or any(char.isspace() for char in target) or len(target) > 253:
        print(paint("Invalid domain or IP input.", Color.RED))
        return
    try:
        completed = subprocess.run([whois, target], capture_output=True, text=True, check=False, timeout=15)
        print(completed.stdout[:12000] or completed.stderr[:4000])
    except subprocess.TimeoutExpired:
        print(paint("WHOIS request timed out.", Color.YELLOW))


def local_network_info() -> None:
    title("LOCAL NETWORK INFO")
    hostname = socket.gethostname()
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)})
    print(paint(f"Hostname : {hostname}", Color.GREEN))
    print(paint(f"User     : {os.getenv('USER', 'unknown')}", Color.GREEN))
    for address in addresses:
        print(f"Address  : {address}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            print(paint(f"Primary  : {sock.getsockname()[0]}", Color.GREEN))
    except OSError:
        print(paint("Primary  : unavailable", Color.DIM))


def subnet_calculator() -> None:
    title("SUBNET CALCULATOR")
    raw = input(paint("Network (example: 192.168.1.0/24): ", Color.GREEN)).strip()
    try:
        network = ipaddress.ip_network(raw, strict=False)
        hosts = network.num_addresses - (2 if network.version == 4 and network.prefixlen < 31 else 0)
        print(paint(f"Network   : {network.network_address}", Color.GREEN))
        print(paint(f"Netmask   : {network.netmask}", Color.GREEN))
        print(paint(f"Broadcast : {network.broadcast_address}", Color.GREEN))
        print(paint(f"Prefix    : /{network.prefixlen}", Color.GREEN))
        print(paint(f"Usable    : {max(hosts, 0):,}", Color.GREEN))
    except ValueError as exc:
        print(paint(f"Invalid network: {exc}", Color.RED))


def show_scan_menu() -> None:
    title("NMAP SCAN PROFILES")
    for profile in SCAN_PROFILES:
        suffix = paint(" [root]", Color.YELLOW) if profile.needs_root else ""
        print(f"  {paint(profile.key.rjust(2), Color.CYAN)}  {profile.label}{suffix}")
    print(f"  {paint('0'.rjust(2), Color.RED)}  Back")


def nmap_menu() -> None:
    if not nmap_available():
        print(paint("Nmap was not found in PATH. Install it with your OS package manager.", Color.RED))
        return
    show_scan_menu()
    choice = input(paint("Select profile: ", Color.GREEN)).strip()
    if choice == "0":
        return
    profile = next((item for item in SCAN_PROFILES if item.key == choice), None)
    if profile is None:
        print(paint("Unknown choice.", Color.RED))
        return
    result = ask_target()
    if not result:
        return
    _, target = result
    ports = input(paint("Ports (example 22,80,443): ", Color.GREEN)).strip() if choice == "5" else None
    try:
        code = run_nmap(build_nmap_command(profile, target, ports))
        if code == 0:
            print(paint("\nScan selesai.", Color.GREEN))
        elif code != 130:
            print(paint(f"Nmap selesai dengan exit code {code}.", Color.YELLOW))
    except ValueError as exc:
        print(paint(f"Error: {exc}", Color.RED))


REQUIRED_TOOLS = ("nmap", "ping", "traceroute", "whois")


def package_manager() -> str | None:
    """Return the first supported package manager found on the system."""
    for manager in ("apt-get", "dnf", "pacman", "pkg"):
        if shutil.which(manager):
            return manager
    return None


def install_dependencies() -> None:
    """Install external command-line tools used by NetScope via a safe argv list."""
    title("DEPENDENCY INSTALLER")
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if not missing:
        print(paint("✓ All NetScope dependencies are already installed.", Color.GREEN))
        return

    manager = package_manager()
    if not manager:
        print(paint("No supported package manager found.", Color.RED))
        print("Supported managers: apt-get, dnf, pacman, pkg")
        return

    package_sets = {
        "apt-get": ["nmap", "iputils-ping", "traceroute", "whois"],
        "dnf": ["nmap", "iputils", "traceroute", "whois"],
        "pacman": ["nmap", "iputils", "traceroute", "whois"],
        "pkg": ["nmap", "inetutils", "whois"],
    }
    packages = package_sets[manager]
    prefix = [] if hasattr(os, "geteuid") and os.geteuid() == 0 or manager == "pkg" else ["sudo"]

    print(paint(f"Missing tools: {', '.join(missing)}", Color.YELLOW))
    print(paint(f"Package manager: {manager}", Color.CYAN))
    print(paint(f"Installing: {', '.join(packages)}", Color.DIM))

    commands: list[list[str]] = []
    if manager == "apt-get":
        commands.append([*prefix, manager, "update"])
    commands.append([*prefix, manager, "install", "-y", *packages])

    for command in commands:
        print(paint(f"\n$ {' '.join(command)}", Color.DIM))
        try:
            result = subprocess.run(command, check=False)
        except OSError as exc:
            print(paint(f"Could not start package manager: {exc}", Color.RED))
            return
        if result.returncode != 0:
            print(paint(f"Package manager exited with code {result.returncode}.", Color.RED))
            return

    still_missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if still_missing:
        print(paint(f"Install finished, but these tools are still missing: {', '.join(still_missing)}", Color.YELLOW))
    else:
        print(paint("✓ All NetScope dependencies are ready.", Color.GREEN))


def menu() -> None:
    while True:
        title("MAIN MENU")
        options = (
            ("1", "Resolve host / DNS lookup"),
            ("2", "List all DNS addresses"),
            ("3", "Reverse DNS lookup"),
            ("4", "HTTP header check"),
            ("5", "HTTP status & redirect"),
            ("6", "Single TCP port check"),
            ("7", "Common ports check"),
            ("8", "Ping host"),
            ("9", "Traceroute"),
            ("10", "TLS certificate details"),
            ("11", "WHOIS lookup"),
            ("12", "Local network info"),
            ("13", "Subnet calculator"),
            ("14", "Nmap scanner"),
            ("15", "Install dependencies"),
        )
        for key, label in options:
            print(f"  {paint(key.rjust(2), Color.CYAN)}  {label}")
        print(f"  {paint('16', Color.CYAN)}  Credits & safety")
        print(f"  {paint('17', Color.RED)}  Exit")
        choice = input(paint("\nSelect option: ", Color.GREEN)).strip()
        if choice == "1":
            dns_lookup()
        elif choice == "2":
            dns_addresses()
        elif choice == "3":
            reverse_dns()
        elif choice == "4":
            http_headers()
        elif choice == "5":
            http_status()
        elif choice == "6":
            tcp_port_check()
        elif choice == "7":
            common_ports_check()
        elif choice == "8":
            ping_host()
        elif choice == "9":
            traceroute_host()
        elif choice == "10":
            tls_certificate()
        elif choice == "11":
            whois_lookup()
        elif choice == "12":
            local_network_info()
        elif choice == "13":
            subnet_calculator()
        elif choice == "14":
            nmap_menu()
        elif choice == "15":
            install_dependencies()
        elif choice == "16":
            title("CREDITS & SAFETY")
            print("developer: Wahyu Katnoko")
            print("co-developer: Echarina Bizulifah Putri")
            print(paint("Use the scanner only on systems you own or are explicitly authorized to test.", Color.YELLOW))
        elif choice == "17":
            print(paint("\nThanks for using NetScope CLI.", Color.CYAN))
            return
        else:
            print(paint("Unknown choice.", Color.RED))
        input(paint("\nPress Enter to continue...", Color.DIM))


def main() -> None:
    try:
        banner()
        menu()
    except (EOFError, KeyboardInterrupt):
        print(paint("\n\nKeluar.", Color.YELLOW))


if __name__ == "__main__":
    main()
