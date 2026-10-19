# NetScope CLI

NetScope is a colorful command-line network diagnostics toolkit for DNS inspection, HTTP checks, TCP connectivity testing, TLS certificate inspection, WHOIS lookups, subnet calculations, local network information, and authorized Nmap scanning.

> Use NetScope only against systems, hosts, and networks that you own or are explicitly authorized to inspect. Unauthorized scanning may be illegal or disruptive.

## Overview

NetScope provides a simple terminal interface for common network diagnostics. It is designed to run on Python 3.10 or newer and uses Python's standard library wherever possible. External command-line tools are used only for features that depend on utilities such as Nmap, ping, traceroute, and WHOIS.

The project contains two main interfaces:

- `netscope.py` is the interactive network utility menu.
- `netscope-nmap.py` runs every configured Nmap profile sequentially against one target.
- `netscope_report.py` displays saved results from the `Information/` directory in a readable format.

## Features

NetScope includes the following utilities:

1. **DNS lookup** — resolve a hostname to an IPv4 address.
2. **All DNS addresses** — display all IPv4 and IPv6 addresses returned by the resolver.
3. **Reverse DNS** — find the hostname associated with an IP address.
4. **HTTP header check** — inspect selected HTTP response headers and display the resolved address.
5. **HTTP status and redirect check** — inspect response status codes and final redirect URLs.
6. **TCP port check** — test one specific TCP port.
7. **Common ports check** — check a limited list of common service ports.
8. **Ping** — send four bounded ICMP echo requests when the local operating system provides ping.
9. **Traceroute** — run a bounded traceroute or tracepath operation.
10. **TLS certificate** — inspect TLS version, cipher, subject, issuer, and validity information.
11. **WHOIS lookup** — query the local WHOIS command-line utility.
12. **Local network information** — display local hostname and detected addresses.
13. **Subnet calculator** — calculate network address, netmask, broadcast, prefix, and usable hosts.
14. **Nmap scanner** — select one of ten Nmap scan profiles.
15. **Dependency installer** — detect and install required external command-line tools.

## Nmap Matrix Runner

`netscope-nmap.py` is the automated Nmap interface. It runs all configured profiles one after another instead of requiring manual selection.

```bash
python3 netscope-nmap.py example.com
```

The runner provides:

- A colored terminal banner and progress display.
- Sequential execution of all configured profiles.
- Red error messages for unavailable or failed scans.
- Automatic continuation after a profile fails.
- Timeout protection for each profile.
- Hidden resolved IP output in the visible terminal results.
- Saved scan history in `Information/nmap.json`.

A custom port list can be supplied for the specific-port profile:

```bash
python3 netscope-nmap.py example.com --ports 22,80,443
```

The timeout is configurable in seconds:

```bash
python3 netscope-nmap.py example.com --timeout 120
```

Only run Nmap profiles against authorized targets. Some profiles, including SYN and operating-system detection, may require elevated privileges and may not be supported in every environment.

## Requirements

- Python 3.10 or newer.
- Nmap for Nmap features.
- `ping` for the ping feature.
- `traceroute` or `tracepath` for route tracing.
- `whois` for WHOIS lookups.

NetScope does not require third-party Python packages for normal operation.

## Installation

Clone or download the project, then enter its directory:

```bash
git clone https://github.com/USERNAME/netscope-cli.git
cd netscope-cli
```

Start the interactive application:

```bash
python3 netscope.py
```

### Installing external tools manually

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install nmap iputils-ping traceroute whois
```

On Fedora or RHEL:

```bash
sudo dnf install nmap iputils traceroute whois
```

On Arch Linux:

```bash
sudo pacman -S nmap iputils traceroute whois
```

On Termux:

```bash
pkg install nmap iputils traceroute whois
```

Alternatively, open `netscope.py` and select menu option **15** to use the built-in dependency installer.

## Usage

### Interactive menu

```bash
python3 netscope.py
```

The interactive menu guides you through target input, validation, execution, and colored results.

### Report viewer

```bash
python3 netscope_report.py
```

The report viewer reads feature history files from `Information/` and displays them as numbered, human-readable sections. It does not print raw JSON objects as the primary view.

To create a one-off DNS and HTTP report:

```bash
python3 netscope_report.py example.com --output report.md
```

JSON output is also supported:

```bash
python3 netscope_report.py example.com --output report.json
```

## Information history

NetScope stores feature history in separate JSON files inside `Information/`:

```text
Information/
├── common_ports.json
├── dependency.json
├── dns.json
├── dns_addresses.json
├── http.json
├── http_headers.json
├── http_status.json
├── local_network.json
├── nmap.json
├── ping.json
├── reverse_dns.json
├── subnet.json
├── tcp.json
├── tls.json
├── traceroute.json
└── whois.json
```

Each file contains a list of records generated by its matching feature. Empty files contain an empty list until that feature is used.

Network history may contain sensitive operational information. Review the contents of `Information/` before sharing the project directory publicly.

## Development commands

Run the unit tests:

```bash
python3 -m unittest discover -s tests -v
```

Run a syntax check for all Python modules:

```bash
python3 -m py_compile netscope.py netscope-nmap.py netscope_report.py netscope_storage.py
```

The project also provides shortcuts through `package.json`:

```bash
npm start
npm test
npm run check
npm run report
npm run nmap-all -- example.com
```

Makefile shortcuts are available as well:

```bash
make start
make test
make check
make report
make nmap-all
```

## Project structure

```text
netscope-cli/
├── Information/              # per-feature JSON history
├── tests/                    # automated tests
├── .github/workflows/        # continuous integration workflow
├── netscope.py               # main interactive CLI
├── netscope-nmap.py          # colored all-profile Nmap runner
├── netscope_report.py        # readable history viewer
├── netscope_storage.py       # JSON storage helpers
├── package.json              # command runner and project metadata
├── pyproject.toml             # Python package metadata
├── Makefile                  # development shortcuts
├── SECURITY.md               # responsible-use policy
├── CHANGELOG.md              # release history
├── LICENSE                   # MIT license
└── README.md                 # project documentation
```

## Safety notes

NetScope is intended for diagnostics, inventory, and authorized security testing. It does not provide DDoS functionality, traffic flooding, credential theft, exploitation, or evasion features.

Nmap commands are constructed as argument lists and executed without a shell. Inputs are validated before network operations begin, and Nmap failures are handled without stopping the remaining profiles in the matrix runner.

Always follow the rules, policies, and authorization requirements that apply to the target environment.

## License

Released under the MIT License. See [LICENSE](LICENSE) for the full text.
