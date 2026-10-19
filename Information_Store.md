# Information Store

This directory contains NetScope's local feature history. Each JSON file stores records produced by the corresponding diagnostic feature.

The files are intended to be read through `python3 netscope_report.py`, which renders them as numbered, human-readable sections instead of raw JSON.

- `nmap.json`: all-profile Nmap runs from `netscope-nmap.py` and the main CLI.
- `dns.json`: hostname-to-IP DNS lookups.
- `dns_addresses.json`: all IPv4/IPv6 addresses returned by DNS.
- `reverse_dns.json`: reverse DNS lookups.
- `http.json`: one-off report records.
- `http_headers.json`: HTTP response-header checks.
- `http_status.json`: HTTP status and redirect checks.
- `tcp.json`: single-port TCP checks.
- `common_ports.json`: fixed common-port checks.
- `ping.json`: ping diagnostics.
- `traceroute.json`: traceroute/tracepath diagnostics.
- `tls.json`: TLS certificate details.
- `whois.json`: WHOIS results.
- `subnet.json`: CIDR calculations.
- `local_network.json`: local network information.
- `dependency.json`: dependency installation history.

Use only with authorized targets. These files may contain sensitive operational data; review them before publishing a repository publicly.
