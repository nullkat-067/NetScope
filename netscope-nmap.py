#!/usr/bin/env python3
"""Run every NetScope Nmap profile against one authorized web target."""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone

from netscope import SCAN_PROFILES, build_nmap_command, resolve_target
from netscope_storage import save_record

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def red(text: str) -> str:
    return f"{RED}{text}{RESET}"


def green(text: str) -> str:
    return f"{GREEN}{text}{RESET}"


def cyan(text: str) -> str:
    return f"{CYAN}{text}{RESET}"


def yellow(text: str) -> str:
    return f"{YELLOW}{text}{RESET}"


def banner() -> None:
    print(cyan(r"""
╔══════════════════════════════════════════════════════════════════╗
║                 NETSCOPE // NMAP MATRIX                        ║
║            authorized multi-profile scanner                     ║
╚══════════════════════════════════════════════════════════════════╝
"""))
    print(f"{DIM}All profiles run sequentially • resolved IP output is hidden{RESET}\n")


def progress(index: int, total: int, label: str) -> None:
    filled = "█" * index
    empty = "░" * (total - index)
    print(f"{BLUE}[{index:02}/{total:02}] {filled}{empty}{RESET} {BOLD}{label}{RESET}")


def output_panel(output: str) -> None:
    if not output:
        return
    print(f"{DIM}┌─ nmap output ──────────────────────────────────────────────────┐{RESET}")
    for line in output.splitlines():
        print(f"{DIM}│{RESET} {line}")
    print(f"{DIM}└───────────────────────────────────────────────────────────────┘{RESET}")


def hide_ip(text: str, ip_address: str) -> str:
    """Redact the resolved address from visible output and stored history."""
    return text.replace(ip_address, "[hidden-ip]")


def profile_command(profile_key: str, target: str, custom_ports: str) -> list[str]:
    profile = next(profile for profile in SCAN_PROFILES if profile.key == profile_key)
    return build_nmap_command(profile, target, custom_ports if profile_key == "5" else None)


def run_profile(profile_key: str, target: str, resolved_ip: str, custom_ports: str, timeout: int) -> dict:
    profile = next(profile for profile in SCAN_PROFILES if profile.key == profile_key)
    started = datetime.now(timezone.utc).isoformat()
    label = profile.label
    try:
        command = profile_command(profile_key, target, custom_ports)
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        output = hide_ip((completed.stdout + "\n" + completed.stderr).strip(), resolved_ip)
        if completed.returncode == 0:
            print(green(f"  ✓ SUCCESS  {label}"))
            output_panel(output)
            return {
                "profile": label,
                "status": "success",
                "returncode": completed.returncode,
                "output": output,
                "started_at": started,
            }
        reason = output or f"Nmap exited with code {completed.returncode}"
        print(red(f"  error nmap {label} {reason}"))
        return {
            "profile": label,
            "status": "error",
            "returncode": completed.returncode,
            "error": reason,
            "started_at": started,
        }
    except FileNotFoundError as exc:
        reason = f"Nmap executable not found: {exc}"
    except subprocess.TimeoutExpired:
        reason = f"scan timed out after {timeout} seconds"
    except (OSError, ValueError) as exc:
        reason = str(exc)

    print(red(f"  error nmap {label} {reason}"))
    return {
        "profile": label,
        "status": "error",
        "error": reason,
        "started_at": started,
    }


def run_all(target_name: str, custom_ports: str, timeout: int) -> int:
    try:
        resolved_ip = resolve_target(target_name)
    except ValueError as exc:
        print(red(f"error nmap target {exc}"))
        return 2

    banner()
    print(f"{MAGENTA}{BOLD}TARGET{RESET}  {target_name}")
    print(f"{MAGENTA}{BOLD}PORTS{RESET}   {custom_ports} (custom-port profile)\n")

    scans = []
    for index, profile in enumerate(SCAN_PROFILES, 1):
        progress(index, len(SCAN_PROFILES), profile.label)
        scans.append(run_profile(profile.key, resolved_ip, resolved_ip, custom_ports, timeout))
        print()

    save_record(
        "nmap",
        {
            "target": target_name,
            "ip_hidden": True,
            "custom_ports": custom_ports,
            "scan_count": len(scans),
            "scans": scans,
        },
    )
    successful = sum(item["status"] == "success" for item in scans)
    failed = len(scans) - successful
    print(cyan("╔══════════════════════════════════════════════════════════════════╗"))
    print(cyan("║                    SCAN COMPLETE                               ║"))
    print(cyan("╚══════════════════════════════════════════════════════════════════╝"))
    print(f"  {green('SUCCESS')} : {successful}")
    print(f"  {red('ERROR')}   : {failed}")
    print(f"  {DIM}History  : Information/nmap.json{RESET}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run every NetScope Nmap profile.")
    parser.add_argument("target", nargs="?", help="Authorized hostname or web domain")
    parser.add_argument("--ports", default="80,443", help="Ports for the custom-port profile")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout per profile in seconds")
    args = parser.parse_args()
    target = args.target or input("Web hostname: ").strip()
    if not target:
        print(red("error nmap target target cannot be empty"))
        return 2
    if args.timeout < 1 or args.timeout > 900:
        parser.error("--timeout must be between 1 and 900 seconds")
    return run_all(target, args.ports, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
