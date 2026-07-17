#!/usr/bin/env python3
"""
Batch-check proxy exit IPs for fraud/reputation score before pointing a browser at them.

Usage:
    python proxy_ip_check.py proxies.txt
    python proxy_ip_check.py proxies.txt --ip-filter 4
    python proxy_ip_check.py proxies.txt --ip-filter 6

proxies.txt format (one per line), matches your cliproxy style:
    http://host:port:username:password

Blank lines and lines starting with # are ignored.

--- IPQS API key setup (do this once, no more typing it each run) ---
Create a file named "ipqs_key.txt" in the SAME FOLDER as this script,
containing nothing but your key, e.g.:

    ipqs_key.txt
    ---------------
    abcd1234yourkeyhere

The script auto-loads it. Priority order: --ipqs-key flag > IPQS_KEY env var
> ipqs_key.txt file. If none are found, the script still runs, just without
fraud-score columns.

--- IP version filtering ---
Some proxies return IPv6 exit IPs (e.g. 2600:4040:a49e:b500:7548:83e3:1ee0:4541)
instead of IPv4. Use --ip-filter to only keep rows matching one format:
    --ip-filter 4    only keep IPv4 exit IPs
    --ip-filter 6    only keep IPv6 exit IPs
    --ip-filter any  keep both (default)

Free tier notes:
  - ip-api.com: no key needed, ~45 req/min, gives proxy/hosting/mobile flags.
  - ipqualityscore.com: free tier needs a key (sign up at ipqualityscore.com),
    gives an actual 0-100 fraud score.

--- Saving a shortlist of clean proxies ---
    python proxy_ip_check.py proxies.txt --ip-filter 6 --save-clean clean_ips.txt

Writes only the "clean" proxy lines (ready to reuse) to clean_ips.txt:
  - With an IPQS key: fraud score <= --max-fraud-score (default 40),
    AND not flagged as proxy/vpn/recent_abuse by IPQS.
  - Without an IPQS key: falls back to the free ip-api.com proxy/hosting flags.
"""

import argparse
import ipaddress
import os
import re
import sys
import time
import requests

from rich.console import Console
from rich.table import Table

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(SCRIPT_DIR, "ipqs_key.txt")

PROXY_LINE_RE = re.compile(
    r"^((?P<scheme>https?)://)?(?P<host>[^:]+):(?P<port>\d+):(?P<user>[^:]+):(?P<pw>.+)$"
)

console = Console()


def load_ipqs_key(cli_key):
    if cli_key:
        console.print("[dim]IPQS key source: --ipqs-key flag[/dim]")
        return cli_key.strip()
    env_key = os.environ.get("IPQS_KEY")
    if env_key:
        console.print("[dim]IPQS key source: IPQS_KEY env var[/dim]")
        return env_key.strip()
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, encoding="utf-8-sig") as f:  # utf-8-sig strips a BOM if present
            key = f.read().strip().strip('"').strip("'")
            if key and key != "PASTE_YOUR_IPQS_API_KEY_HERE":
                console.print(f"[dim]IPQS key source: {KEY_FILE}[/dim]")
                return key
            elif key == "PASTE_YOUR_IPQS_API_KEY_HERE":
                console.print(f"[yellow]{KEY_FILE} still has the placeholder text — "
                               "replace it with your real key.[/yellow]")
    return None


def parse_proxy_line(line):
    m = PROXY_LINE_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    scheme = d["scheme"] or "http"
    proxy_url = f"{scheme}://{d['user']}:{d['pw']}@{d['host']}:{d['port']}"
    return {"raw": line.strip(), "proxy_url": proxy_url, "host": d["host"]}


def ip_version(ip):
    try:
        return ipaddress.ip_address(ip).version  # 4 or 6
    except ValueError:
        return None


def get_exit_ip(proxy_url, timeout=15):
    try:
        r = requests.get(
            "https://api64.ipify.org?format=json",
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json().get("ip"), None
    except Exception as e:
        return None, str(e)


def check_ip_api(ip):
    """Free, no key. Returns proxy/hosting flags + geo/ISP. Works for IPv4 and IPv6."""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,"
            f"city,isp,org,as,proxy,hosting,mobile",
            timeout=10,
        )
        return r.json()
    except Exception as e:
        return {"status": "fail", "message": str(e)}


def verify_ipqs_key(key):
    """One cheap call against a known-safe IP (Google DNS) just to confirm the key works."""
    try:
        r = requests.get(
            f"https://ipqualityscore.com/api/json/ip/{key}/8.8.8.8",
            timeout=10,
        )
        data = r.json()
        if data.get("success") is False:
            return False, data.get("message", "unknown error")
        return True, None
    except Exception as e:
        return False, str(e)


def check_ipqs(ip, key):
    """Requires free API key from ipqualityscore.com."""
    try:
        r = requests.get(
            f"https://ipqualityscore.com/api/json/ip/{key}/{ip}"
            f"?strictness=1&allow_public_access_points=true",
            timeout=10,
        )
        return r.json()
    except Exception as e:
        return {"success": False, "message": str(e)}


def risk_style(fraud_score):
    if fraud_score == "?" or fraud_score is None:
        return "dim", "?"
    try:
        score = int(fraud_score)
    except (ValueError, TypeError):
        return "dim", "?"
    if score >= 75:
        return "bold red", "HIGH"
    if score >= 40:
        return "bold yellow", "MED"
    return "bold green", "LOW"


def bool_style(val):
    if val is True:
        return "[red]True[/red]"
    if val is False:
        return "[green]False[/green]"
    return "[dim]?[/dim]"


def is_clean(row, has_ipqs, max_fraud_score):
    """Same 'clean' definition used for both the --save-clean file and the table sort/marker."""
    if row.get("exit_ip") == "ERROR":
        return False
    if has_ipqs:
        score = row.get("ipqs_fraud_score", "?")
        try:
            score_val = int(score)
        except (ValueError, TypeError):
            return False  # unknown score, don't count as clean
        if score_val > max_fraud_score:
            return False
        if row.get("ipqs_proxy") is True or row.get("ipqs_vpn") is True or row.get("ipqs_recent_abuse") is True:
            return False
        return True
    else:
        return not (row.get("is_proxy_flag") is True or row.get("is_hosting_flag") is True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("proxy_file", help="text file with one proxy per line")
    ap.add_argument("--ipqs-key", default=None, help="IPQualityScore API key (optional, see file header)")
    ap.add_argument(
        "--ip-filter",
        choices=["4", "6", "any"],
        default="any",
        help="Only keep results matching this IP version (default: any)",
    )
    ap.add_argument(
        "--save-clean",
        metavar="FILE",
        default=None,
        help="Write a shortlist of 'clean' proxies (passing --max-fraud-score, "
             "not flagged as proxy/vpn/recent_abuse) to this file, one proxy line per row.",
    )
    ap.add_argument(
        "--max-fraud-score",
        type=int,
        default=40,
        help="Fraud score threshold (0-100) for a proxy to count as 'clean' when using "
             "--save-clean. Default: 40 (only meaningful if an IPQS key is set).",
    )
    ap.add_argument(
        "--clean-only",
        action="store_true",
        help="Only print clean proxies in the terminal table (still checks all of them). "
             "Clean ones are also always sorted to the top and marked with a Clean column.",
    )
    args = ap.parse_args()
    ipqs_key = load_ipqs_key(args.ipqs_key)

    if not ipqs_key:
        console.print("[yellow]No IPQS key found (checked --ipqs-key, IPQS_KEY env var, ipqs_key.txt). "
                       "Running without fraud scores.[/yellow]")
    else:
        ok, msg = verify_ipqs_key(ipqs_key)
        if not ok:
            console.print(f"[bold red]IPQS key check failed: {msg}[/bold red]")
            console.print("[yellow]Continuing without fraud scores so we don't waste calls on a broken key.[/yellow]")
            ipqs_key = None
        else:
            console.print("[green]IPQS key verified.[/green]")

    with open(args.proxy_file) as f:
        lines = [l for l in f if l.strip() and not l.strip().startswith("#")]

    rows = []
    for line in lines:
        parsed = parse_proxy_line(line)
        if not parsed:
            console.print(f"[dim][skip] couldn't parse: {line.strip()}[/dim]")
            continue

        console.print(f"[dim]checking {parsed['host']} ...[/dim]")
        exit_ip, err = get_exit_ip(parsed["proxy_url"])
        if err:
            rows.append({"host": parsed["host"], "exit_ip": "ERROR", "version": "-", "detail": err})
            continue

        version = ip_version(exit_ip)
        if args.ip_filter != "any" and str(version) != args.ip_filter:
            console.print(f"[dim]  -> {exit_ip} is IPv{version}, skipped (filter={args.ip_filter})[/dim]")
            continue

        geo = check_ip_api(exit_ip)
        row = {
            "raw": parsed["raw"],
            "host": parsed["host"],
            "exit_ip": exit_ip,
            "version": f"IPv{version}" if version else "?",
            "country": geo.get("country", "?"),
            "city": geo.get("city", "?"),
            "isp": geo.get("isp", "?"),
            "is_proxy_flag": geo.get("proxy", "?"),
            "is_hosting_flag": geo.get("hosting", "?"),
        }

        if ipqs_key:
            ipqs = check_ipqs(exit_ip, ipqs_key)
            row["ipqs_fraud_score"] = ipqs.get("fraud_score", "?")
            row["ipqs_proxy"] = ipqs.get("proxy", "?")
            row["ipqs_vpn"] = ipqs.get("vpn", "?")
            row["ipqs_recent_abuse"] = ipqs.get("recent_abuse", "?")
            time.sleep(0.5)  # be polite to free tier rate limits

        rows.append(row)

    if not rows:
        console.print("[yellow]No results to show (empty file, all filtered out, or all errored).[/yellow]")
        return

    has_ipqs = any("ipqs_fraud_score" in r for r in rows)

    # Sort: clean ones first, then by fraud score ascending (unknown/'?' scores sink to the bottom).
    def sort_key(r):
        clean = is_clean(r, has_ipqs, args.max_fraud_score)
        if has_ipqs:
            try:
                score = int(r.get("ipqs_fraud_score", "?"))
            except (ValueError, TypeError):
                score = 999
        else:
            score = 0 if clean else 999
        return (not clean, score)

    rows.sort(key=sort_key)

    display_rows = [r for r in rows if is_clean(r, has_ipqs, args.max_fraud_score)] if args.clean_only else rows

    table = Table(show_lines=False, header_style="bold cyan")
    table.add_column("Clean")
    table.add_column("Host")
    table.add_column("Exit IP")
    table.add_column("Ver")
    table.add_column("Country")
    table.add_column("City")
    table.add_column("ISP")
    table.add_column("Proxy?")
    table.add_column("Hosting?")
    if has_ipqs:
        table.add_column("Fraud Score")
        table.add_column("Risk")
        table.add_column("IPQS Proxy")
        table.add_column("IPQS VPN")
        table.add_column("Recent Abuse")

    for r in display_rows:
        clean_mark = "[bold green]✔[/bold green]" if is_clean(r, has_ipqs, args.max_fraud_score) else "[dim]-[/dim]"

        if r.get("exit_ip") == "ERROR":
            table.add_row("[red]✘[/red]", r["host"], "[red]ERROR[/red]", "-", r.get("detail", ""), "", "", "", "",
                          *(["", "", "", "", ""] if has_ipqs else []))
            continue

        base = [
            clean_mark,
            r["host"],
            r["exit_ip"],
            r["version"],
            str(r.get("country", "?")),
            str(r.get("city", "?")),
            str(r.get("isp", "?")),
            bool_style(r.get("is_proxy_flag")),
            bool_style(r.get("is_hosting_flag")),
        ]
        if has_ipqs:
            score = r.get("ipqs_fraud_score", "?")
            style, label = risk_style(score)
            base += [
                f"[{style}]{score}[/{style}]",
                f"[{style}]{label}[/{style}]",
                bool_style(r.get("ipqs_proxy")),
                bool_style(r.get("ipqs_vpn")),
                bool_style(r.get("ipqs_recent_abuse")),
            ]
        table.add_row(*base)

    console.print(table)
    total_clean = sum(1 for r in rows if is_clean(r, has_ipqs, args.max_fraud_score))
    console.print(f"[bold]{total_clean} of {len(rows)}[/bold] proxies are clean "
                  f"(fraud score ≤ {args.max_fraud_score}, not flagged proxy/vpn/abuse)." if has_ipqs else
                  f"[bold]{total_clean} of {len(rows)}[/bold] proxies are clean (not flagged proxy/hosting).")

    if args.save_clean:
        clean_rows = [r for r in rows if is_clean(r, has_ipqs, args.max_fraud_score)]

        with open(args.save_clean, "w") as f:
            for r in clean_rows:
                f.write(r["raw"] + "\n")

        if clean_rows:
            console.print(f"[bold green]Saved {len(clean_rows)} clean proxy line(s) to {args.save_clean}[/bold green]")
        else:
            console.print(f"[yellow]No proxies passed the clean threshold — {args.save_clean} was written but is empty.[/yellow]")


if __name__ == "__main__":
    main()