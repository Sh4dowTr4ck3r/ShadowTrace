#!/usr/bin/env python3
"""
ShadowTrace - Advanced OSINT Investigation Tool
Designed for cyber investigations, digital forensics, and security operations.
"""

import requests
import urllib.parse
import json
import hashlib
import socket
import re
import os
import sys
import csv
import time
import struct
import email
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Optional: Pillow for EXIF extraction
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

# ============================================================
# Configuration
# ============================================================
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ShadowTrace_config.json")
DEFAULT_CONFIG = {
    "api_keys": {
        "shodan": "",
        "hibp": "",
        "abuseipdb": "",
        "virustotal": "",
        "courtlistener": "",
        "opencorporates": ""
    },
    "output_dir": "reports",
    "timeout": 10,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# ANSI Colors
COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m"
}

# Global state
session = requests.Session()
findings = defaultdict(list)
config = {}

# Known disposable email domains (subset)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "dispostable.com", "trashmail.com", "fakeinbox.com", "mailnesia.com",
    "maildrop.cc", "discard.email", "temp-mail.org", "10minutemail.com",
    "burnermail.io", "tempail.com", "mohmal.com", "getnada.com"
}


def c(text, color):
    """Colorize text for terminal output."""
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def banner():
    art = r"""
       _____ __              __             ______
      / ___// /_  ____ _____/ /___ _      _/_  __/________ ________
      \__ \/ __ \/ __ `/ __  / __ \ | /| / // / / ___/ __ `/ ___/ _ \
     ___/ / / / / /_/ / /_/ / /_/ / |/ |/ // / / /  / /_/ / /__/  __/
    /____/_/ /_/\__,_/\__,_/\____/|__/|__//_/ /_/   \__,_/\___/\___/
    """
    print(c(art, "red"))
    print(c("    +-----------------------------------------------------------+", "dim"))
    print(c("    |", "dim") + c("  ShadowTrace", "red") + c(" // ", "dim") + c("Advanced OSINT Investigation Toolkit", "cyan") + c("  |", "dim"))
    print(c("    |", "dim") + c("  v2.0", "green") + c("  |  ", "dim") + c("github.com/Sh4dowTr4ck3r/ShadowTrace", "white") + c("       |", "dim"))
    print(c("    |", "dim") + c("  by Sh4dowTr4ck3r", "magenta") + c("                                    |", "dim"))
    print(c("    +-----------------------------------------------------------+", "dim"))
    print()


def load_config():
    global config
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            loaded = json.load(f)
        # Merge with defaults so new keys are always present
        config = DEFAULT_CONFIG.copy()
        for key, val in loaded.items():
            if key == "api_keys" and isinstance(val, dict):
                config["api_keys"].update(val)
            else:
                config[key] = val
    else:
        config = DEFAULT_CONFIG.copy()
        save_config()
    session.headers.update({"User-Agent": config.get("user_agent", DEFAULT_CONFIG["user_agent"])})


def save_config():
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def get_api_key(service):
    val = config.get("api_keys", {}).get(service, "")
    if not val or val.upper() in ("YOUR_KEY", "API_KEY", "YOUR_KEY_HERE", "API_KEY_HERE"):
        return ""
    return val


def log_finding(category, entry):
    """Log a finding for later report export."""
    findings[category].append({
        "timestamp": datetime.now().isoformat(),
        **entry
    })


def safe_request(url, method="GET", timeout=None, headers=None, allow_redirects=True):
    """Make a request with error handling. Returns (response, error_string)."""
    t = timeout or config.get("timeout", 10)
    try:
        resp = session.request(method, url, timeout=t, headers=headers or {},
                               allow_redirects=allow_redirects)
        return resp, None
    except requests.exceptions.Timeout:
        return None, "timeout"
    except requests.exceptions.ConnectionError:
        return None, "connection_error"
    except requests.exceptions.RequestException as e:
        return None, str(e)


def ensure_output_dir():
    out = config.get("output_dir", "reports")
    os.makedirs(out, exist_ok=True)
    return out


def resolve_user_file_path(raw_path):
    """Resolve user-entered file paths against common base directories."""
    if not raw_path:
        return None

    cleaned = raw_path.strip().strip('"').strip("'")
    if not cleaned:
        return None

    candidate = Path(os.path.expandvars(os.path.expanduser(cleaned)))
    script_dir = Path(__file__).resolve().parent
    cwd = Path.cwd()

    candidates = []
    if candidate.is_absolute():
        candidates.append(candidate)
    else:
        candidates.append(candidate)
        candidates.append(cwd / candidate)
        candidates.append(script_dir / candidate)

    # If user pastes "ShadowTrace\\file.png" while already in ShadowTrace,
    # also try dropping that redundant leading folder.
    parts_lower = [p.lower() for p in candidate.parts]
    if parts_lower and parts_lower[0] == script_dir.name.lower():
        trimmed = Path(*candidate.parts[1:]) if len(candidate.parts) > 1 else Path(".")
        candidates.append(cwd / trimmed)
        candidates.append(script_dir / trimmed)

    for path_candidate in candidates:
        try:
            resolved = path_candidate.resolve(strict=False)
        except Exception:
            resolved = path_candidate
        if resolved.is_file():
            return str(resolved)

    return None


# ============================================================
# 2. Username Permutation Engine
# ============================================================
def generate_username_variants(base_input):
    """Generate username permutations from a name or base username."""
    variants = set()
    variants.add(base_input.lower())
    variants.add(base_input.lower().replace(" ", ""))
    variants.add(base_input.lower().replace(" ", "."))
    variants.add(base_input.lower().replace(" ", "_"))
    variants.add(base_input.lower().replace(" ", "-"))

    parts = base_input.lower().split()
    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
        variants.update([
            f"{first}{last}",
            f"{last}{first}",
            f"{first}.{last}",
            f"{last}.{first}",
            f"{first}_{last}",
            f"{first}-{last}",
            f"{first[0]}{last}",
            f"{first}{last[0]}",
            f"{first[0]}.{last}",
            f"{first[0]}_{last}",
            f"{last}{first[0]}",
            f"{first}{last}1",
            f"{first}{last}123",
            f"{first}.{last}1",
            f"{first}_{last}99",
            f"{first}{last}01",
            f"{first}{last}00",
            f"the{first}{last}",
            f"real{first}{last}",
            f"official{first}{last}",
            f"x{first}{last}",
            f"{first}{last}x",
        ])
        # Common birth year patterns
        for year in ["90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "00", "01", "02"]:
            variants.add(f"{first}{last}{year}")
            variants.add(f"{first[0]}{last}{year}")
    else:
        base = parts[0]
        variants.update([
            f"{base}1", f"{base}123", f"{base}_", f"{base}99",
            f"the{base}", f"real{base}", f"official{base}",
            f"x{base}", f"{base}x", f"{base}01", f"{base}00",
        ])

    return sorted(variants)


def check_username_across_platforms(username):
    """Check a single username across many platforms."""
    platforms = {
        "Twitter/X": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Facebook": f"https://www.facebook.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "Tumblr": f"https://{username}.tumblr.com",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Snapchat": f"https://www.snapchat.com/add/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Flickr": f"https://www.flickr.com/photos/{username}/",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Spotify": f"https://open.spotify.com/user/{username}",
        "DeviantArt": f"https://www.deviantart.com/{username}",
        "Keybase": f"https://keybase.io/{username}",
        "HackerNews": f"https://news.ycombinator.com/user?id={username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Bitbucket": f"https://bitbucket.org/{username}/",
        "Patreon": f"https://www.patreon.com/{username}",
        "Dribbble": f"https://dribbble.com/{username}",
        "Behance": f"https://www.behance.net/{username}",
        "Gravatar": f"https://en.gravatar.com/{username}",
        "About.me": f"https://about.me/{username}",
        "Cash App": f"https://cash.app/${username}",
        "Linktree": f"https://linktr.ee/{username}",
        "Replit": f"https://replit.com/@{username}",
    }

    found = []
    print(f"\n{c('[USERNAME SCAN]', 'cyan')} Target: {c(username, 'bold')}\n")

    for platform, url in platforms.items():
        resp, err = safe_request(url, allow_redirects=False)
        if err:
            indicator = c("  [?]", "yellow")
        elif resp.status_code == 200:
            indicator = c("  [+]", "green")
            found.append((platform, url))
            log_finding("username", {"username": username, "platform": platform, "url": url})
        elif resp.status_code in (301, 302):
            # Some sites redirect to login — might still mean account exists
            indicator = c("  [~]", "yellow")
        else:
            indicator = c("  [-]", "red")
        print(f"    {indicator} {platform}: {url}")

    print(f"\n  {c(f'Results: {len(found)} potential matches found', 'green')}")
    return found


def check_username_permutations(base_input):
    """Generate permutations and scan all of them."""
    variants = generate_username_variants(base_input)
    print(f"\n{c('[USERNAME PERMUTATION ENGINE]', 'cyan')}")
    print(f"  Generated {c(str(len(variants)), 'bold')} username variants from: {c(base_input, 'bold')}\n")

    for i, v in enumerate(variants):
        print(f"  {c(f'[{i+1}]', 'dim')} {v}")
    print()

    choice = input("  Check ALL variants across platforms? This will take a while. (y/n): ").strip().lower()
    if choice == "y":
        all_found = {}
        for v in variants:
            results = check_username_across_platforms(v)
            if results:
                all_found[v] = results
        print(f"\n{c('[PERMUTATION SUMMARY]', 'cyan')}")
        for uname, hits in all_found.items():
            print(f"  {c(uname, 'bold')}: {len(hits)} platforms")
            for platform, url in hits:
                print(f"    {c('[+]', 'green')} {platform}: {url}")
    else:
        pick = input("  Enter a specific username to check (or press Enter to go back): ").strip()
        if pick:
            check_username_across_platforms(pick)


# ============================================================
# 3. Email Intelligence
# ============================================================
def check_email_intel(email_address):
    print(f"\n{c('[EMAIL INTELLIGENCE]', 'cyan')} Target: {c(email_address, 'bold')}\n")

    local_part, domain = email_address.split("@") if "@" in email_address else (email_address, "")

    # --- Gravatar ---
    print(f"  {c('--- Gravatar ---', 'yellow')}")
    email_hash = hashlib.md5(email_address.strip().lower().encode()).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    gravatar_profile = f"https://en.gravatar.com/{email_hash}.json"
    resp, err = safe_request(gravatar_url)
    if resp is not None and resp.status_code == 200:
        print(f"    {c('[+]', 'green')} Gravatar avatar exists: {gravatar_url}")
        log_finding("email", {"type": "gravatar_avatar", "url": gravatar_url})
        # Try to get profile JSON
        resp2, _ = safe_request(gravatar_profile)
        if resp2 and resp2.status_code == 200:
            try:
                gdata = resp2.json()
                entry = gdata.get("entry", [{}])[0]
                display = entry.get("displayName", "N/A")
                about = entry.get("aboutMe", "N/A")
                location = entry.get("currentLocation", "N/A")
                print(f"    {c('[+]', 'green')} Display Name: {display}")
                print(f"    {c('[+]', 'green')} About: {about}")
                print(f"    {c('[+]', 'green')} Location: {location}")
                for acct in entry.get("accounts", []):
                    print(f"    {c('[+]', 'green')} Linked: {acct.get('shortname', '?')} -> {acct.get('url', '?')}")
                log_finding("email", {"type": "gravatar_profile", "name": display, "location": location})
            except (json.JSONDecodeError, IndexError, KeyError):
                pass
    else:
        print(f"    {c('[-]', 'red')} No Gravatar found")

    # --- Disposable Email Check ---
    print(f"\n  {c('--- Disposable Email Check ---', 'yellow')}")
    if domain in DISPOSABLE_DOMAINS:
        print(f"    {c('[!]', 'red')} WARNING: This is a known disposable/temporary email domain!")
        log_finding("email", {"type": "disposable", "domain": domain, "is_disposable": True})
    else:
        print(f"    {c('[OK]', 'green')} Domain '{domain}' is not in known disposable list")

    # --- MX Record Check ---
    print(f"\n  {c('--- Domain MX Records ---', 'yellow')}")
    try:
        import subprocess
        result = subprocess.run(["nslookup", "-type=mx", domain], capture_output=True, text=True, timeout=10)
        mx_lines = [l.strip() for l in result.stdout.split("\n") if "mail exchanger" in l.lower() or "mx" in l.lower()]
        if mx_lines:
            for line in mx_lines:
                print(f"    {c('[+]', 'green')} {line}")
        else:
            # Fallback: just show the output
            print(f"    {c('[i]', 'blue')} MX lookup output:")
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    print(f"      {line.strip()}")
    except Exception:
        print(f"    {c('[?]', 'yellow')} Could not resolve MX records")

    # --- Breach Exposure Links ---
    print(f"\n  {c('--- Breach Exposure ---', 'yellow')}")
    hibp_key = get_api_key("hibp")
    if hibp_key:
        hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email_address)}"
        resp, err = safe_request(hibp_url, headers={
            "hibp-api-key": hibp_key,
            "user-agent": "ShadowTrace-OSINT"
        })
        if resp is not None and resp.status_code == 200:
            breaches = resp.json()
            print(f"    {c('[!]', 'red')} Found in {len(breaches)} breaches:")
            for b in breaches:
                print(f"      - {b['Name']} ({b.get('BreachDate', '?')}) — {b.get('DataClasses', [])}")
            log_finding("email", {"type": "breaches", "count": len(breaches), "breaches": [b["Name"] for b in breaches]})
        elif resp is not None and resp.status_code == 404:
            print(f"    {c('[OK]', 'green')} Not found in any known breaches")
        else:
            print(f"    {c('[?]', 'yellow')} HIBP API returned: {resp.status_code if resp is not None else err}")
    else:
        print(f"    {c('[i]', 'blue')} No HIBP API key set. Manual check:")
        print(f"      -> https://haveibeenpwned.com/account/{urllib.parse.quote(email_address)}")

    # --- Email Permutations (verified via Gravatar) ---
    print(f"\n  {c('--- Checking Related Emails (Gravatar verify) ---', 'yellow')}")
    if len(local_part) > 2:
        common_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com"]
        perms = []
        for d in common_domains:
            if d != domain:
                perms.append(f"{local_part}@{d}")
        # Also try common variations of the local part
        if "." in local_part:
            no_dots = local_part.replace(".", "")
            for d in ["gmail.com", "yahoo.com", "outlook.com"]:
                perms.append(f"{no_dots}@{d}")
        for p in perms:
            p_hash = hashlib.md5(p.strip().lower().encode()).hexdigest()
            p_gravatar = f"https://www.gravatar.com/avatar/{p_hash}?d=404&s=1"
            resp_p, _ = safe_request(p_gravatar, timeout=5)
            if resp_p is not None and resp_p.status_code == 200:
                print(f"    {c('[MATCH]', 'green')} {p} — Gravatar exists (real account likely)")
                log_finding("email", {"type": "permutation_verified", "email": p})
            else:
                print(f"    {c('[--]', 'dim')} {p}")


# ============================================================
# 4. Enhanced GeoIP + IP Threat Intelligence
# ============================================================
def check_ip_intel(ip_address):
    print(f"\n{c('[IP INTELLIGENCE]', 'cyan')} Target: {c(ip_address, 'bold')}\n")

    # --- Basic GeoIP ---
    print(f"  {c('--- GeoIP ---', 'yellow')}")
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query"
    resp, err = safe_request(url)
    if resp is not None and resp.status_code == 200:
        data = resp.json()
        if data.get("status") == "success":
            print(f"    {c('[+]', 'green')} Country: {data.get('country', '?')} ({data.get('countryCode', '?')})")
            print(f"    {c('[+]', 'green')} Region: {data.get('regionName', '?')}")
            print(f"    {c('[+]', 'green')} City: {data.get('city', '?')} (ZIP: {data.get('zip', '?')})")
            print(f"    {c('[+]', 'green')} Coords: {data.get('lat', '?')}, {data.get('lon', '?')}")
            print(f"    {c('[+]', 'green')} Timezone: {data.get('timezone', '?')}")
            print(f"    {c('[+]', 'green')} ISP: {data.get('isp', '?')}")
            print(f"    {c('[+]', 'green')} Org: {data.get('org', '?')}")
            print(f"    {c('[+]', 'green')} AS: {data.get('as', '?')}")
            if data.get("proxy"):
                print(f"    {c('[!]', 'red')} PROXY/VPN/TOR DETECTED")
            if data.get("hosting"):
                print(f"    {c('[!]', 'yellow')} Hosting/Datacenter IP")
            log_finding("ip", {"type": "geoip", "ip": ip_address, **data})

            # Map link
            lat, lon = data.get("lat"), data.get("lon")
            if lat and lon:
                print(f"    {c('[MAP]', 'blue')} https://www.google.com/maps?q={lat},{lon}")
        else:
            print(f"    {c('[-]', 'red')} GeoIP failed: {data.get('message', 'unknown error')}")
    else:
        print(f"    {c('[!]', 'red')} GeoIP request failed: {err}")

    # --- Reverse DNS ---
    print(f"\n  {c('--- Reverse DNS ---', 'yellow')}")
    try:
        hostname = socket.gethostbyaddr(ip_address)
        print(f"    {c('[+]', 'green')} Hostname: {hostname[0]}")
        if hostname[1]:
            print(f"    {c('[+]', 'green')} Aliases: {', '.join(hostname[1])}")
        log_finding("ip", {"type": "rdns", "ip": ip_address, "hostname": hostname[0]})
    except socket.herror:
        print(f"    {c('[-]', 'red')} No reverse DNS record found")
    except Exception as e:
        print(f"    {c('[!]', 'yellow')} rDNS error: {e}")

    # --- AbuseIPDB ---
    print(f"\n  {c('--- Abuse / Threat Intel ---', 'yellow')}")
    abuseipdb_key = get_api_key("abuseipdb")
    if abuseipdb_key:
        abuse_url = f"https://api.abuseipdb.com/api/v2/check"
        resp, err = safe_request(abuse_url + f"?ipAddress={ip_address}&maxAgeInDays=90",
                                 headers={"Key": abuseipdb_key, "Accept": "application/json"})
        if resp is not None and resp.status_code == 200:
            adata = resp.json().get("data", {})
            score = adata.get("abuseConfidenceScore", 0)
            reports = adata.get("totalReports", 0)
            color = "red" if score > 50 else ("yellow" if score > 10 else "green")
            print(f"    {c(f'[{score}%]', color)} Abuse Confidence Score: {score}% ({reports} reports)")
            print(f"    {c('[i]', 'blue')} ISP: {adata.get('isp', '?')}")
            print(f"    {c('[i]', 'blue')} Usage: {adata.get('usageType', '?')}")
            print(f"    {c('[i]', 'blue')} Domain: {adata.get('domain', '?')}")
            log_finding("ip", {"type": "abuseipdb", "score": score, "reports": reports})
        else:
            print(f"    {c('[?]', 'yellow')} AbuseIPDB query failed")
    else:
        print(f"    {c('[->]', 'blue')} AbuseIPDB: https://www.abuseipdb.com/check/{ip_address}")

    # --- Shodan ---
    shodan_key = get_api_key("shodan")
    if shodan_key:
        print(f"\n  {c('--- Shodan ---', 'yellow')}")
        shodan_url = f"https://api.shodan.io/shodan/host/{ip_address}?key={shodan_key}"
        resp, err = safe_request(shodan_url)
        if resp is not None and resp.status_code == 200:
            sdata = resp.json()
            print(f"    {c('[+]', 'green')} OS: {sdata.get('os', '?')}")
            print(f"    {c('[+]', 'green')} Open Ports: {sdata.get('ports', [])}")
            print(f"    {c('[+]', 'green')} Hostnames: {sdata.get('hostnames', [])}")
            vulns = sdata.get("vulns", [])
            if vulns:
                print(f"    {c('[!]', 'red')} Known Vulns: {', '.join(vulns[:10])}")
            log_finding("ip", {"type": "shodan", "ports": sdata.get("ports"), "vulns": vulns})
        else:
            print(f"    {c('[?]', 'yellow')} Shodan query failed")
    else:
        print(f"    {c('[->]', 'blue')} Shodan: https://www.shodan.io/host/{ip_address}")

    # --- VirusTotal ---
    print(f"\n  {c('--- VirusTotal ---', 'yellow')}")
    vt_key = get_api_key("virustotal")
    if vt_key:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        resp, err = safe_request(vt_url, headers={"x-apikey": vt_key})
        if resp is not None and resp.status_code == 200:
            vdata = resp.json().get("data", {}).get("attributes", {})
            stats = vdata.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            color = "red" if malicious > 0 else "green"
            print(f"    {c(f'[{malicious}]', color)} Malicious detections: {malicious}, Suspicious: {suspicious}")
            log_finding("ip", {"type": "virustotal", "malicious": malicious, "suspicious": suspicious})
    else:
        print(f"    {c('[->]', 'blue')} VirusTotal: https://www.virustotal.com/gui/ip-address/{ip_address}")



# ============================================================
# 5. Domain Reconnaissance
# ============================================================
def check_domain_recon(domain):
    print(f"\n{c('[DOMAIN RECON]', 'cyan')} Target: {c(domain, 'bold')}\n")

    # --- DNS Records (via Cloudflare DoH — clean JSON, no local resolver noise) ---
    print(f"  {c('--- DNS Records ---', 'yellow')}")
    # DNS type number -> name mapping
    dns_types = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5, "SOA": 6}
    dns_type_names = {v: k for k, v in dns_types.items()}
    all_a_records = []

    for rtype, rtype_num in dns_types.items():
        doh_url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type={rtype}"
        resp, err = safe_request(doh_url, headers={"Accept": "application/dns-json"}, timeout=10)
        if resp is None or resp.status_code != 200:
            continue
        try:
            data = resp.json()
            answers = data.get("Answer", [])
            if not answers:
                continue
            for record in answers:
                rdata = record.get("data", "").strip()
                if not rdata:
                    continue
                # MX: "10 mail.example.com" — show priority and host separately
                if rtype == "MX":
                    parts = rdata.split(None, 1)
                    prio = parts[0] if len(parts) == 2 else "?"
                    host = parts[1].rstrip(".") if len(parts) == 2 else rdata
                    print(f"    {c('[+]', 'green')} MX  priority={prio}  {host}")
                elif rtype in ("NS", "CNAME"):
                    print(f"    {c('[+]', 'green')} {rtype:<5} {rdata.rstrip('.')}")
                elif rtype == "SOA":
                    print(f"    {c('[+]', 'green')} SOA   {rdata}")
                elif rtype == "TXT":
                    # Strip surrounding quotes
                    txt = rdata.strip('"')
                    print(f"    {c('[+]', 'green')} TXT   {txt}")
                else:
                    print(f"    {c('[+]', 'green')} {rtype:<5} {rdata}")
                    if rtype == "A":
                        all_a_records.append(rdata)
            log_finding("domain", {"type": "dns", "record": rtype,
                                   "data": [r.get("data", "") for r in answers]})
        except (json.JSONDecodeError, ValueError):
            pass

    # --- Hosting Detection ---
    if all_a_records:
        print(f"\n  {c('--- Hosting / Infrastructure Detection ---', 'yellow')}")
        github_pages_ips = set()
        for ip in all_a_records:
            parts = ip.split(".")
            if len(parts) == 4 and parts[0] == "185" and parts[1] == "199" and parts[2] in ("108","109","110","111"):
                github_pages_ips.add(ip)

        if github_pages_ips:
            print(f"    {c('[+]', 'green')} Hosted on GitHub Pages (IPs: {', '.join(github_pages_ips)})")
            log_finding("domain", {"type": "hosting", "platform": "GitHub Pages", "ips": list(github_pages_ips)})
        else:
            # Check NS / known CDN patterns
            ns_resp, _ = safe_request(f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=NS",
                                      headers={"Accept": "application/dns-json"}, timeout=10)
            hosting_detected = False
            if ns_resp is not None and ns_resp.status_code == 200:
                try:
                    ns_data = ns_resp.json().get("Answer", [])
                    ns_vals = [r.get("data","").lower() for r in ns_data]
                    if any("cloudflare" in n for n in ns_vals):
                        print(f"    {c('[+]', 'green')} DNS managed by Cloudflare (proxied — real IP hidden)")
                        hosting_detected = True
                    if any("awsdns" in n for n in ns_vals):
                        print(f"    {c('[+]', 'green')} DNS managed by AWS Route53")
                        hosting_detected = True
                    if any("google" in n for n in ns_vals):
                        print(f"    {c('[+]', 'green')} DNS managed by Google Cloud DNS")
                        hosting_detected = True
                except (json.JSONDecodeError, ValueError):
                    pass
            if not hosting_detected:
                print(f"    {c('[i]', 'blue')} Hosting provider not auto-identified from IPs/NS")

    # --- Certificate Transparency (crt.sh) ---
    print(f"\n  {c('--- Certificate Transparency (crt.sh) ---', 'yellow')}")
    print(f"    Querying crt.sh for SSL certificates...")
    crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp, err = safe_request(crt_url, timeout=30)
    if resp is not None and resp.status_code == 200:
        try:
            certs = resp.json()
            # Deduplicate by common name
            seen_names = set()
            unique_certs = []
            for cert in certs:
                cn = cert.get("common_name", "")
                if cn not in seen_names:
                    seen_names.add(cn)
                    unique_certs.append(cert)

            print(f"    {c(f'[+] Found {len(unique_certs)} unique certificate entries', 'green')}")
            for cert in unique_certs[:30]:  # Show first 30
                cn = cert.get("common_name", "?")
                issuer = cert.get("issuer_name", "?")
                not_after = cert.get("not_after", "?")
                print(f"      {c('[CERT]', 'blue')} {cn} (expires: {not_after})")
            if len(unique_certs) > 30:
                print(f"      ... and {len(unique_certs) - 30} more")

            # Extract subdomains
            subdomains = set()
            for cert in certs:
                name = cert.get("common_name", "")
                if name and name != domain and domain in name:
                    subdomains.add(name.lstrip("*."))
                name_value = cert.get("name_value", "")
                for n in name_value.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n and n != domain and domain in n:
                        subdomains.add(n)

            if subdomains:
                print(f"\n    {c(f'[+] Discovered {len(subdomains)} subdomains:', 'green')}")
                for sd in sorted(subdomains)[:50]:
                    print(f"      {c('[SUB]', 'magenta')} {sd}")
                log_finding("domain", {"type": "subdomains", "count": len(subdomains), "list": sorted(subdomains)[:50]})
        except (json.JSONDecodeError, ValueError):
            print(f"    {c('[?]', 'yellow')} Could not parse crt.sh response")
    else:
        print(f"    {c('[!]', 'red')} crt.sh query failed: {err}")

    # --- Wayback Machine ---
    print(f"\n  {c('--- Wayback Machine ---', 'yellow')}")
    wb_url = f"https://web.archive.org/web/timemap/json?url={domain}&limit=10&output=json"
    resp, err = safe_request(wb_url, timeout=15)
    if resp is not None and resp.status_code == 200:
        try:
            snapshots = resp.json()
            if len(snapshots) > 1:  # First row is headers
                print(f"    {c(f'[+] Found {len(snapshots)-1} archived snapshots', 'green')}")
                for snap in snapshots[1:6]:  # Show first 5
                    ts = snap[1] if len(snap) > 1 else "?"
                    original = snap[2] if len(snap) > 2 else "?"
                    print(f"      {c('[SNAP]', 'blue')} {ts}: {original}")
                log_finding("domain", {"type": "wayback", "snapshots": len(snapshots) - 1})
            else:
                print(f"    {c('[-]', 'red')} No archived snapshots found")
        except (json.JSONDecodeError, ValueError):
            print(f"    {c('[?]', 'yellow')} Could not parse Wayback response")
    else:
        print(f"    {c('[-]', 'red')} Wayback query failed")

    # --- WHOIS via RDAP ---
    print(f"\n  {c('--- WHOIS (RDAP) ---', 'yellow')}")
    # Try TLD-specific RDAP servers (rdap.org blocks tool user-agents)
    tld = domain.rsplit(".", 1)[-1].lower()
    rdap_servers = {
        "com": "https://rdap.verisign.com/com/v1/domain/",
        "net": "https://rdap.verisign.com/net/v1/domain/",
        "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
        "io":  "https://rdap.iana.org/domain/",
        "co":  "https://rdap.iana.org/domain/",
    }
    rdap_base = rdap_servers.get(tld, "https://rdap.iana.org/domain/")
    rdap_url = f"{rdap_base}{domain}"
    resp, err = safe_request(rdap_url, timeout=15)
    if resp is not None and resp.status_code == 200:
        try:
            rdata = resp.json()
            # Registration dates
            for evt in rdata.get("events", []):
                action = evt.get("eventAction", "?")
                date = evt.get("eventDate", "?")
                print(f"    {c('[+]', 'green')} {action}: {date}")

            # Nameservers
            for ns in rdata.get("nameservers", []):
                print(f"    {c('[NS]', 'blue')} {ns.get('ldhName', '?')}")

            # Registrant info — only print non-empty fields
            for entity in rdata.get("entities", []):
                roles = entity.get("roles", [])
                vcard = entity.get("vcardArray", [None, []])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        val = field[3] if len(field) > 3 else ""
                        if not val or str(val).strip() in ("", "REDACTED FOR PRIVACY", "DATA REDACTED"):
                            continue
                        if field[0] == "fn":
                            print(f"    {c('[+]', 'green')} Contact ({', '.join(roles)}): {val}")
                        elif field[0] == "email":
                            print(f"    {c('[+]', 'green')} Email: {val}")
                        elif field[0] == "org":
                            print(f"    {c('[+]', 'green')} Org: {val}")
                        elif field[0] == "adr":
                            addr = " ".join(str(p) for p in (val if isinstance(val, list) else [val]) if str(p).strip())
                            if addr.strip():
                                print(f"    {c('[+]', 'green')} Address: {addr.strip()}")

            log_finding("domain", {"type": "rdap", "domain": domain})
        except (json.JSONDecodeError, ValueError, KeyError):
            print(f"    {c('[?]', 'yellow')} Could not parse RDAP response")
    else:
        print(f"    {c('[?]', 'yellow')} RDAP query failed — try: https://who.is/whois/{domain}")



# ============================================================
# 6. WiFi Network Recon
# ============================================================
def _decode_netsh(raw_bytes):
    """Decode netsh output bytes using OEM encoding (Windows console default)."""
    try:
        return raw_bytes.decode("oem", errors="replace")
    except (LookupError, AttributeError):
        return raw_bytes.decode("utf-8", errors="replace")


def scan_nearby_wifi():
    """Scan for nearby WiFi networks using OS-level commands.
    Returns (networks_list, error_string). error_string is None on success."""
    import subprocess
    networks = []

    if sys.platform == "win32":
        raw_output = None
        last_error = None

        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            capture_output=True, timeout=15
        )
        output = _decode_netsh(result.stdout)

        if "location permission" in output.lower():
            return [], "location_permission"

        if result.returncode == 0 and "SSID" in output:
            raw_output = output

        if raw_output:
            blocks = re.split(r'(?=^SSID\s+\d+\s*:)', raw_output, flags=re.MULTILINE)
            for block in blocks:
                ssid_m    = re.search(r'^SSID\s+\d+\s*:\s*(.+)', block, re.MULTILINE)
                bssid_m   = re.search(r'BSSID\s+1\s*:\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', block, re.MULTILINE)
                signal_m  = re.search(r'Signal\s*:\s*(\S+)', block, re.MULTILINE | re.IGNORECASE)
                channel_m = re.search(r'Channel\s*:\s*(\S+)', block, re.MULTILINE | re.IGNORECASE)
                band_m    = re.search(r'Band\s*:\s*(.+)$', block, re.MULTILINE | re.IGNORECASE)
                auth_m    = re.search(r'Authentication\s*:\s*(.+)$', block, re.MULTILINE | re.IGNORECASE)
                enc_m     = re.search(r'Encryption\s*:\s*(.+)$', block, re.MULTILINE | re.IGNORECASE)
                if not ssid_m:
                    continue
                ssid = ssid_m.group(1).strip()
                # Skip parsing artifacts (field values grabbed by mistake — contain ":" or too long)
                if len(ssid) > 32 or ":" in ssid:
                    continue
                # Empty SSID = hidden network; label it so the BSSID is still surfaced
                if not ssid:
                    ssid = "[Hidden Network]"
                networks.append({
                    "ssid":       ssid,
                    "bssid":      bssid_m.group(1).strip() if bssid_m else "",
                    "signal":     signal_m.group(1).strip() if signal_m else "?",
                    "channel":    channel_m.group(1).strip() if channel_m else "?",
                    "band":       band_m.group(1).strip() if band_m else "?",
                    "auth":       auth_m.group(1).strip() if auth_m else "?",
                    "encryption": enc_m.group(1).strip() if enc_m else "?",
                })

    elif sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
                capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n")[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        networks.append({
                            "ssid": parts[0], "bssid": parts[1],
                            "signal": parts[2], "channel": parts[3]
                        })
        except Exception:
            pass

    else:  # Linux
        try:
            result = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"],
                capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    parts = line.split(":")
                    if len(parts) >= 5:
                        networks.append({
                            "ssid": parts[0],
                            "bssid": ":".join(parts[1:7]).strip(),
                            "signal": parts[7] if len(parts) > 7 else "?",
                            "channel": parts[8] if len(parts) > 8 else "?",
                            "auth": parts[9] if len(parts) > 9 else "?"
                        })
        except Exception:
            pass

    return ([n for n in networks if n.get("ssid")], None)


def check_wifi_recon(selected_net=None):
    import subprocess as _sp
    print(f"\n{c('[WIFI NETWORK RECON]', 'cyan')}\n")

    if not selected_net:
        print(f"  {c('--- Scanning Nearby WiFi Networks ---', 'yellow')}\n")
        nearby, err = scan_nearby_wifi()

        if err == "location_permission":
            print(f"  {c('[!]', 'red')} Windows Location Services is OFF — netsh cannot list networks.")
            print(f"  {c('[i]', 'blue')} Opening Location Settings now...")
            _sp.Popen(["powershell", "-Command", "Start-Process 'ms-settings:privacy-location'"],
                      stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            print(f"\n  Turn on {c('Location services', 'bold')} (top toggle), then press Enter to retry.")
            input("  Press Enter when ready: ")
            nearby, err = scan_nearby_wifi()

        if not nearby:
            print(f"  {c('[-]', 'red')} No networks found — WiFi adapter may be off or no networks in range.")
            return

        print(f"  {c(f'[+] Found {len(nearby)} network(s) nearby:', 'green')}\n")
        for i, net in enumerate(nearby, 1):
            ssid = net.get("ssid", "?")
            bssid = net.get("bssid", "") or "no BSSID"
            signal = net.get("signal", "?")
            ch = net.get("channel", "?")
            auth = net.get("auth", net.get("encryption", "?"))
            print(f"    {c(f'[{i:>2}]', 'cyan')} {c(ssid, 'bold')}")
            print(f"         BSSID: {bssid}  Signal: {signal}  Ch: {ch}  Auth: {auth}")
        print()

        pick = input("  Select a network number for details: ").strip()
        if not pick.isdigit() or not (1 <= int(pick) <= len(nearby)):
            print(f"  {c('[!]', 'red')} Invalid selection.")
            return
        selected_net = nearby[int(pick) - 1]

    ssid = selected_net.get("ssid", "?")
    bssid = selected_net.get("bssid", "")
    signal = selected_net.get("signal", "?")
    channel = selected_net.get("channel", "?")
    radio = selected_net.get("radio", "?")
    auth = selected_net.get("auth", "?")
    encryption = selected_net.get("encryption", "?")

    print(f"\n  {c('--- Network Details ---', 'yellow')}\n")
    print(f"    {c('[SSID]', 'green')}        {ssid}")
    if bssid:
        print(f"    {c('[BSSID]', 'green')}       {bssid}")
    print(f"    {c('[Signal]', 'green')}      {signal}")
    print(f"    {c('[Channel]', 'green')}     {channel}")
    if radio and radio != "?":
        print(f"    {c('[Radio]', 'green')}       {radio}")
    print(f"    {c('[Auth]', 'green')}         {auth}")
    if encryption and encryption != "?":
        print(f"    {c('[Encryption]', 'green')}  {encryption}")

    # Frequency band from channel
    try:
        ch_num = int(re.sub(r'\D', '', str(channel)))
        band = "5 GHz" if ch_num > 14 else "2.4 GHz"
        print(f"    {c('[Band]', 'green')}        {band}")
    except (ValueError, TypeError):
        pass

    # OUI lookup — identify the router/AP manufacturer from BSSID
    if bssid:
        print(f"\n  {c('--- Device Manufacturer (OUI Lookup) ---', 'yellow')}\n")
        mac_clean = bssid.replace("-", ":").upper()
        resp, err = safe_request(f"https://api.macvendors.com/{urllib.parse.quote(mac_clean)}", timeout=8)
        if resp is not None and resp.status_code == 200:
            vendor = resp.text.strip()
            print(f"    {c('[VENDOR]', 'green')} {vendor}")
            log_finding("wifi", {"ssid": ssid, "bssid": bssid, "vendor": vendor, "signal": signal})
        elif resp is not None and resp.status_code == 404:
            print(f"    {c('[?]', 'yellow')} Manufacturer unknown (OUI not in database)")
        else:
            print(f"    {c('[?]', 'yellow')} OUI lookup unavailable")

    # Security assessment
    print(f"\n  {c('--- Security Assessment ---', 'yellow')}\n")
    auth_lower = auth.lower() if auth else ""
    enc_lower = encryption.lower() if encryption else ""
    if "open" in auth_lower or (not auth_lower or auth_lower == "?"):
        print(f"    {c('[OPEN]', 'red')} No authentication — traffic is unencrypted")
    elif "wep" in auth_lower or "wep" in enc_lower:
        print(f"    {c('[WEAK]', 'red')} WEP encryption — crackable in minutes")
    elif "wpa3" in auth_lower:
        print(f"    {c('[STRONG]', 'green')} WPA3 — current strongest standard")
    elif "wpa2" in auth_lower:
        print(f"    {c('[OK]', 'yellow')} WPA2 — secure if strong password; vulnerable to PMKID capture")
    elif "wpa" in auth_lower:
        print(f"    {c('[WEAK]', 'red')} WPA (TKIP) — deprecated, consider upgrading")

    # Intel tips
    print(f"\n  {c('--- Intelligence Value ---', 'yellow')}\n")
    print(f"    {c('[TIP]', 'bold')} SSID naming often reveals the owner (e.g. 'Smith_Home', 'JohnsiPhone')")
    print(f"    {c('[TIP]', 'bold')} Vendor identifies the router model — useful for known CVE searches")
    print(f"    {c('[TIP]', 'bold')} Default ISP router SSIDs (e.g. 'BELL123', 'Virgin-XXXX') can be looked up")
    print(f"    {c('[TIP]', 'bold')} Corporate SSIDs reveal employer name and work location")
    print(f"    {c('[TIP]', 'bold')} Signal strength indicates physical proximity to the access point")


# ============================================================
# 6c. Image Metadata / EXIF Forensics
# ============================================================
def check_image_metadata(filepath):
    resolved_path = resolve_user_file_path(filepath)
    print(f"\n{c('[IMAGE METADATA FORENSICS]', 'cyan')} File: {c(filepath, 'bold')}\n")

    if not resolved_path:
        print(f"  {c('[!]', 'red')} File not found: {filepath}")
        print(f"  {c('[i]', 'blue')} Tip: Use an absolute path or path relative to {Path.cwd()}")
        return

    filepath = resolved_path

    # Get file info
    file_size = os.path.getsize(filepath)
    file_mod = datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d %H:%M:%S")
    file_ext = os.path.splitext(filepath)[1].lower()

    print(f"  {c('--- File Info ---', 'yellow')}")
    print(f"    {c('[+]', 'green')} Path: {os.path.abspath(filepath)}")
    print(f"    {c('[+]', 'green')} Size: {file_size:,} bytes ({file_size/1024:.1f} KB)")
    print(f"    {c('[+]', 'green')} Last Modified: {file_mod}")
    print(f"    {c('[+]', 'green')} Extension: {file_ext}")

    supported_exif = {".jpg", ".jpeg", ".tiff", ".tif", ".heic", ".heif"}
    supported_image = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
                       ".webp", ".ico", ".heic", ".heif", ".svg"}

    if file_ext not in supported_image:
        print(f"\n  {c('[!]', 'yellow')} Extension '{file_ext}' may not be a standard image format")

    if not PILLOW_AVAILABLE:
        print(f"\n  {c('[!]', 'red')} Pillow library not installed in this Python environment")
        print(f"  {c('[i]', 'blue')} Active interpreter: {sys.executable}")
        print(f"  {c('[i]', 'blue')} Install with: {sys.executable} -m pip install Pillow")
        print(f"  {c('[i]', 'blue')} Pillow supports: JPEG, PNG, GIF, BMP, TIFF, WebP, ICO, HEIC*")
        return

    try:
        img = Image.open(filepath)
    except Exception as e:
        print(f"\n  {c('[!]', 'red')} Cannot open image: {e}")
        return

    print(f"\n  {c('--- Image Properties ---', 'yellow')}")
    print(f"    {c('[+]', 'green')} Format: {img.format}")
    print(f"    {c('[+]', 'green')} Dimensions: {img.size[0]} x {img.size[1]} pixels")
    print(f"    {c('[+]', 'green')} Color Mode: {img.mode}")
    if hasattr(img, 'n_frames') and img.n_frames > 1:
        print(f"    {c('[+]', 'green')} Frames: {img.n_frames} (animated)")
    dpi = img.info.get("dpi")
    if dpi:
        print(f"    {c('[+]', 'green')} DPI: {dpi}")

    log_finding("image", {"file": filepath, "format": img.format,
                           "width": img.size[0], "height": img.size[1], "mode": img.mode})

    # --- PNG text chunks (tEXt, iTXt, zTXt) ---
    if img.format == "PNG":
        print(f"\n  {c('--- PNG Metadata Chunks ---', 'yellow')}")
        png_meta = img.info
        found_meta = False
        for key, val in png_meta.items():
            if key in ("dpi", "gamma"):
                continue
            if isinstance(val, (str, bytes)):
                val_str = val if isinstance(val, str) else val.decode("utf-8", errors="replace")
                if len(val_str) > 200:
                    val_str = val_str[:200] + "..."
                print(f"    {c('[+]', 'green')} {key}: {val_str}")
                log_finding("image", {"type": "png_meta", "key": key, "value": val_str[:100]})
                found_meta = True
        if not found_meta:
            print(f"    {c('[-]', 'red')} No text metadata chunks found")

    # --- EXIF Data ---
    exif_data = None
    if file_ext in supported_exif or img.format in ("JPEG", "TIFF"):
        try:
            exif_data = img._getexif()
        except Exception:
            pass

    if exif_data:
        print(f"\n  {c('--- EXIF Metadata ---', 'yellow')}")
        gps_info = {}

        important_tags = {
            "Make": "Camera Make", "Model": "Camera Model", "Software": "Software",
            "DateTime": "Date/Time", "DateTimeOriginal": "Original Date",
            "DateTimeDigitized": "Digitized Date", "Artist": "Artist",
            "Copyright": "Copyright", "ImageDescription": "Description",
            "XPAuthor": "Author (XP)", "XPComment": "Comment (XP)",
            "HostComputer": "Host Computer", "LensMake": "Lens Make",
            "LensModel": "Lens Model", "ExifImageWidth": "EXIF Width",
            "ExifImageHeight": "EXIF Height", "ExposureTime": "Exposure Time",
            "FNumber": "F-Number", "ISOSpeedRatings": "ISO",
            "FocalLength": "Focal Length", "Flash": "Flash",
            "WhiteBalance": "White Balance", "ExposureProgram": "Exposure Program",
            "MeteringMode": "Metering Mode", "Orientation": "Orientation",
        }

        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, str(tag_id))

            if tag == "GPSInfo":
                for gps_tag_id in value:
                    gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                    gps_info[gps_tag] = value[gps_tag_id]
                continue

            if isinstance(value, bytes) and len(value) > 50:
                continue

            if tag in important_tags:
                print(f"    {c('[+]', 'green')} {important_tags[tag]}: {value}")
                log_finding("image", {"type": "exif", "tag": tag, "value": str(value)})

        # --- GPS ---
        if gps_info:
            print(f"\n  {c('--- GPS LOCATION DATA ---', 'red')}")

            def _to_degrees(value):
                d, m, s = value
                return float(d) + float(m) / 60 + float(s) / 3600

            try:
                lat = _to_degrees(gps_info.get("GPSLatitude", (0, 0, 0)))
                lat_ref = gps_info.get("GPSLatitudeRef", "N")
                lon = _to_degrees(gps_info.get("GPSLongitude", (0, 0, 0)))
                lon_ref = gps_info.get("GPSLongitudeRef", "E")

                if lat_ref == "S":
                    lat = -lat
                if lon_ref == "W":
                    lon = -lon

                print(f"    {c('[GPS]', 'red')} Latitude:  {lat:.6f}")
                print(f"    {c('[GPS]', 'red')} Longitude: {lon:.6f}")
                print(f"    {c('[MAP]', 'blue')} https://www.google.com/maps?q={lat},{lon}")
                print(f"    {c('[MAP]', 'blue')} https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}")
                log_finding("image", {"type": "gps", "lat": lat, "lon": lon})
            except Exception as e:
                print(f"    {c('[!]', 'yellow')} Could not parse GPS coords: {e}")

            if "GPSAltitude" in gps_info:
                print(f"    {c('[GPS]', 'red')} Altitude: {gps_info['GPSAltitude']}m")
            if "GPSTimeStamp" in gps_info:
                print(f"    {c('[GPS]', 'red')} GPS Time: {gps_info['GPSTimeStamp']}")
            if "GPSDateStamp" in gps_info:
                print(f"    {c('[GPS]', 'red')} GPS Date: {gps_info['GPSDateStamp']}")
            if "GPSSpeed" in gps_info:
                print(f"    {c('[GPS]', 'red')} Speed: {gps_info['GPSSpeed']}")
            if "GPSImgDirection" in gps_info:
                print(f"    {c('[GPS]', 'red')} Camera Direction: {gps_info['GPSImgDirection']}")
        else:
            print(f"\n  {c('[-]', 'red')} No GPS data embedded in image")
    elif file_ext in supported_exif:
        print(f"\n  {c('[-]', 'red')} No EXIF metadata found (may have been stripped)")
    else:
        print(f"\n  {c('[i]', 'blue')} {img.format} format does not support EXIF metadata")



# ============================================================
# 6e. Person Location Intelligence (Comprehensive)
# ============================================================
def check_person_locator(full_name, city="", state=""):
    print(f"\n{c('[PERSON LOCATOR INTELLIGENCE]', 'cyan')} Target: {c(full_name, 'bold')}")
    if city or state:
        print(f"  Area: {city} {state}")
    print()

    parts = full_name.strip().split()
    first = parts[0] if parts else full_name
    last = parts[-1] if len(parts) > 1 else ""

    # --- CourtListener (US federal & state court records — free account at courtlistener.com) ---
    print(f"  {c('--- Court Records (CourtListener) ---', 'yellow')}")
    cl_key = get_api_key("courtlistener")
    cl_headers = {"Accept": "application/json"}
    if cl_key:
        cl_headers["Authorization"] = f"Token {cl_key}"
    cl_url = f"https://www.courtlistener.com/api/rest/v3/dockets/?party_name={urllib.parse.quote(full_name)}&format=json"
    resp, err = safe_request(cl_url, headers=cl_headers, timeout=15)
    if resp is not None and resp.status_code == 200:
        try:
            data = resp.json()
            count = data.get("count", 0)
            if count > 0:
                print(f"    {c('[!]', 'red')} Found {count} court case(s) involving this name")
                for case in data.get("results", [])[:5]:
                    case_name = case.get("case_name", "?")
                    court = case.get("court", "?")
                    date_filed = case.get("date_filed", "?")
                    print(f"      {c('[CASE]', 'red')} {case_name}")
                    print(f"             Court: {court} | Filed: {date_filed}")
                log_finding("person_locator", {"type": "court_records", "name": full_name, "count": count})
            else:
                print(f"    {c('[OK]', 'green')} No court cases found for this name")
        except (json.JSONDecodeError, ValueError):
            print(f"    {c('[?]', 'yellow')} Could not parse CourtListener response")
    elif resp is not None and resp.status_code == 401:
        print(f"    {c('[i]', 'blue')} CourtListener requires a free account token.")
        print(f"    {c('[i]', 'blue')} Register at courtlistener.com, go to Profile > API Token, then set via Option 17.")
    elif resp is not None:
        print(f"    {c('[?]', 'yellow')} CourtListener query failed (HTTP {resp.status_code})")
    else:
        print(f"    {c('[?]', 'yellow')} CourtListener unreachable: {err}")

    # --- OpenCorporates (company officer/director records worldwide — free API token at opencorporates.com) ---
    print(f"\n  {c('--- Corporate Officer Records (OpenCorporates) ---', 'yellow')}")
    oc_key = get_api_key("opencorporates")
    oc_url = f"https://api.opencorporates.com/v0.4/officers/search?q={urllib.parse.quote(full_name)}&per_page=5"
    if oc_key:
        oc_url += f"&api_token={oc_key}"
    resp, err = safe_request(oc_url, headers={"Accept": "application/json"}, timeout=15)
    if resp is not None and resp.status_code == 200:
        try:
            data = resp.json()
            officers = data.get("results", {}).get("officers", [])
            if officers:
                print(f"    {c('[+]', 'green')} Found {len(officers)} corporate officer record(s):")
                for item in officers[:5]:
                    off = item.get("officer", {})
                    name = off.get("name", "?")
                    role = off.get("position", "?")
                    company = off.get("company", {}).get("name", "?") if off.get("company") else "?"
                    jurisdiction = off.get("company", {}).get("jurisdiction_code", "?") if off.get("company") else "?"
                    inactive = off.get("inactive", False)
                    status = "Inactive" if inactive else "Active"
                    print(f"      {c('[OFFICER]', 'green')} {name} — {role} at {company} ({jurisdiction}) [{status}]")
                log_finding("person_locator", {"type": "corporate_officer", "name": full_name, "count": len(officers)})
            else:
                print(f"    {c('[-]', 'red')} No corporate officer records found")
        except (json.JSONDecodeError, ValueError, KeyError):
            print(f"    {c('[?]', 'yellow')} Could not parse OpenCorporates response")
    elif resp is not None and resp.status_code == 401:
        print(f"    {c('[i]', 'blue')} OpenCorporates requires a free API token.")
        print(f"    {c('[i]', 'blue')} Register at opencorporates.com/api_accounts/new_signup, then set via Option 17.")
    elif resp is not None:
        print(f"    {c('[?]', 'yellow')} OpenCorporates query failed (HTTP {resp.status_code})")
    else:
        print(f"    {c('[?]', 'yellow')} OpenCorporates unreachable: {err}")

    # --- ORCID (free — academic/researcher identity database) ---
    print(f"\n  {c('--- Academic / Researcher Records (ORCID) ---', 'yellow')}")
    orcid_query = f"given-names:{urllib.parse.quote(first)}+AND+family-name:{urllib.parse.quote(last)}" if last else urllib.parse.quote(first)
    orcid_url = f"https://pub.orcid.org/v3.0/search/?q={orcid_query}&rows=5"
    resp, err = safe_request(orcid_url, headers={"Accept": "application/json"}, timeout=15)
    if resp is not None and resp.status_code == 200:
        try:
            data = resp.json()
            results = data.get("result", [])
            total = data.get("num-found", 0)
            if total > 0:
                print(f"    {c('[+]', 'green')} Found {total} ORCID researcher profile(s):")
                for r in results[:5]:
                    orcid_id = r.get("orcid-identifier", {}).get("path", "?")
                    uri = r.get("orcid-identifier", {}).get("uri", "")
                    print(f"      {c('[ORCID]', 'green')} ID: {orcid_id}  {uri}")
                log_finding("person_locator", {"type": "orcid", "name": full_name, "count": total})
            else:
                print(f"    {c('[-]', 'red')} No ORCID profiles found")
        except (json.JSONDecodeError, ValueError, KeyError):
            print(f"    {c('[?]', 'yellow')} Could not parse ORCID response")
    elif resp is not None:
        print(f"    {c('[?]', 'yellow')} ORCID query failed (HTTP {resp.status_code})")
    else:
        print(f"    {c('[?]', 'yellow')} ORCID unreachable: {err}")

    log_finding("person_locator", {"name": full_name, "city": city, "state": state})



# ============================================================
# 7. MAC Address Lookup
# ============================================================
def check_mac_address(mac):
    print(f"\n{c('[MAC ADDRESS LOOKUP]', 'cyan')} Target: {c(mac, 'bold')}\n")

    # Normalize MAC address
    clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac)
    if len(clean_mac) < 6:
        print(f"  {c('[!]', 'red')} Invalid MAC address")
        return

    oui = clean_mac[:6].upper()
    formatted = ':'.join(clean_mac[i:i+2] for i in range(0, len(clean_mac), 2)).upper()
    print(f"  {c('[i]', 'blue')} Normalized: {formatted}")
    print(f"  {c('[i]', 'blue')} OUI Prefix: {oui[:2]}:{oui[2:4]}:{oui[4:6]}")

    # Query macvendors.com
    lookup_url = f"https://api.macvendors.com/{formatted}"
    resp, err = safe_request(lookup_url)
    if resp is not None and resp.status_code == 200:
        vendor = resp.text.strip()
        print(f"  {c('[+]', 'green')} Manufacturer: {vendor}")
        log_finding("mac", {"mac": formatted, "vendor": vendor})
    elif resp is not None and resp.status_code == 404:
        print(f"  {c('[-]', 'red')} Unknown vendor (MAC not in database)")
    else:
        print(f"  {c('[?]', 'yellow')} Lookup failed: {err}")

    # Determine address type
    first_byte = int(clean_mac[:2], 16)
    if first_byte & 0x02:
        print(f"  {c('[!]', 'yellow')} Locally Administered Address (possibly randomized/spoofed)")
    else:
        print(f"  {c('[i]', 'blue')} Universally Administered Address (factory assigned)")

    if first_byte & 0x01:
        print(f"  {c('[i]', 'blue')} Multicast address")
    else:
        print(f"  {c('[i]', 'blue')} Unicast address")


# ============================================================
# 9. Email Header Analyzer
# ============================================================
def analyze_email_headers(raw_headers=None, filepath=None):
    print(f"\n{c('[EMAIL HEADER ANALYSIS]', 'cyan')}\n")

    # Load from file if provided
    if filepath:
        if not os.path.isfile(filepath):
            print(f"  {c('[!]', 'red')} File not found: {filepath}")
            return
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                raw_headers = f.read()
            print(f"  {c('[+]', 'green')} Loaded headers from: {filepath}")
            print(f"  {c('[i]', 'blue')} File size: {len(raw_headers):,} bytes\n")
        except Exception as e:
            print(f"  {c('[!]', 'red')} Could not read file: {e}")
            return

    if not raw_headers:
        print(f"  {c('[!]', 'red')} No headers provided")
        return

    # Parse headers
    msg = email.message_from_string(raw_headers)

    # Key headers
    key_headers = ["From", "To", "Subject", "Date", "Reply-To", "Return-Path",
                   "Message-ID", "X-Mailer", "X-Originating-IP", "X-Sender-IP",
                   "Authentication-Results", "Received-SPF", "DKIM-Signature",
                   "ARC-Authentication-Results"]

    print(f"  {c('--- Key Headers ---', 'yellow')}")
    for h in key_headers:
        value = msg.get(h)
        if value:
            # Clean up multiline headers
            value = " ".join(value.split())
            if "originating-ip" in h.lower() or "sender-ip" in h.lower():
                print(f"    {c('[!]', 'red')} {h}: {value}")
            elif "authentication" in h.lower() or "spf" in h.lower() or "dkim" in h.lower():
                if "pass" in value.lower():
                    print(f"    {c('[OK]', 'green')} {h}: {value[:100]}")
                elif "fail" in value.lower():
                    print(f"    {c('[!]', 'red')} {h}: {value[:100]}")
                else:
                    print(f"    {c('[?]', 'yellow')} {h}: {value[:100]}")
            else:
                print(f"    {c('[+]', 'green')} {h}: {value[:100]}")

    # Trace routing (Received headers - bottom to top)
    received = msg.get_all("Received", [])
    if received:
        print(f"\n  {c('--- Mail Routing (oldest to newest) ---', 'yellow')}")
        for i, r in enumerate(reversed(received)):
            r_clean = " ".join(r.split())
            # Try to extract IPs
            ips = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', r)
            hop_ips = ", ".join(ips) if ips else "no IP"
            print(f"    {c(f'[Hop {i+1}]', 'blue')} ({hop_ips})")
            print(f"      {r_clean[:150]}")
            log_finding("email_header", {"hop": i + 1, "ips": ips, "raw": r_clean[:200]})

        # Extract all unique IPs from headers
        all_ips = set()
        for r in received:
            all_ips.update(re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', r))

        # Filter out private IPs
        public_ips = [ip for ip in all_ips
                      if not ip.startswith("10.") and not ip.startswith("192.168.")
                      and not ip.startswith("127.") and not ip.startswith("172.")]

        if public_ips:
            print(f"\n  {c('--- Public IPs Found in Headers ---', 'yellow')}")
            for ip in public_ips:
                print(f"    {c('[IP]', 'red')} {ip}")
            print(f"\n  {c('[TIP]', 'bold')} Run IP Intelligence scan on these addresses for origin tracing")
    else:
        print(f"\n  {c('[-]', 'red')} No Received headers found")


# ============================================================
# 10. Google Dork Generator
# ============================================================
def generate_dorks(target):
    print(f"\n{c('[GOOGLE DORK GENERATOR]', 'cyan')} Target: {c(target, 'bold')}\n")
    encoded = urllib.parse.quote(f'"{target}"')

    dork_categories = {
        "Personal Information": [
            (f'"{target}" filetype:pdf', "PDF documents mentioning target"),
            (f'"{target}" filetype:doc OR filetype:docx', "Word documents"),
            (f'"{target}" filetype:xls OR filetype:xlsx', "Spreadsheets"),
            (f'"{target}" filetype:ppt OR filetype:pptx', "Presentations"),
            (f'"{target}" resume OR CV filetype:pdf', "Resumes/CVs"),
            (f'"{target}" address OR phone OR email', "Contact information"),
        ],
        "Social Media & Profiles": [
            (f'"{target}" site:linkedin.com', "LinkedIn profiles"),
            (f'"{target}" site:facebook.com', "Facebook profiles"),
            (f'"{target}" site:twitter.com OR site:x.com', "Twitter/X profiles"),
            (f'"{target}" site:instagram.com', "Instagram mentions"),
            (f'"{target}" site:reddit.com', "Reddit mentions"),
            (f'"{target}" site:medium.com', "Medium articles"),
            (f'"{target}" site:github.com', "GitHub profiles/repos"),
        ],
        "Legal & Court Records": [
            (f'"{target}" site:courtlistener.com', "CourtListener records"),
            (f'"{target}" court OR case OR docket filetype:pdf', "Court documents"),
            (f'"{target}" arrest OR warrant OR indictment', "Criminal records"),
            (f'"{target}" lawsuit OR plaintiff OR defendant', "Lawsuits"),
            (f'"{target}" bankruptcy', "Bankruptcy filings"),
        ],
        "Business & Financial": [
            (f'"{target}" site:sec.gov', "SEC filings"),
            (f'"{target}" site:opencorporates.com', "Corporate records"),
            (f'"{target}" director OR officer OR founder', "Business roles"),
            (f'"{target}" LLC OR Inc OR Corp', "Business entities"),
        ],
        "Data Leaks & Paste Sites": [
            (f'"{target}" site:pastebin.com', "Pastebin mentions"),
            (f'"{target}" site:paste.ee', "Paste.ee mentions"),
            (f'"{target}" site:hastebin.com', "Hastebin mentions"),
            (f'"{target}" password OR leak OR dump', "Potential data leaks"),
            (f'"{target}" database OR sql OR dump filetype:sql', "Database dumps"),
        ],
        "Location & Property": [
            (f'"{target}" property OR deed OR parcel', "Property records"),
            (f'"{target}" site:zillow.com OR site:realtor.com', "Real estate listings"),
            (f'"{target}" voter OR registration', "Voter registration"),
        ],
        "Technical / Infrastructure": [
            (f'"{target}" inurl:admin OR inurl:login', "Admin panels"),
            (f'"{target}" ext:env OR ext:yml OR ext:cfg', "Config files"),
            (f'"{target}" api_key OR apikey OR secret_key', "Exposed API keys"),
            (f'site:{target} intitle:"index of"', "Open directories"),
            (f'site:{target} ext:sql OR ext:db OR ext:bak', "Database/backup files"),
        ],
    }

    for cat, dorks in dork_categories.items():
        print(f"  {c(f'--- {cat} ---', 'yellow')}")
        for dork, desc in dorks:
            google_url = f"https://www.google.com/search?q={urllib.parse.quote(dork)}"
            print(f"    {c('[DORK]', 'magenta')} {desc}")
            print(f"           {c(dork, 'dim')}")
            print(f"           {c(google_url, 'blue')}")
        print()



# ============================================================
# 12. Report Generator
# ============================================================
def export_report():
    if not findings:
        print(f"\n  {c('[i]', 'blue')} No findings to export. Run some scans first.")
        return

    out_dir = ensure_output_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # --- JSON Export ---
    json_path = os.path.join(out_dir, f"ShadowTrace_report_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(dict(findings), f, indent=2, default=str)
    print(f"\n  {c('[+]', 'green')} JSON report saved: {json_path}")

    # --- HTML Export ---
    html_path = os.path.join(out_dir, f"ShadowTrace_report_{timestamp}.html")
    html = ["""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>ShadowTrace Report</title>
<style>
body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff41; padding: 20px; }
h1 { color: #00ff41; border-bottom: 2px solid #00ff41; padding-bottom: 10px; }
h2 { color: #00ccff; margin-top: 30px; }
.finding { background: #111; border-left: 3px solid #00ff41; padding: 10px; margin: 10px 0; }
.timestamp { color: #666; font-size: 0.8em; }
a { color: #00ccff; }
.meta { color: #888; margin-bottom: 20px; }
</style></head><body>"""]
    html.append(f"<h1>ShadowTrace OSINT Report</h1>")
    html.append(f"<div class='meta'>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>")

    for category, items in findings.items():
        html.append(f"<h2>{category.upper()} ({len(items)} findings)</h2>")
        for item in items:
            ts = item.get("timestamp", "")
            html.append(f"<div class='finding'>")
            html.append(f"<span class='timestamp'>{ts}</span><br>")
            for k, v in item.items():
                if k == "timestamp":
                    continue
                if isinstance(v, str) and v.startswith("http"):
                    html.append(f"<b>{k}:</b> <a href='{v}' target='_blank'>{v}</a><br>")
                else:
                    html.append(f"<b>{k}:</b> {v}<br>")
            html.append("</div>")

    html.append("</body></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
    print(f"  {c('[+]', 'green')} HTML report saved: {html_path}")

    # --- CSV Export ---
    csv_path = os.path.join(out_dir, f"ShadowTrace_report_{timestamp}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "timestamp", "key", "value"])
        for category, items in findings.items():
            for item in items:
                ts = item.get("timestamp", "")
                for k, v in item.items():
                    if k == "timestamp":
                        continue
                    writer.writerow([category, ts, k, str(v)])
    print(f"  {c('[+]', 'green')} CSV report saved: {csv_path}")


# ============================================================
# API Key Configuration
# ============================================================
def configure_api_keys():
    print(f"\n{c('[API KEY CONFIGURATION]', 'cyan')}\n")
    print("  Configure API keys for enhanced functionality.")
    print("  Leave blank to skip / keep existing.\n")

    keys = config.get("api_keys", {})
    key_info = {
        "shodan": "Shodan (https://shodan.io)",
        "hibp": "Have I Been Pwned (https://haveibeenpwned.com/API/Key)",
        "abuseipdb": "AbuseIPDB (https://abuseipdb.com)",
        "virustotal": "VirusTotal (https://virustotal.com)",
        "courtlistener": "CourtListener API Token (courtlistener.com -> Profile -> API Token) [free]",
        "opencorporates": "OpenCorporates API Token (opencorporates.com/api_accounts/new_signup) [free]",
    }

    for key_name, description in key_info.items():
        current = keys.get(key_name, "")
        masked = f"{current[:4]}...{current[-4:]}" if len(current) > 8 else ("(not set)" if not current else current)
        new_val = input(f"  {description}\n    Current: {masked}\n    New value: ").strip()
        if new_val:
            keys[key_name] = new_val

    config["api_keys"] = keys
    save_config()
    print(f"\n  {c('[+]', 'green')} Configuration saved to {CONFIG_FILE}")


# ============================================================
# Main Menu
# ============================================================
def main():
    load_config()
    banner()

    menu_options = {
        "1":  ("Username Recon", "Check username across 30+ platforms"),
        "2":  ("Username Permutation Engine", "Generate & scan username variants"),
        "3":  ("Email Intelligence", "Gravatar, breaches, disposable check, verify permutations"),
        "4":  ("IP Intelligence", "GeoIP, rDNS, threat intel, Shodan, VT"),
        "5":  ("Domain Reconnaissance", "DNS, certs, subdomains, WHOIS, Wayback"),
        "6":  ("WiFi Network Recon", "Scan nearby networks, show details & device manufacturer"),
        "7":  ("Image Metadata / EXIF", "Extract GPS, camera, timestamps from images"),
        "8":  ("MAC Address Lookup", "Vendor identification, address type"),
        "9":  ("Email Header Analyzer", "Trace origin, routing, spoofing (paste or file)"),
        "10": ("Google Dork Generator", "Advanced search queries for any target"),
        "11": ("Export Report", "Save all findings to JSON/HTML/CSV"),
        "12": ("Configure API Keys", "Set up API keys for enhanced features"),
        "0":  ("Exit", ""),
    }

    while True:
        print(f"\n{c('=' * 60, 'dim')}")
        print(f"{c('  MAIN MENU', 'bold')}")
        print(f"{c('=' * 60, 'dim')}\n")

        for key, (name, desc) in menu_options.items():
            if key == "0":
                print(f"  {c('[0]', 'red')}  Exit\n")
            else:
                print(f"  {c(f'[{key:>2}]', 'cyan')} {name}")
                if desc:
                    print(f"       {c(desc, 'dim')}")

        choice = input(f"\n  {c('>>>', 'green')} Select option: ").strip()

        if choice == "1":
            username = input("\n  Enter Username: ").strip()
            if username:
                check_username_across_platforms(username)

        elif choice == "2":
            base = input("\n  Enter name or base username: ").strip()
            if base:
                check_username_permutations(base)

        elif choice == "3":
            addr = input("\n  Enter Email Address: ").strip()
            if addr:
                check_email_intel(addr)

        elif choice == "4":
            ip = input("\n  Enter IP Address: ").strip()
            if ip:
                check_ip_intel(ip)

        elif choice == "5":
            domain = input("\n  Enter Domain (e.g., example.com): ").strip()
            if domain:
                check_domain_recon(domain)

        elif choice == "6":
            check_wifi_recon()

        elif choice == "7":
            filepath = input("\n  Enter image file path (jpg/png/gif/tiff/webp/heic): ").strip()
            # Strip surrounding quotes if user copies from file explorer
            filepath = filepath.strip('"').strip("'")
            if filepath:
                check_image_metadata(filepath)

        elif choice == "8":
            mac = input("\n  Enter MAC Address (e.g., AA:BB:CC:DD:EE:FF): ").strip()
            if mac:
                check_mac_address(mac)

        elif choice == "9":
            print(f"\n  {c('[1]', 'cyan')} Paste headers manually")
            print(f"  {c('[2]', 'cyan')} Load from file (.txt / .eml)")
            hdr_choice = input(f"\n  Choice (1/2): ").strip()
            if hdr_choice == "2":
                hdr_file = input("\n  Enter file path: ").strip().strip('"').strip("'")
                if hdr_file:
                    analyze_email_headers(filepath=hdr_file)
            else:
                print("\n  Paste raw email headers below (enter a blank line when done):")
                lines = []
                while True:
                    line = input()
                    if line == "":
                        break
                    lines.append(line)
                if lines:
                    analyze_email_headers(raw_headers="\n".join(lines))

        elif choice == "10":
            target = input("\n  Enter target (name, email, domain, etc.): ").strip()
            if target:
                generate_dorks(target)

        elif choice == "11":
            export_report()

        elif choice == "12":
            configure_api_keys()

        elif choice == "0":
            print(f"\n  {c('Exiting ShadowTrace. Stay sharp.', 'cyan')}\n")
            break

        else:
            print(f"\n  {c('[!]', 'red')} Invalid option")


if __name__ == "__main__":
    main()
