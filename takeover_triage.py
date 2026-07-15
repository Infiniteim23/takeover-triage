#!/usr/bin/env python3
"""
takeover_triage.py  -  High-confidence subdomain takeover triage.

Design principle: a fingerprint match is a HYPOTHESIS, not a verdict.
This tool enforces three gates and NEVER reports "vulnerable" from
automation alone. Its best verdict is CONFIRM_MANUALLY: dangling record
+ deprovisioned resource + a service that is *structurally* claimable.
The final claim (Gate 3 proof) is left to you, under program RoE.

    Gate 1  dangling CNAME/NS pointing at a 3rd-party service
    Gate 2  backing resource is gone  (NXDOMAIN on target, OR
            service returns its known "unclaimed" error string)
    Gate 3  the exact name is re-registerable (not hashed / not
            behind ownership-verification)   <-- MANUAL, human-only

Usage:
    python takeover_triage.py -l subs.txt
    python takeover_triage.py -l subs.txt --json out.json -w 20
    echo sub.target.com | python takeover_triage.py
    python takeover_triage.py -l subs.txt --verbose --doh-fallback
    python takeover_triage.py -l subs.txt --xyz          # cross-ref can-i-take-over-xyz
    python takeover_triage.py -l subs.txt --delay 0.2    # be polite to target infra

Dependencies: dnspython, requests
Only run against targets you are authorized to test.
"""
import argparse
import json
import re
import sys
import random
import time
import textwrap
import os
import hashlib
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Handle missing dependencies gracefully
try:
    import dns.resolver
    import dns.name
except ImportError:
    sys.exit("Error: Missing required dependency 'dnspython'.\n"
             "Install it with: pip install dnspython")

try:
    import requests
except ImportError:
    sys.exit("Error: Missing required dependency 'requests'.\n"
             "Install it with: pip install requests")

requests.packages.urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# BANNER
# ---------------------------------------------------------------------------
BANNER = r"""
  _____     _                           _____     _
 |_   _|_ _| | _____  _____   _____ _ _|_   _| __(_) __ _  __ _  ___
   | |/ _` | |/ / _ \/ _ \ \ / / _ \ '__|| || '__| |/ _` |/ _` |/ _ \
   | | (_| |   <  __/ (_) \ V /  __/ |   | || |  | | (_| | (_| |  __/
   |_|\__,_|_|\_\___|\___/ \_/ \___|_|   |_||_|  |_|\__,_|\__, |\___|
                                                           |___/
                    High-Confidence Subdomain Takeover Triage
                          Three-Gate Verification System
"""

BANNER_INFO = """
                      "Trust, but verify. Then verify again."
                      -- Responsible Bug Bounty Hunters
"""

# ---------------------------------------------------------------------------
# Fingerprint DB.  Curated from can-i-take-over-xyz + field experience.
#   cname              : regex the CNAME target must match to be *this* service
#   fingerprint        : HTTP body strings that appear when the resource is UNCLAIMED
#   status             : "vulnerable" | "edge" | "not_vulnerable"
#   claimable          : is the name re-registerable by you? (Gate 3 default)
#   nxdomain_is_enough : does a bare NXDOMAIN on the target confirm Gate 2 alone?
#                        (NOTE: this does NOT disable the HTTP fingerprint check;
#                         a live target showing the unclaimed-error string still
#                         satisfies Gate 2.)
#   note               : human guidance for the manual step
# ---------------------------------------------------------------------------
FINGERPRINTS = [
    # ---- genuinely takeoverable, name-choosable services ----
    {"service": "AWS S3", "cname": r"\.s3[.-].*amazonaws\.com|\.s3\.amazonaws\.com",
     "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "Create bucket with the EXACT subdomain name in the SAME region."},
    {"service": "GitHub Pages", "cname": r"\.github\.io|github\.map\.fastly\.net",
     "fingerprint": ["There isn't a GitHub Pages site here", "For root URLs"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "Create repo, add CNAME file matching the victim subdomain."},
    {"service": "Azure APIM", "cname": r"\.azure-api\.net$",
     "fingerprint": [],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": True,
     "note": "ONLY if target is NXDOMAIN. Check name is green in APIM create."},
    {"service": "Azure App Service", "cname": r"\.azurewebsites\.net$",
     "fingerprint": ["Web App - Unavailable", "404 Web Site not found"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": True,
     "note": "NXDOMAIN => try create Web App with that name (uncheck 'secure unique default hostname')."},
    {"service": "Azure Cloud Service (classic)", "cname": r"\.cloudapp\.(net|azure\.com)$",
     "fingerprint": [],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": True,
     "note": "NXDOMAIN => re-create classic cloud service with that DNS name."},
    {"service": "Azure Cloud Service (hashed)", "cname": r"\.cloudapp\.(net|azure\.com)$",
     "fingerprint": [],
     "status": "not_vulnerable", "claimable": False, "nxdomain_is_enough": False,
     "note": "Cloud service name contains random hash -> NOT re-registerable."},
    {"service": "Azure Blob", "cname": r"\.blob\.core\.windows\.net$",
     "fingerprint": [],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": True,
     "note": "NXDOMAIN => create storage account with that name."},
    {"service": "Azure Storage (Web)", "cname": r"\.web\.core\.windows\.net$",
     "fingerprint": ["The requested content does not exist", "404 Not Found"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": True,
     "note": "NXDOMAIN => static website hosting. Storage account can be recreated."},
    {"service": "Azure Traffic Manager", "cname": r"\.trafficmanager\.net$",
     "fingerprint": [],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": True,
     "note": "NXDOMAIN => re-create TM profile with that name."},
    {"service": "Heroku", "cname": r"\.herok(u|udns)\.com|\.herokuapp\.com",
     "fingerprint": ["No such app", "herokucdn.com/error-pages/no-such-app"],
     "status": "edge", "claimable": True, "nxdomain_is_enough": False,
     "note": "Region/account bound; heroku domains:add <sub>. Confirm before reporting."},
    {"service": "Shopify", "cname": r"\.myshopify\.com",
     "fingerprint": ["Sorry, this shop is currently unavailable"],
     "status": "edge", "claimable": True, "nxdomain_is_enough": False,
     "note": "Shopify often requires verification now; confirm manually."},
    {"service": "Cargo", "cname": r"\.cargocollective\.com|cargo\.site",
     "fingerprint": ["404 Not Found", "<title>404"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "Add the domain in a Cargo account."},
    {"service": "Tumblr", "cname": r"\.domains\.tumblr\.com",
     "fingerprint": ["Whatever you were looking for doesn't currently exist"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "Register the blog and add the custom domain."},
    {"service": "Readme.io", "cname": r"\.readme\.io",
     "fingerprint": ["Project doesnt exist... yet!"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "Create Readme project with the orphan hostname."},
    {"service": "Wordpress.com", "cname": r"\.wordpress\.com",
     "fingerprint": ["Do you want to register"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "Map the domain in a WordPress.com account."},
    {"service": "Wasabi", "cname": r"\.wasabisys\.com",
     "fingerprint": ["NoSuchBucket"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "Create bucket with the same name/region."},
    {"service": "Elastic Beanstalk", "cname": r"\.elasticbeanstalk\.com$",
     "fingerprint": ["Not Found", "404", "The site you were trying to reach doesn't currently have a default page"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": True,
     "note": "NXDOMAIN => re-create Elastic Beanstalk environment with same name."},
    {"service": "SendGrid", "cname": r"\.sendgrid\.net$",
     "fingerprint": [],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": True,
     "note": "NXDOMAIN => verify domain ownership in SendGrid dashboard."},
    {"service": "Unbounce", "cname": r"\.unbouncepages\.com|\.unbounce\.com",
     "fingerprint": ["The page you are looking for doesn't exist", "Page Not Found"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "Create Unbounce landing page with the orphan domain."},
    {"service": "Surge.sh", "cname": r"\.surge\.sh$",
     "fingerprint": ["project not found"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "surge CLI: surge --domain <subdomain> to claim."},
    {"service": "Netlify", "cname": r"\.netlify\.app$|\.netlify\.com$",
     "fingerprint": ["Not Found - Site not found", "No such site", "This site is not currently available"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "Create Netlify site and add custom domain."},
    {"service": "Pantheon", "cname": r"\.gotpantheon\.com|\.pantheonsite\.io",
     "fingerprint": ["404 - Page Not Found", "Site not found"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "Add the domain in Pantheon dashboard."},
    {"service": "WP Engine", "cname": r"\.wpengine\.com",
     "fingerprint": ["This site is not currently available", "Site not found"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "WP Engine hosting - may allow domain addition to new install."},
    {"service": "Ghost.org", "cname": r"\.ghost\.io$|\.ghost\.org$",
     "fingerprint": ["The site you were looking for couldn't be found", "Site not found"],
     "status": "vulnerable", "claimable": True, "nxdomain_is_enough": False,
     "note": "Create Ghost(Pro) blog and add custom domain."},

    # ---- MITIGATED / verification-required: fingerprint may fire but NOT claimable ----
    {"service": "Azure Front Door", "cname": r"\.azurefd\.net$",
     "fingerprint": ["Our services aren't available right now"],
     "status": "not_vulnerable", "claimable": False, "nxdomain_is_enough": False,
     "note": "Modern AFD endpoints carry a random hash -> NOT re-registerable. Only old unhashed classic names on NXDOMAIN are candidates."},
    {"service": "Fastly", "cname": r"\.fastly\.net|\.fastlylb\.net",
     "fingerprint": ["Fastly error: unknown domain"],
     "status": "not_vulnerable", "claimable": False, "nxdomain_is_enough": False,
     "note": "Host-header verification since 2018 -> error string shows but reclaim needs account proof."},
    {"service": "Cloudfront", "cname": r"\.cloudfront\.net$",
     "fingerprint": ["ERROR: The request could not be satisfied"],
     "status": "edge", "claimable": False, "nxdomain_is_enough": False,
     "note": "AWS binds alt-domain names to a distribution; usually NOT claimable. Verify carefully."},
    {"service": "Cloudflare", "cname": r"\.cloudflare(ssl)?\.(net|com)",
     "fingerprint": [],
     "status": "not_vulnerable", "claimable": False, "nxdomain_is_enough": False,
     "note": "Anycast; 4xx/5xx here is NOT a takeover signal."},
    {"service": "Zendesk", "cname": r"\.zendesk\.com",
     "fingerprint": ["Help Center Closed"],
     "status": "not_vulnerable", "claimable": False, "nxdomain_is_enough": False,
     "note": "Requires host verification; low/again-check."},
    {"service": "Akamai CDN (EdgeKey)", "cname": r"\.edgekey\.net|\.akamaiedge\.net|\.akamai\.net|\.akadns\.net",
     "fingerprint": [],
     "status": "not_vulnerable", "claimable": False, "nxdomain_is_enough": False,
     "note": "Akamai CDN edge nodes - customer-specific configurations, not claimable."},
    {"service": "Google Workspace (GHS)", "cname": r"ghs\.google\.com|ghs\.googlehosted\.com",
     "fingerprint": [],
     "status": "not_vulnerable", "claimable": False, "nxdomain_is_enough": False,
     "note": "Google Hosted Services for Workspace - requires domain verification."},
    {"service": "Salesforce Marketing Cloud", "cname": r"\.sfmc-content\.com|\.exacttarget\.com",
     "fingerprint": [],
     "status": "edge", "claimable": False, "nxdomain_is_enough": False,
     "note": "SFMC content delivery - typically requires account verification."},
    {"service": "Azure App Proxy (MS Identity)", "cname": r"\.msappproxy\.net|\.msidentity\.com",
     "fingerprint": [],
     "status": "not_vulnerable", "claimable": False, "nxdomain_is_enough": False,
     "note": "Microsoft Application Proxy - tenant-specific, not claimable."},
    {"service": "Microsoft Edge CDN", "cname": r"\.t-msedge\.net$|part-\d+\.t-\d+\.t-msedge\.net",
     "fingerprint": [],
     "status": "not_vulnerable", "claimable": False, "nxdomain_is_enough": False,
     "note": "Microsoft Edge CDN node - infrastructure endpoint, not claimable."},
]

# Azure Front Door modern hashed-endpoint pattern -> structurally unclaimable.
HASHED_AFD = re.compile(r"-[a-z0-9]{12,}\.(z|a)\d{2}\.azurefd\.net", re.I)

# Azure Cloud Service hashed name pattern -> not re-registerable
HASHED_CLOUDAPP = re.compile(r"[a-z0-9]{40,}\.cloudapp\.(net|azure\.com)$", re.I)

# Services that incur costs when resources are created
COST_WARNING_SERVICES = {
    "Azure App Service": "Creating Azure Web App may incur costs. Verify RoE allows resource creation.",
    "Azure Cloud Service (classic)": "Classic Cloud Service may generate billing charges.",
    "Azure APIM": "Creating APIM instance may incur significant costs.",
    "Azure Traffic Manager": "Traffic Manager profiles may generate usage charges.",
    "Azure Blob": "Storage account creation may incur costs.",
    "Azure Storage (Web)": "Storage account creation may incur costs.",
    "AWS S3": "S3 bucket creation may incur storage costs.",
    "Elastic Beanstalk": "EB environment creation may incur AWS charges.",
}

# RFC-1123-ish hostname validation (allows leading '_' for DMARC/etc style labels).
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*"
    r"\.?$"
)


def valid_hostname(h):
    """Basic structural validation of a hostname before hitting the resolver."""
    return bool(h) and bool(HOSTNAME_RE.match(h))


# Our fingerprint DB splits some vendors more finely than can-i-take-over-xyz
# does. This maps our granular service names onto the repo's single umbrella
# entry so cross-referencing lines up instead of reporting "not in xyz repo".
XYZ_SERVICE_ALIASES = {
    "azure apim": "microsoft azure",
    "azure app service": "microsoft azure",
    "azure cloud service (classic)": "microsoft azure",
    "azure cloud service (hashed)": "microsoft azure",
    "azure blob": "microsoft azure",
    "azure storage (web)": "microsoft azure",
    "azure traffic manager": "microsoft azure",
    "azure front door": "microsoft azure",
    "azure front door (hashed)": "microsoft azure",
    "elastic beanstalk": "amazon elastic beanstalk",
    "aws s3": "amazon s3",
    "wordpress.com": "wordpress",
    "readme.io": "readme",
}


def xyz_family(service_name):
    """Normalize a tool service name to the can-i-take-over-xyz umbrella name."""
    n = (service_name or "").strip().lower()
    return XYZ_SERVICE_ALIASES.get(n, n)


# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# Try to import colorama for Windows support, fallback to basic ANSI
try:
    from colorama import init, Fore, Back, Style
    init()
except ImportError:
    pass


def dbg(msg):
    """Verbose/debug logging to stderr (does not pollute JSON/stdout)."""
    print(f"{Colors.DIM}[debug] {msg}{Colors.RESET}", file=sys.stderr)


resolver = dns.resolver.Resolver()
resolver.lifetime = 6.0
resolver.timeout = 6.0

# Global politeness delay (seconds). Set from --delay. Jittered per request.
REQUEST_DELAY = 0.0


def polite_sleep():
    """Optional jittered delay to avoid hammering target/3rd-party infra."""
    if REQUEST_DELAY > 0:
        time.sleep(REQUEST_DELAY + random.uniform(0, REQUEST_DELAY))


# Cache directory for GitHub repo data
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".takeover_triage_cache")
CACHE_EXPIRY_HOURS = 24  # Refresh cache after 24 hours


# ===========================================================================
# Cache helpers
# ===========================================================================
def get_cache_path(filename):
    """Get cache file path."""
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
    return os.path.join(CACHE_DIR, filename)


def is_cache_valid(cache_file):
    """Check if cache file exists and is not expired."""
    if not os.path.exists(cache_file):
        return False
    cache_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(cache_file))
    return cache_age < timedelta(hours=CACHE_EXPIRY_HOURS)


# ===========================================================================
# can-i-take-over-xyz fetch / parse
# ===========================================================================
def fetch_github_repo_raw(repo_url, file_path, verbose=False):
    """Fetch raw file content from GitHub repository (tries master then main)."""
    raw_base = repo_url.replace("github.com", "raw.githubusercontent.com").rstrip("/")
    for branch in ("master", "main"):
        raw_url = f"{raw_base}/{branch}/{file_path}"
        try:
            polite_sleep()
            response = requests.get(raw_url, timeout=10,
                                    headers={"User-Agent": "TakeoverTriage/2.1"})
            if response.status_code == 200:
                return response.text
        except Exception as e:
            if verbose:
                dbg(f"GitHub fetch failed ({raw_url}): {e}")
    return None


def parse_xyz_readme_vulnerable(readme_content):
    """Parse the README.md to extract vulnerable services from the table."""
    vulnerable_services = []
    lines = readme_content.split('\n')
    in_table = False
    header_found = False

    for line in lines:
        if '| Service' in line and '| Status' in line and '| Fingerprint' in line:
            in_table = True
            header_found = True
            continue

        if header_found and re.match(r'^\|[\s\-:]+\|', line):
            header_found = False
            continue

        if in_table and line.startswith('|') and not header_found:
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 4:
                service_name = parts[1] if len(parts) > 1 else ""
                status = parts[2] if len(parts) > 2 else ""
                service_name = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', service_name)
                status_l = status.lower()
                # NOTE: 'not vulnerable' also contains 'vulnerable' -> exclude it.
                if 'vulnerable' in status_l and 'not vulnerable' not in status_l and service_name:
                    vulnerable_services.append({
                        "service": service_name,
                        "status": "vulnerable",
                        "source": "readme"
                    })

        if in_table and line.startswith('##') and not line.startswith('###'):
            in_table = False

    return vulnerable_services


def fetch_can_i_take_over_xyz(verbose=False):
    """Fetch and parse fingerprints from can-i-take-over-xyz repository."""
    cache_file = get_cache_path("can-i-take-over-xyz.json")

    if is_cache_valid(cache_file):
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            if verbose:
                dbg(f"Cache read failed, refetching: {e}")

    print(f"{Colors.YELLOW}[*] Fetching latest fingerprints from can-i-take-over-xyz repository...{Colors.RESET}")

    repo_url = "https://github.com/EdOverflow/can-i-take-over-xyz"
    fingerprints_data = {
        "source": repo_url,
        "fetch_time": datetime.now().isoformat(),
        "services": [],
        "vulnerable": [],
        "not_vulnerable": [],
        "unknown": []
    }

    readme = fetch_github_repo_raw(repo_url, "README.md", verbose)
    if readme:
        fingerprints_data["readme_hash"] = hashlib.md5(readme.encode()).hexdigest()

        service_pattern = re.compile(r'^\s*\*\s*\[([^\]]+)\]\(([^)]+)\)', re.MULTILINE)
        for match in service_pattern.finditer(readme):
            fingerprints_data["services"].append({
                "name": match.group(1),
                "url": match.group(2)
            })

        for svc in parse_xyz_readme_vulnerable(readme):
            fingerprints_data["vulnerable"].append(svc)

        vuln_pattern = re.compile(r'^\s*\*\s*\[Vulnerable\]\s*\[([^\]]+)\]', re.MULTILINE)
        for match in vuln_pattern.finditer(readme):
            service_name = match.group(1)
            if not any(v.get("service") == service_name for v in fingerprints_data["vulnerable"]):
                fingerprints_data["vulnerable"].append({
                    "service": service_name,
                    "status": "vulnerable",
                    "source": "readme_tag"
                })

    fingerprints_json = fetch_github_repo_raw(repo_url, "fingerprints.json", verbose)
    if fingerprints_json:
        try:
            parsed = json.loads(fingerprints_json)
            if isinstance(parsed, list):
                for entry in parsed:
                    if not isinstance(entry, dict):
                        continue
                    service_name = entry.get("service", "")
                    # The repo uses "status": "Vulnerable" (capitalised) AND a
                    # boolean "vulnerable": true. Our old exact lowercase compare
                    # matched neither, so nothing was ever counted vulnerable.
                    status_raw = str(entry.get("status", "unknown"))
                    status_norm = status_raw.strip().lower()
                    is_vuln = entry.get("vulnerable", None)
                    if is_vuln is None:
                        is_vuln = (status_norm == "vulnerable")
                    cname = entry.get("cname", [])
                    if isinstance(cname, list):
                        cname = "|".join(cname)
                    fingerprint_entries = entry.get("fingerprint", [])
                    if isinstance(fingerprint_entries, str):
                        fingerprint_entries = [fingerprint_entries]
                    service_data = {
                        "service": service_name,
                        "cname": cname,
                        "fingerprint": fingerprint_entries,
                        "status": status_raw,
                        "vulnerable": bool(is_vuln),
                        "nxdomain_is_enough": entry.get("nxdomain", False),
                        "note": entry.get("response", [""])[0] if entry.get("response") else "",
                        "source": "fingerprints.json"
                    }
                    if is_vuln:
                        if not any(v.get("service") == service_name for v in fingerprints_data["vulnerable"]):
                            fingerprints_data["vulnerable"].append(service_data)
                    elif status_norm in ("not vulnerable", "not_vulnerable"):
                        fingerprints_data["not_vulnerable"].append(service_data)
                    else:  # "Edge case", "unknown", etc.
                        fingerprints_data["unknown"].append(service_data)
        except json.JSONDecodeError:
            print(f"{Colors.YELLOW}[!] Failed to parse fingerprints.json from repository{Colors.RESET}")

    if fingerprints_data["services"]:
        print(f"{Colors.DIM}[*] Fetching individual service files...{Colors.RESET}")
        service_files = []
        for service in fingerprints_data["services"][:30]:
            service_slug = service["name"].lower().replace(" ", "-").replace(".", "")
            file_content = fetch_github_repo_raw(repo_url, f"entries/{service_slug}.json", verbose)
            if file_content:
                try:
                    service_info = json.loads(file_content)
                    service_files.append(service_info)
                    svc_status = str(service_info.get("status", "")).lower()
                    svc_is_vuln = service_info.get("vulnerable", None)
                    if svc_is_vuln is None:
                        svc_is_vuln = ("vulnerable" in svc_status and "not vulnerable" not in svc_status)
                    if svc_is_vuln:
                        svc_name = service_info.get("service") or service["name"]
                        if not any(v.get("service") == svc_name for v in fingerprints_data["vulnerable"]):
                            fingerprints_data["vulnerable"].append({
                                "service": svc_name,
                                "status": "vulnerable",
                                "source": "service_file"
                            })
                except json.JSONDecodeError:
                    pass
        fingerprints_data["service_files"] = service_files

    try:
        with open(cache_file, 'w') as f:
            json.dump(fingerprints_data, f, indent=2)
        vuln_count = len(fingerprints_data["vulnerable"])
        print(f"{Colors.GREEN}[\u2713] Cached fingerprints from can-i-take-over-xyz "
              f"({vuln_count} vulnerable services found){Colors.RESET}")
    except Exception as e:
        if verbose:
            dbg(f"Cache write failed: {e}")

    return fingerprints_data


def compare_with_xyz_repo(results, xyz_data):
    """Compare scan results with can-i-take-over-xyz repository data."""
    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}Cross-Reference with can-i-take-over-xyz Repository{Colors.RESET}")
    print(f"{Colors.DIM}Source: {xyz_data.get('source', 'Unknown')}{Colors.RESET}")
    print(f"{Colors.DIM}Fetched: {xyz_data.get('fetch_time', 'Unknown')}{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}\n")

    xyz_vulnerable_services = set()
    xyz_all_services = set()

    for service in xyz_data.get("vulnerable", []):
        if service.get("service"):
            xyz_vulnerable_services.add(service["service"].lower())
            xyz_all_services.add(service["service"].lower())
    for key in ("not_vulnerable", "unknown"):
        for service in xyz_data.get(key, []):
            if service.get("service"):
                xyz_all_services.add(service["service"].lower())
    for service in xyz_data.get("services", []):
        if service.get("name"):
            xyz_all_services.add(service["name"].lower())

    matched_services, missed_by_repo = [], []
    confirmed_by_repo, conflicting = [], []

    for result in results:
        if not result:
            continue
        service_name = xyz_family(result.get("service"))
        if not service_name:
            missed_by_repo.append(result)
            continue
        if service_name in xyz_all_services:
            matched_services.append(result)
            if service_name in xyz_vulnerable_services:
                if result["verdict"] in ["CONFIRM_MANUALLY", "NEEDS_CARE"]:
                    confirmed_by_repo.append(result)
                    print(f"{Colors.GREEN}[\u2713] {result['host']:45} -> {result['service']}{Colors.RESET}")
                    print(f"       {Colors.GREEN}Confirmed by can-i-take-over-xyz: "
                          f"{service_name} is listed as VULNERABLE{Colors.RESET}")
                elif result.get("nxdomain"):
                    # We agree the record is dangling (NXDOMAIN) yet still didn't
                    # green-light it -> a genuine, interesting divergence.
                    conflicting.append(result)
                    print(f"{Colors.YELLOW}[!] {result['host']:45} -> {result['service']}{Colors.RESET}")
                    print(f"       {Colors.YELLOW}CONFLICT: Our verdict={result['verdict']} (NXDOMAIN), "
                          f"xyz says {service_name} is VULNERABLE{Colors.RESET}")
                else:
                    # xyz lists the family as vulnerable-if-dangling, but this
                    # instance resolves/is live -> not a conflict, just N/A.
                    print(f"{Colors.DIM}[-] {result['host']:45} -> {result['service']} "
                          f"(xyz: {service_name} vulnerable only if dangling; this one is live){Colors.RESET}")
            else:
                print(f"{Colors.DIM}[-] {result['host']:45} -> {result['service']} "
                      f"(listed in xyz repo but not marked vulnerable){Colors.RESET}")
        else:
            missed_by_repo.append(result)

    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}XYZ REPO CROSS-REFERENCE SUMMARY:{Colors.RESET}")
    print(f"  {Colors.GREEN}Confirmed by xyz repo:     {len(confirmed_by_repo)}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Conflicting findings:      {len(conflicting)}{Colors.RESET}")
    print(f"  {Colors.DIM}Services matched in repo:   {len(matched_services)}{Colors.RESET}")
    print(f"  {Colors.DIM}Services not in xyz repo:   {len(missed_by_repo)}{Colors.RESET}")
    print(f"  {Colors.DIM}Total xyz vulnerable services: {len(xyz_vulnerable_services)}{Colors.RESET}")
    print(f"  {Colors.DIM}Total xyz services:           {len(xyz_all_services)}{Colors.RESET}")

    if xyz_vulnerable_services:
        print(f"\n{Colors.GREEN}[i] Vulnerable services in can-i-take-over-xyz repo:{Colors.RESET}")
        for svc in sorted(xyz_vulnerable_services)[:15]:
            print(f"    {Colors.DIM}* {svc}{Colors.RESET}")
        if len(xyz_vulnerable_services) > 15:
            print(f"    {Colors.DIM}... and {len(xyz_vulnerable_services) - 15} more{Colors.RESET}")

    if missed_by_repo:
        print(f"\n{Colors.BLUE}[i] Services found by scanner but missing from xyz repo:{Colors.RESET}")
        for result in missed_by_repo[:10]:
            print(f"    {Colors.DIM}* {result.get('service') or 'Unknown'} "
                  f"({result.get('verdict') or '?'}){Colors.RESET}")

    if conflicting:
        print(f"\n{Colors.YELLOW}[!] Conflicts require manual investigation:{Colors.RESET}")
        for result in conflicting[:5]:
            print(f"    {Colors.DIM}* {result['host']} -> {result.get('service', 'Unknown')} "
                  f"(Our: {result['verdict']}, XYZ: VULNERABLE){Colors.RESET}")

    return {
        "matched": len(matched_services),
        "confirmed": len(confirmed_by_repo),
        "conflicting": len(conflicting),
        "missed": len(missed_by_repo)
    }


# ===========================================================================
# DNS resolution
# ===========================================================================
def resolve_doh(host, record_type="A", verbose=False):
    """DNS-over-HTTPS fallback using Cloudflare. Returns list of answer data."""
    try:
        polite_sleep()
        r = requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": host, "type": record_type},
            headers={"accept": "application/dns-json"},
            timeout=5,
        )
        if r.status_code == 200:
            data = r.json()
            return [ans["data"] for ans in data.get("Answer", []) if ans.get("data")]
    except Exception as e:
        if verbose:
            dbg(f"DoH {record_type} lookup failed for {host}: {e}")
    return []


def resolve_a_state(name, use_doh=False, verbose=False):
    """
    Determine the address-resolution state of a name.

    Returns one of:
        "resolves"  - has an A or AAAA record
        "nxdomain"  - authoritative NXDOMAIN
        "unknown"   - exists-but-no-address, or the lookup was inconclusive
                      (timeout/SERVFAIL). Deliberately NOT treated as 'live'.
    """
    saw_noanswer = False
    for rtype in ("A", "AAAA"):
        try:
            resolver.resolve(name, rtype)
            return "resolves"
        except dns.resolver.NXDOMAIN:
            return "nxdomain"
        except dns.resolver.NoAnswer:
            saw_noanswer = True
            continue
        except Exception as e:
            if verbose:
                dbg(f"DNS {rtype} error for {name}: {e}")
            continue

    if use_doh:
        for rtype in ("A", "AAAA"):
            if resolve_doh(name, rtype, verbose):
                return "resolves"

    # No address found. If the name clearly existed (NoAnswer) it's not
    # dangling; if we simply failed, we stay honest and say "unknown".
    return "unknown"


def chase_cname(host, use_doh=False, verbose=False):
    """
    Follow the CNAME chain.

    Returns (chain, final_target, state) where state is the resolve_a_state
    of the final target: "resolves" | "nxdomain" | "unknown".
    """
    chain, cur = [], host
    for _ in range(10):
        try:
            ans = resolver.resolve(cur, "CNAME")
            tgt = str(ans[0].target).rstrip(".")
            chain.append(tgt)
            cur = tgt
        except dns.resolver.NoAnswer:
            break  # no more CNAMEs; cur is the final label
        except dns.resolver.NXDOMAIN:
            return chain, cur, "nxdomain"  # dangling target!
        except Exception as e:
            if verbose:
                dbg(f"CNAME error for {cur}: {e}")
            if use_doh:
                doh_results = resolve_doh(cur, "CNAME", verbose)
                if doh_results:
                    tgt = doh_results[0].rstrip(".")
                    chain.append(tgt)
                    cur = tgt
                    continue
            break

    state = resolve_a_state(cur, use_doh, verbose)
    return chain, cur, state


def chase_ns(host, use_doh=False, verbose=False):
    """
    Check for dangling NS delegation records.
    Returns (ns_target, service_fingerprint) or (None, None).
    """
    try:
        ans = resolver.resolve(host, "NS")
        targets = [str(t).rstrip(".") for t in ans]
        for target in targets:
            fp = match_service(target)
            if fp and fp.get("nxdomain_is_enough"):
                if resolve_a_state(target, use_doh, verbose) == "nxdomain":
                    return target, fp
    except Exception as e:
        if verbose:
            dbg(f"NS lookup error for {host}: {e}")
    return None, None


# ===========================================================================
# Fingerprint matching / HTTP
# ===========================================================================
def match_service(target):
    """Match target against fingerprint database."""
    if HASHED_AFD.search(target or ""):
        return {
            "service": "Azure Front Door (hashed)",
            "status": "not_vulnerable", "claimable": False,
            "nxdomain_is_enough": False, "fingerprint": [],
            "note": "Random hash in endpoint name -> cannot be re-registered."
        }
    if HASHED_CLOUDAPP.search(target or ""):
        return {
            "service": "Azure Cloud Service (hashed)",
            "status": "not_vulnerable", "claimable": False,
            "nxdomain_is_enough": False, "fingerprint": [],
            "note": "Cloud service name contains random hash -> NOT re-registerable."
        }
    for fp in FINGERPRINTS:
        if re.search(fp["cname"], target or "", re.I):
            return fp
    return None


def detect_s3_region(host, cname_target, verbose=False):
    """Try to determine S3 bucket region from CNAME or HTTP response."""
    region_match = re.search(r'\.s3[.-]([^.]+)\.amazonaws', cname_target or "")
    if region_match:
        return region_match.group(1)
    try:
        polite_sleep()
        r = requests.get(f"http://{host}", allow_redirects=False, timeout=5, verify=False)
        location = r.headers.get('Location', '')
        region_match = re.search(r's3[.-]([^.]+)\.amazonaws', location)
        if region_match:
            return region_match.group(1)
    except Exception as e:
        if verbose:
            dbg(f"S3 region detection failed for {host}: {e}")
    return "unknown (try us-east-1)"


def check_fingerprint(body, status_code, fingerprint_strings):
    """
    Check unclaimed-error fingerprints with context awareness.

    For fingerprints that mention '404', we only accept them when the page is
    plausibly a real 404 (HTTP 404, or strong textual 404 indicators). Other
    fingerprint strings in the same list are still evaluated normally.
    """
    if not body or not fingerprint_strings:
        return None

    body_lower = body.lower()
    for fp_string in fingerprint_strings:
        if fp_string.lower() not in body_lower:
            continue
        if "404" in fp_string:
            if status_code == 404:
                return fp_string
            if re.search(r'<title>404|not found|error 404|does not exist|No such|unavailable',
                         body, re.I):
                return fp_string
            # Weak 404 match: skip THIS string, keep testing the rest.
            continue
        return fp_string
    return None


def http_body(host, verbose=False):
    """Fetch HTTP response from host. Returns (status_code, body_or_marker)."""
    for scheme in ("https", "http"):
        try:
            polite_sleep()
            r = requests.get(
                f"{scheme}://{host}",
                timeout=8, verify=False, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; TakeoverTriage/2.1)"}
            )
            return r.status_code, r.text[:4000]
        except requests.exceptions.SSLError:
            return None, "SSL_ERROR"
        except requests.exceptions.ConnectionError:
            continue
        except Exception as e:
            if verbose:
                dbg(f"HTTP {scheme} error for {host}: {e}")
            continue
    return None, ""


# ===========================================================================
# Core triage
# ===========================================================================
def triage(host, use_doh=False, verbose=False):
    """Perform full triage on a single host."""
    start_time = time.time()
    host = host.strip().rstrip(".")
    if not host:
        return None

    r = {
        "host": host, "cname_chain": [], "final_target": None,
        "matched_target": None, "nxdomain": False, "resolve_state": None,
        "service": None, "verdict": "DEAD", "reason": "", "next_step": "",
        "cost_warning": None, "ns_takeover": False, "s3_region": None,
        "gate2_detail": None, "elapsed": "0.00s"
    }

    # ---- NS delegation takeover first ----
    if verbose:
        print(f"{Colors.DIM}[*] Checking NS delegation for {host}{Colors.RESET}")
    ns_target, ns_fp = chase_ns(host, use_doh, verbose)
    if ns_target and ns_fp:
        r.update({
            "ns_takeover": True, "service": ns_fp["service"],
            "final_target": ns_target, "nxdomain": True,
            "resolve_state": "nxdomain", "verdict": "CONFIRM_MANUALLY",
            "reason": f"NS delegation to {ns_target} ({ns_fp['service']}) - nameserver is NXDOMAIN",
            "next_step": ns_fp["note"], "gate2_detail": "NS target is NXDOMAIN",
        })
        if ns_fp["service"] in COST_WARNING_SERVICES:
            r["cost_warning"] = COST_WARNING_SERVICES[ns_fp["service"]]
        r["elapsed"] = f"{time.time() - start_time:.2f}s"
        return r

    # ---- CNAME takeover ----
    if verbose:
        print(f"{Colors.DIM}[*] Resolving CNAME chain for {host}{Colors.RESET}")
    chain, target, state = chase_cname(host, use_doh, verbose)
    nx = (state == "nxdomain")
    r["cname_chain"], r["final_target"] = chain, target
    r["nxdomain"], r["resolve_state"] = nx, state

    # Gate 1: must point at a known 3rd-party service via CNAME
    if not chain:
        r["reason"] = "No CNAME -> not a takeover candidate (A-record host)."
        r["elapsed"] = f"{time.time() - start_time:.2f}s"
        return r

    # Fingerprint EVERY hop, not just the terminal name. A chain can walk past
    # the recognizable, claimable hostname (e.g. <acct>.web.core.windows.net)
    # into internal infra (e.g. web.<stamp>.store.core.windows.net) that matches
    # nothing. Prefer the FIRST CLAIMABLE hop: a non-vulnerable front (e.g.
    # Cloudflare) ahead of a dangling S3/Netlify hop must NOT mask it. Only if
    # no hop is claimable do we fall back to the first match (for the DEAD note).
    fp = matched_hop = None
    first_fp = first_hop = None
    for hop in chain:
        cand = match_service(hop)
        if not cand:
            continue
        if first_fp is None:
            first_fp, first_hop = cand, hop
        if cand.get("claimable") and cand.get("status") != "not_vulnerable":
            fp, matched_hop = cand, hop
            break
    if fp is None:
        fp, matched_hop = first_fp, first_hop

    if not fp:
        r["reason"] = (f"CNAME chain ({' -> '.join(chain)}) matches no known "
                       f"takeoverable service.") if len(chain) > 1 else \
                      f"CNAME to {target} matches no known takeoverable service."
        r["elapsed"] = f"{time.time() - start_time:.2f}s"
        return r

    r["service"] = fp["service"]
    r["matched_target"] = matched_hop
    # For NXDOMAIN semantics, what matters is whether the matched service hop is
    # the one that is gone. If the chain broke (NXDOMAIN) at/after the matched
    # hop, treat it as gone; if the chain continued past it to a live target,
    # the matched resource is still live.
    if matched_hop != target and state == "resolves":
        # matched an intermediate hop but the chain resolves further -> the
        # matched resource is live; NXDOMAIN shortcut does not apply here.
        nx = False

    if "S3" in fp["service"]:
        r["s3_region"] = detect_s3_region(host, matched_hop, verbose)
        if r["s3_region"] and r["s3_region"] != "unknown (try us-east-1)":
            r["next_step"] = f"Create bucket in {r['s3_region']}: {fp['note']}"

    if fp["service"] in COST_WARNING_SERVICES:
        r["cost_warning"] = COST_WARNING_SERVICES[fp["service"]]

    # Structurally not claimable -> dead regardless of everything else
    if fp["status"] == "not_vulnerable" or not fp.get("claimable", False):
        r["verdict"] = "DEAD"
        r["reason"] = f"{fp['service']}: {fp['note']}"
        r["elapsed"] = f"{time.time() - start_time:.2f}s"
        return r

    # Gate 2: is the backing resource gone?
    resource_gone = False
    if nx:
        resource_gone = True
        gate2_detail = "target is NXDOMAIN"
    else:
        status_code, body = http_body(host, verbose)
        if verbose and status_code:
            print(f"{Colors.DIM}[*] HTTP {status_code} for {host}{Colors.RESET}")

        if body == "SSL_ERROR":
            gate2_detail = "SSL error - host exists but certificate mismatch"
        else:
            hit = check_fingerprint(body, status_code, fp.get("fingerprint", []))
            # Two Gate-2 regimes, split on nxdomain_is_enough:
            #  * nxdomain_is_enough=False (S3, GitHub Pages, Heroku, ...): the CNAME
            #    target stays LIVE even when the bucket/app is unclaimed, so the HTTP
            #    body error string IS the correct "resource gone" signal.
            #  * nxdomain_is_enough=True  (Azure Storage/App Service/APIM/TM, EB, ...):
            #    the endpoint only resolves while the account/app EXISTS. A resolving
            #    endpoint therefore means it is CLAIMED. The body may still say
            #    "content does not exist" (empty $web container, missing path, etc.),
            #    but that is normal live-account behaviour - NOT a takeover signal.
            #    For these, only NXDOMAIN (handled above) satisfies Gate 2.
            if hit and not fp.get("nxdomain_is_enough"):
                resource_gone = True
                gate2_detail = f"unclaimed-error string present: {hit!r}"
            elif hit and fp.get("nxdomain_is_enough"):
                gate2_detail = (f"error string {hit!r} present BUT endpoint {state} "
                                f"(account/app exists -> claimed). NXDOMAIN required "
                                f"for this service; treating as live.")
            else:
                gate2_detail = f"target {state} and no unclaimed-error string"
    r["gate2_detail"] = gate2_detail

    if not resource_gone:
        r["verdict"] = "DEAD"
        if state == "unknown":
            r["reason"] = (f"Gate 2 INCONCLUSIVE: {gate2_detail}. "
                           f"Resolution was inconclusive - re-run (try --doh-fallback).")
        else:
            r["reason"] = f"Gate 2 FAIL: {gate2_detail}. Resource is live."
        r["elapsed"] = f"{time.time() - start_time:.2f}s"
        return r

    # Gates 1+2 passed and service is claimable -> hand to human for Gate 3
    r["verdict"] = "CONFIRM_MANUALLY"
    r["reason"] = (f"Gate1 OK (CNAME->{fp['service']}); "
                   f"Gate2 OK ({gate2_detail}); Gate3 pending.")
    r["next_step"] = r.get("next_step") or fp["note"]

    if fp["status"] == "edge":
        r["verdict"] = "NEEDS_CARE"
        r["reason"] += " [edge service: verification may block reclaim]"

    r["elapsed"] = f"{time.time() - start_time:.2f}s"
    return r


def process_hosts(hosts, use_doh=False, verbose=False, workers=10):
    """Process hosts with controlled concurrency."""
    results = []
    total = len(hosts)

    if workers <= 1:
        for i, host in enumerate(hosts, 1):
            if verbose:
                print(f"\n{Colors.CYAN}[{i}/{total}] Processing: {host}{Colors.RESET}")
            result = triage(host, use_doh, verbose)
            if result:
                results.append(result)
                if verbose:
                    print(f"  {Colors.DIM}-> {result['verdict']} ({result['service']}){Colors.RESET}")
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(triage, host, use_doh, verbose): host for host in hosts}
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    if verbose:
                        dbg(f"Worker crashed for {futures[future]}: {e}")
                    result = None
                if result:
                    results.append(result)
    return results


# ===========================================================================
# Output / display
# ===========================================================================
def print_banner():
    print(f"{Colors.CYAN}{Colors.BOLD}{BANNER}{Colors.RESET}")
    print(f"{Colors.YELLOW}{BANNER_INFO}{Colors.RESET}")


def print_result_line(res, verbose=False):
    """Print a single finding block."""
    icon_map = {
        "CONFIRM_MANUALLY": f"{Colors.RED}{Colors.BOLD}[!!]{Colors.RESET}",
        "NEEDS_CARE": f"{Colors.YELLOW}[? ]{Colors.RESET}",
        "DEAD": f"{Colors.DIM}[- ]{Colors.RESET}",
    }
    icon = icon_map.get(res["verdict"], f"{Colors.DIM}[- ]{Colors.RESET}")

    print(f"{icon} {Colors.BOLD}{res['host']:45}{Colors.RESET} -> "
          f"{Colors.CYAN}{res['service'] or '(no service)'}{Colors.RESET}")
    print(f"       {Colors.DIM}{res['reason']}{Colors.RESET}")

    if res.get("ns_takeover"):
        print(f"       {Colors.MAGENTA}TYPE: NS Delegation Takeover{Colors.RESET}")
    if res.get("s3_region") and res["s3_region"] != "unknown (try us-east-1)":
        print(f"       {Colors.BLUE}S3 REGION: {res['s3_region']}{Colors.RESET}")
    if res.get("gate2_detail"):
        print(f"       {Colors.DIM}GATE2: {res['gate2_detail']}{Colors.RESET}")
    if res.get("cost_warning"):
        print(f"       {Colors.YELLOW}WARNING: {res['cost_warning']}{Colors.RESET}")
    if res.get("next_step"):
        print(f"       {Colors.GREEN}NEXT: {res['next_step']}{Colors.RESET}")
    if res.get("elapsed"):
        print(f"       {Colors.DIM}TIME: {res['elapsed']}{Colors.RESET}")

    if verbose:
        if res.get("cname_chain"):
            chain_str = f"       {Colors.DIM}CNAME CHAIN: {' -> '.join(res['cname_chain'])}{Colors.RESET}"
            if len(chain_str) > 120:
                print(f"       {Colors.DIM}CNAME CHAIN:{Colors.RESET}")
                for i, link in enumerate(res['cname_chain']):
                    print(f"       {Colors.DIM}  {i + 1}. {link}{Colors.RESET}")
            else:
                print(chain_str)
        if res.get("final_target"):
            print(f"       {Colors.DIM}FINAL TARGET: {res['final_target']}{Colors.RESET}")
        if res.get("resolve_state"):
            print(f"       {Colors.DIM}RESOLVE STATE: {res['resolve_state']}{Colors.RESET}")
        if res.get("nxdomain") is not None:
            nx_color = Colors.RED if res['nxdomain'] else Colors.GREEN
            print(f"       {Colors.DIM}NXDOMAIN: {nx_color}{res['nxdomain']}{Colors.RESET}")


def print_summary(buckets, results, scan_time):
    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}SUMMARY:{Colors.RESET}")
    confirm = buckets.get('CONFIRM_MANUALLY', [])
    needs_care = buckets.get('NEEDS_CARE', [])
    dead = buckets.get('DEAD', [])
    print(f"  {Colors.RED}{Colors.BOLD}CONFIRM_MANUALLY: {len(confirm)}{Colors.RESET}  "
          f"(require manual verification - Gate 3)")
    print(f"  {Colors.YELLOW}NEEDS_CARE:       {len(needs_care)}{Colors.RESET}  "
          f"(edge cases, verify carefully)")
    print(f"  {Colors.GREEN}DEAD:             {len(dead)}{Colors.RESET}  (not vulnerable)")
    print(f"  {Colors.CYAN}TOTAL:            {len(results)}{Colors.RESET}")
    print(f"\n{Colors.DIM}Scan completed in {scan_time:.2f}s{Colors.RESET}")

    cost_flagged = [r for r in results if r.get("cost_warning")]
    if cost_flagged:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}WARNING: {len(cost_flagged)} finding(s) "
              f"flagged with cost warnings.{Colors.RESET}")
        print(f"{Colors.YELLOW}   Please verify RoE allows resource creation before testing.{Colors.RESET}")


def print_help_examples():
    print(f"""
{Colors.CYAN}{Colors.BOLD}EXAMPLES:{Colors.RESET}
  {Colors.GREEN}Basic usage with file input:{Colors.RESET}
    python takeover_triage.py -l subs.txt

  {Colors.GREEN}Read from stdin:{Colors.RESET}
    cat subs.txt | python takeover_triage.py
    echo "sub.example.com" | python takeover_triage.py

  {Colors.GREEN}Save results to JSON:{Colors.RESET}
    python takeover_triage.py -l subs.txt --json results.json

  {Colors.GREEN}Verbose mode:{Colors.RESET}
    python takeover_triage.py -l subs.txt -v

  {Colors.GREEN}DNS-over-HTTPS fallback:{Colors.RESET}
    python takeover_triage.py -l subs.txt --doh-fallback

  {Colors.GREEN}Concurrent processing:{Colors.RESET}
    python takeover_triage.py -l subs.txt -w 20

  {Colors.GREEN}Be polite to target infra (delay + jitter):{Colors.RESET}
    python takeover_triage.py -l subs.txt --delay 0.2

  {Colors.GREEN}Cross-reference with can-i-take-over-xyz repo:{Colors.RESET}
    python takeover_triage.py -l subs.txt --xyz

{Colors.CYAN}{Colors.BOLD}VERDICTS EXPLAINED:{Colors.RESET}
  {Colors.RED}CONFIRM_MANUALLY{Colors.RESET}  High-confidence candidate. Resource appears unclaimed
                     but you MUST manually attempt to claim it (Gate 3).
  {Colors.YELLOW}NEEDS_CARE{Colors.RESET}        Likely candidate but service has known verification
                     mechanisms that may prevent takeover.
  {Colors.GREEN}DEAD{Colors.RESET}              No takeover possible: no CNAME, resource live, service
                     structurally unclaimable, or resolution inconclusive.
""")


# ===========================================================================
# Host loading
# ===========================================================================
def read_hosts(list_path, verbose=False):
    """Read hosts from a file or stdin; validate and de-duplicate."""
    if list_path:
        with open(list_path) as f:
            raw = [line.strip() for line in f if line.strip()]
    else:
        raw = [line.strip() for line in sys.stdin if line.strip()]

    hosts, skipped, seen = [], 0, set()
    for h in raw:
        h = h.rstrip(".")
        if not valid_hostname(h):
            skipped += 1
            if verbose:
                dbg(f"Skipping invalid hostname: {h!r}")
            continue
        if h.lower() in seen:
            continue
        seen.add(h.lower())
        hosts.append(h)

    if skipped:
        print(f"{Colors.YELLOW}[!] Skipped {skipped} invalid hostname(s).{Colors.RESET}")
    return hosts


def load_fingerprint_override(path):
    """Optionally replace the inline fingerprint DB with an external JSON file."""
    global FINGERPRINTS
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Fingerprint file must be a JSON list of objects.")
    FINGERPRINTS = data
    print(f"{Colors.GREEN}[\u2713] Loaded {len(data)} fingerprints from {path}{Colors.RESET}")


# ===========================================================================
# main
# ===========================================================================
def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="High-confidence subdomain-takeover triage tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          python takeover_triage.py -l subs.txt
          python takeover_triage.py -l subs.txt --json out.json
          echo sub.target.com | python takeover_triage.py
          python takeover_triage.py -l subs.txt -v --doh-fallback -w 15
          python takeover_triage.py -l subs.txt --xyz
        """)
    )
    parser.add_argument("-l", "--list", help="File of subdomains (one per line)")
    parser.add_argument("--json", help="Write full results to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show verbose processing information")
    parser.add_argument("--doh-fallback", action="store_true",
                        help="Use DNS-over-HTTPS fallback when system DNS fails")
    parser.add_argument("-w", "--workers", type=int, default=10,
                        help="Number of concurrent workers (default: 10, use 1 for sequential)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Politeness delay in seconds per request (jittered). Default: 0")
    parser.add_argument("-x", "--xyz", action="store_true",
                        help="Cross-reference findings with can-i-take-over-xyz GitHub repository")
    parser.add_argument("--no-cache", action="store_true",
                        help="Force fresh fetch from GitHub (ignore cache) when using --xyz")
    parser.add_argument("--fingerprints", metavar="FILE",
                        help="Load an external fingerprint DB (JSON list) instead of the inline one")
    parser.add_argument("--show-fingerprints", action="store_true",
                        help="Display the fingerprint database and exit")
    parser.add_argument("--show-services", action="store_true",
                        help="Show list of supported services and exit")
    parser.add_argument("--examples", action="store_true",
                        help="Show detailed examples and exit")
    parser.add_argument("--version", action="version",
                        version="takeover_triage v2.1 - Enhanced Edition with XYZ Support")
    return parser


def handle_info_commands(args):
    """Handle the exit-early informational flags. Returns True if handled."""
    if args.show_fingerprints:
        print(json.dumps(FINGERPRINTS, indent=2))
        return True

    if args.show_services:
        print(f"\n{Colors.CYAN}{Colors.BOLD}Supported Services:{Colors.RESET}")
        print("=" * 70)
        vulnerable = [f for f in FINGERPRINTS if f['status'] == 'vulnerable']
        edge = [f for f in FINGERPRINTS if f['status'] == 'edge']
        not_vuln = [f for f in FINGERPRINTS if f['status'] == 'not_vulnerable']

        print(f"\n{Colors.GREEN}{Colors.BOLD}Vulnerable (claimable - {len(vulnerable)} services):{Colors.RESET}")
        for f in vulnerable:
            cost = (f" {Colors.YELLOW}[MAY INCUR COSTS]{Colors.RESET}"
                    if f['service'] in COST_WARNING_SERVICES else "")
            print(f"  * {Colors.GREEN}{f['service']}{Colors.RESET}{cost}")

        print(f"\n{Colors.YELLOW}{Colors.BOLD}Edge Cases (verify carefully - {len(edge)} services):{Colors.RESET}")
        for f in edge:
            print(f"  * {Colors.YELLOW}{f['service']}{Colors.RESET}")

        print(f"\n{Colors.RED}{Colors.BOLD}Not Vulnerable (mitigated - {len(not_vuln)} services):{Colors.RESET}")
        for f in not_vuln:
            print(f"  * {Colors.RED}{f['service']}{Colors.RESET}")
        print()
        return True

    if args.examples:
        print_help_examples()
        return True

    return False


def main():
    global REQUEST_DELAY

    parser = build_arg_parser()
    args = parser.parse_args()

    if not any([args.show_fingerprints, args.show_services, args.examples]):
        print_banner()

    if args.fingerprints:
        try:
            load_fingerprint_override(args.fingerprints)
        except Exception as e:
            print(f"{Colors.RED}Error loading fingerprints file: {e}{Colors.RESET}")
            sys.exit(1)

    if handle_info_commands(args):
        return

    REQUEST_DELAY = max(0.0, args.delay)

    # Clear cache if requested
    if args.no_cache and args.xyz:
        cache_file = get_cache_path("can-i-take-over-xyz.json")
        if os.path.exists(cache_file):
            os.remove(cache_file)
            print(f"{Colors.YELLOW}[!] Cache cleared{Colors.RESET}")

    # Fetch xyz data if requested
    xyz_data = None
    if args.xyz:
        try:
            xyz_data = fetch_can_i_take_over_xyz(args.verbose)
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Failed to fetch xyz repository data: {e}{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Continuing with normal scan...{Colors.RESET}")

    # Read + validate hosts
    hosts = read_hosts(args.list, args.verbose)
    if not hosts:
        print(f"{Colors.RED}Error: No valid hosts provided. Use -l <file> or pipe input via stdin.{Colors.RESET}")
        print("Try --examples for usage examples.")
        sys.exit(1)

    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}Takeover Triage - Processing {len(hosts)} host(s){Colors.RESET}")
    if args.workers > 1:
        print(f"{Colors.DIM}Concurrency: {args.workers} workers{Colors.RESET}")
    if args.doh_fallback:
        print(f"{Colors.DIM}DNS-over-HTTPS fallback: Enabled{Colors.RESET}")
    if REQUEST_DELAY > 0:
        print(f"{Colors.DIM}Politeness delay: ~{REQUEST_DELAY}s (jittered){Colors.RESET}")
    if args.xyz:
        print(f"{Colors.MAGENTA}XYZ Repo Verification: Enabled{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}\n")

    # Process
    start_scan = time.time()
    results = process_hosts(hosts, args.doh_fallback, args.verbose, args.workers)
    scan_time = time.time() - start_scan

    # Sort: CONFIRM_MANUALLY first, then NEEDS_CARE, then DEAD
    verdict_order = {"CONFIRM_MANUALLY": 0, "NEEDS_CARE": 1, "DEAD": 2}
    results.sort(key=lambda x: verdict_order.get(x["verdict"], 99))

    # Display
    buckets = {"CONFIRM_MANUALLY": [], "NEEDS_CARE": [], "DEAD": []}
    for res in results:
        buckets.setdefault(res["verdict"], []).append(res)
        print_result_line(res, args.verbose)

    print_summary(buckets, results, scan_time)

    # Cross-reference with xyz repo
    if args.xyz and xyz_data:
        compare_with_xyz_repo(results, xyz_data)

        xyz_vulnerable_set, xyz_not_vulnerable_set, xyz_unknown_set = set(), set(), set()
        for s in xyz_data.get("vulnerable", []):
            if s.get("service"):
                xyz_vulnerable_set.add(s["service"].lower())
        for s in xyz_data.get("not_vulnerable", []):
            if s.get("service"):
                xyz_not_vulnerable_set.add(s["service"].lower())
        for s in xyz_data.get("unknown", []):
            if s.get("service"):
                xyz_unknown_set.add(s["service"].lower())

        for result in results:
            svc = xyz_family(result.get("service"))
            result["xyz_cross_reference"] = {
                "source": xyz_data.get("source"),
                "fetch_time": xyz_data.get("fetch_time"),
                "matched": (svc in (xyz_vulnerable_set | xyz_not_vulnerable_set | xyz_unknown_set))
                if svc else False,
                "listed_vulnerable": (svc in xyz_vulnerable_set) if svc else False
            }

    print(f"\n{Colors.DIM}Only CONFIRM_MANUALLY / NEEDS_CARE need the manual{Colors.RESET}")
    print(f"{Colors.DIM}claimability check (Gate 3). Never claim without authorization.{Colors.RESET}")

    # Save JSON
    if args.json:
        output_data = {
            "scan_info": {
                "tool": "takeover_triage v2.1",
                "scan_time": datetime.now().isoformat(),
                "total_hosts": len(hosts),
                "total_findings": len(results),
                "scan_duration": f"{scan_time:.2f}s",
                "xyz_verified": args.xyz,
            },
            "results": results,
        }
        with open(args.json, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\n{Colors.GREEN}Full results saved to: {args.json}{Colors.RESET}")


if __name__ == "__main__":
    main()
