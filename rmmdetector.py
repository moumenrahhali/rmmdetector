#!/usr/bin/env python3
"""
Enhanced RMM/PSA Detector
Detects RMM, PSA, and Helpdesk software from a list of URLs.

Detection Methods:
- DNS CNAME resolution
- URL/domain pattern matching
- HTTP redirect analysis
- HTTP header inspection
- Cookie name fingerprinting
- Favicon hash matching
- HTML source signatures
- JavaScript/CSS asset path detection
- Meta tag inspection
- Form field fingerprinting
- Portal link discovery
"""

import requests
import dns.resolver  # type: ignore[import-untyped]
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re
import csv
import json
import argparse
import concurrent.futures
import hashlib
import base64
import time
import urllib3

# Suppress SSL warnings for fallback requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Optional: mmh3 for Shodan-compatible favicon hashing
try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

# --- Configuration ---
TIMEOUT = 10
MAX_THREADS = 10
MAX_RETRIES = 2
RETRY_BACKOFF = 1.5  # seconds; multiplied by attempt number
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

# Confidence score labels (1=Low, 2=Medium, 3=High)
CONFIDENCE_LABELS = {3: 'High', 2: 'Medium', 1: 'Low', 0: 'Unknown'}

# --- Expanded Signatures ---

# HTML/Source Code Patterns
HTML_SIGNATURES = {
    # PSA Platforms
    'HaloPSA': [r'NHServer', r'NetHelpDesk', r'halopsa\.com', r'/api/v[0-9]+/', r'haloitsm', r'hloapi'],
    'Syncro': [r'kabuto', r'repairtech', r'syncromsp\.com', r'/my_profile/user_login', r'syncro-msp'],
    'ConnectWise Manage': [r'connectwise', r'cwManage', r'cw-portal', r'ConnectWise\.aspx'],
    'Autotask': [r'autotask', r'datto\.com/autotask', r'atws_', r'AutotaskExtend'],
    'Kaseya BMS': [r'kaseya.*bms', r'bms\.kaseya', r'vorex'],
    'Accelo': [r'accelo\.com', r'accelo-', r'affinitydb'],
    'Tigerpaw': [r'tigerpaw', r'tigerpawsoftware'],

    # RMM Platforms
    'NinjaOne': [r'ninjarmm', r'ninjaone', r'app\.ninjarmm\.com', r'ninja-rmm'],
    'Datto RMM': [r'datto-rmm', r'centrastage', r'dattormm', r'datto\.net/rmm'],
    'Kaseya VSA': [r'kaseya.*vsa', r'/vsaWS/', r'kaseyavsapremium', r'LiveConnect'],
    'Atera': [r'atera\.com', r'ateracdn', r'atera-agent', r'atera\.network'],
    'Pulseway': [r'pulseway', r'mmsoft\.com', r'pulseway-api'],
    'Action1': [r'action1\.com', r'action1-rmm'],
    'Level': [r'level\.io', r'uselevel\.io'],
    'N-able': [r'n-able', r'solarwindsmsp', r'n-central', r'nable\.com'],
    'SuperOps': [r'superops\.ai', r'superops\.com'],
    'Addigy': [r'addigy\.com', r'addigy-'],

    # Remote Access
    'ConnectWise Control': [r'ScreenConnect', r'control\.connectwise', r'screenconnect\.com', r'hostedrmm\.com'],
    'TeamViewer': [r'teamviewer', r'teamviewerapi', r'tvnetwork'],
    'Splashtop': [r'splashtop', r'splashtopremote', r'splashtopstreamer'],
    'GoTo Resolve': [r'gotoassist', r'gotoresolve', r'logmein.*rescue'],
    'AnyDesk': [r'anydesk', r'anydesk\.com'],

    # Helpdesk/ITSM
    'Zendesk': [r'zendesk', r'zopim', r'zdassets', r'zdusercontent', r'zendesk_app'],
    'Freshdesk': [r'freshdesk', r'freshworks', r'freshservice', r'freshcaller', r'freshchat'],
    'ServiceNow': [r'servicenow', r'service-now', r'snc\.core', r'glide', r'sn_frame'],
    'Jira Service Management': [r'jira.*service', r'atlassian.*servicedesk', r'jsm\.atlassian'],
    'ManageEngine': [r'manageengine', r'zoho.*servicedesk', r'sdpondemand', r'servicedesk.*plus'],
    'Spiceworks': [r'spiceworks', r'spiceworks-cdn'],
}

# Domain/URL Patterns
DOMAIN_SIGNATURES = {
    # PSA
    'HaloPSA': ['halopsa.com', 'haloitsm.com', 'nethelpdesk.com', 'haloservicedesk.com'],
    'Syncro': ['syncromsp.com', 'kabutoservices.com', 'repairtechsolutions.com'],
    'ConnectWise Manage': ['connectwise.com', 'myconnectwise.net', 'connectwisepsa.com'],
    'Autotask': ['autotask.net', 'autotask.com'],
    'Kaseya BMS': ['bms.kaseya.com', 'vorex.com'],
    'Accelo': ['accelo.com'],
    'Tigerpaw': ['tigerpawsoftware.com'],

    # RMM
    'NinjaOne': ['ninjarmm.com', 'ninjaone.com', 'ninja.dev'],
    'Datto RMM': ['datto.com', 'dattobackup.com', 'centrastage.net', 'datto.net'],
    'Kaseya VSA': ['kaseya.com', 'kaseyaone.com'],
    'Atera': ['atera.com', 'ateranetworks.com'],
    'Pulseway': ['pulseway.com', 'mmsoft.com'],
    'Action1': ['action1.com'],
    'Level': ['level.io', 'uselevel.io'],
    'N-able': ['n-able.com', 'solarwindsmsp.com', 'n-central.com'],
    'SuperOps': ['superops.ai', 'superops.com'],
    'Addigy': ['addigy.com'],

    # Remote Access
    'ConnectWise Control': ['screenconnect.com', 'hostedrmm.com', 'control.connectwise.com'],
    'TeamViewer': ['teamviewer.com'],
    'Splashtop': ['splashtop.com'],
    'GoTo Resolve': ['gotoresolve.com', 'gotoassist.com', 'logmeinrescue.com'],
    'AnyDesk': ['anydesk.com'],

    # Helpdesk
    'Zendesk': ['zendesk.com', 'zopim.com', 'zdassets.com', 'zdusercontent.com'],
    'Freshdesk': ['freshdesk.com', 'freshservice.com', 'freshworks.com'],
    'ServiceNow': ['servicenow.com', 'service-now.com'],
    'Jira Service Management': ['atlassian.net', 'jira.com'],
    'ManageEngine': ['manageengine.com', 'sdpondemand.com', 'zoho.com/servicedesk'],
    'Spiceworks': ['spiceworks.com', 'on.spiceworks.com'],
}

# HTTP Header Patterns
HEADER_SIGNATURES = {
    'Zendesk': ['x-zendesk', 'zendesk'],
    'Freshdesk': ['x-freshdesk', 'x-fd-', 'freshworks'],
    'ServiceNow': ['x-sn-', 'glide', 'servicenow'],
    'ConnectWise Manage': ['x-cw-', 'connectwise'],
    'ConnectWise Control': ['screenconnect', 'x-sc-'],
    'Autotask': ['x-autotask', 'autotask'],
    'Datto RMM': ['x-datto', 'datto'],
    'HaloPSA': ['x-halo', 'haloitsm'],
    'Kaseya VSA': ['x-kaseya', 'kaseya'],
    'NinjaOne': ['x-ninja', 'ninjarmm'],
}

# Cookie Name Patterns
COOKIE_SIGNATURES = {
    'Zendesk': ['_zendesk', '_zd', 'zdsession'],
    'Freshdesk': ['_freshdesk', '_fd_', 'freshworks'],
    'ServiceNow': ['glide_user', 'glide_session', 'BIGipServer'],
    'ConnectWise Manage': ['cwsso', 'cw_session', 'connectwise'],
    'ConnectWise Control': ['sc_session', 'screenconnect'],
    'Autotask': ['autotask', 'atws_session'],
    'HaloPSA': ['halo_session', 'nhserver', 'halopsa'],
    'Syncro': ['syncro', 'kabuto', '_repairtech'],
    'Kaseya VSA': ['kaseya', 'vsa_session'],
    'NinjaOne': ['ninja_', 'ninjarmm'],
    'Datto RMM': ['datto_', 'centrastage'],
    'Atera': ['atera_', 'atera-session'],
}

# JavaScript/CSS Asset Path Patterns
ASSET_SIGNATURES = {
    'ConnectWise Manage': ['/cw-theme/', '/connectwise-', 'cwmanage', '/cw/'],
    'ConnectWise Control': ['/screenconnect/', '/sc-', '/control/'],
    'Datto RMM': ['/autotask/', '/datto-', '/centrastage/'],
    'NinjaOne': ['/ninja/', 'ninjarmm', '/ninjaone/'],
    'Kaseya VSA': ['/kaseya/', '/vsa/', '/kaseyaone/'],
    'Atera': ['/atera/', 'ateracdn', '/atera-assets/'],
    'Freshdesk': ['/freshservice/', '/freshworks/', '/freshdesk/'],
    'Zendesk': ['/zendesk/', '/embeddable/', '/zdassets/'],
    'ServiceNow': ['/styles/sn_', '/scripts/sn_', '/sn_'],
    'HaloPSA': ['/haloapi/', '/halocdn/', '/halopsa/'],
    'Syncro': ['/syncro/', '/kabuto/', '/repairtech/'],
    'Pulseway': ['/pulseway/', '/mmsoft/'],
    'SuperOps': ['/superops/'],
}

# Form Field/ID Patterns
FORM_SIGNATURES = {
    'Zendesk': ['user[email]', 'zendesk-form', 'zd_ticket'],
    'Freshdesk': ['freshdesk', 'helpdesk_ticket', 'fd_form'],
    'ServiceNow': ['sysparm_', 'glide_', 'sn_form'],
    'ConnectWise Manage': ['cwsso', 'connectwiselogin', 'cw_form'],
    'Autotask': ['autotask', 'atws_', 'at_login'],
    'HaloPSA': ['halo_', 'nhserver', 'halopsa'],
    'Syncro': ['syncro_', 'kabuto', 'repairtech'],
}

# Favicon Hashes (MMH3 - Shodan compatible)
# These need to be populated with actual hashes from research
FAVICON_HASHES = {
    # Format: hash_value: 'Platform Name'
    # These are examples - actual hashes need verification
    116323821: 'ConnectWise Manage',
    -1293291441: 'Zendesk',
    -1840324437: 'Freshdesk',
    # Add more hashes as discovered
}

PORTAL_KEYWORDS = ['support', 'portal', 'login', 'help', 'client', 'ticket',
                   'service', 'helpdesk', 'desk', 'request', 'contact', 'submit']


def requests_get_with_retry(url, *, verify=True, allow_redirects=True, max_retries=None):
    """GET request with exponential-backoff retry on transient errors.

    max_retries defaults to the module-level MAX_RETRIES when not specified.
    """
    retries = MAX_RETRIES if max_retries is None else max_retries
    headers = {'User-Agent': USER_AGENT}
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return requests.get(
                url,
                headers=headers,
                timeout=TIMEOUT,
                verify=verify,
                allow_redirects=allow_redirects,
            )
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(RETRY_BACKOFF * (attempt + 1))
        except requests.exceptions.SSLError:
            raise  # Let callers handle SSL errors explicitly
    raise last_exc


def get_cname(hostname):
    """Resolves CNAME to check for vendor domains."""
    try:
        answers = dns.resolver.resolve(hostname, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except Exception:
        return None


def get_txt_records(domain):
    """Check TXT records for vendor verification strings."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def check_text_signatures(text):
    """Scans text for regex signatures."""
    for vendor, patterns in HTML_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return vendor, f"Source signature: '{pattern}'"
    return None, None


def check_domain_signatures(domain):
    """Checks if domain matches vendor list."""
    domain_lower = domain.lower()
    for vendor, domains in DOMAIN_SIGNATURES.items():
        for d in domains:
            if d in domain_lower:
                return vendor, f"Domain match: {d}"
    return None, None


def check_headers(response):
    """Inspect HTTP headers for vendor signatures."""
    for vendor, patterns in HEADER_SIGNATURES.items():
        for header, value in response.headers.items():
            header_lower = header.lower()
            value_lower = str(value).lower()
            for pattern in patterns:
                if pattern in header_lower or pattern in value_lower:
                    return vendor, f"Header: {header}={value[:50]}"
    return None, None


def check_cookies(response):
    """Check cookie names for vendor signatures."""
    for vendor, patterns in COOKIE_SIGNATURES.items():
        for cookie in response.cookies:
            cookie_lower = cookie.name.lower()
            for pattern in patterns:
                if pattern in cookie_lower:
                    return vendor, f"Cookie: {cookie.name}"
    return None, None


def check_asset_paths(soup):
    """Check JavaScript and CSS paths for vendor signatures."""
    scripts = [s.get('src', '') for s in soup.find_all('script', src=True)]
    styles = [l.get('href', '') for l in soup.find_all('link', rel='stylesheet')]
    all_assets = scripts + styles

    for vendor, patterns in ASSET_SIGNATURES.items():
        for asset in all_assets:
            asset_lower = asset.lower()
            for pattern in patterns:
                if pattern.lower() in asset_lower:
                    # Truncate long paths
                    display_asset = asset if len(asset) < 60 else asset[:57] + '...'
                    return vendor, f"Asset: {display_asset}"
    return None, None


def check_meta_tags(soup):
    """Check meta tags for generator/vendor info."""
    vendor_keywords = {
        'zendesk': 'Zendesk',
        'freshdesk': 'Freshdesk',
        'freshservice': 'Freshdesk',
        'servicenow': 'ServiceNow',
        'connectwise': 'ConnectWise Manage',
        'autotask': 'Autotask',
        'halopsa': 'HaloPSA',
        'syncro': 'Syncro',
        'ninja': 'NinjaOne',
        'datto': 'Datto RMM',
        'kaseya': 'Kaseya VSA',
        'atera': 'Atera',
    }

    for meta in soup.find_all('meta'):
        name = meta.get('name', '').lower()
        content = meta.get('content', '').lower()

        # Check generator tag
        if name == 'generator':
            for key, vendor in vendor_keywords.items():
                if key in content:
                    return vendor, f"Generator: {content[:50]}"

        # Check application-name
        if name == 'application-name':
            for key, vendor in vendor_keywords.items():
                if key in content:
                    return vendor, f"App name: {content[:50]}"

    return None, None


def check_form_fields(soup):
    """Check form fields and IDs for vendor signatures."""
    forms = soup.find_all('form')
    for form in forms:
        form_str = str(form).lower()
        for vendor, patterns in FORM_SIGNATURES.items():
            for pattern in patterns:
                if pattern in form_str:
                    return vendor, f"Form signature: {pattern}"
    return None, None


def check_favicon_hash(url):
    """Calculate favicon hash and match against known platforms."""
    if not HAS_MMH3:
        return None, None

    try:
        parsed = urlparse(url)
        favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        response = requests.get(favicon_url, headers={'User-Agent': USER_AGENT}, timeout=5)

        if response.status_code == 200 and len(response.content) > 0:
            favicon_b64 = base64.encodebytes(response.content)
            favicon_hash = mmh3.hash(favicon_b64)

            if favicon_hash in FAVICON_HASHES:
                return FAVICON_HASHES[favicon_hash], f"Favicon hash: {favicon_hash}"
    except Exception:
        pass

    return None, None


def check_txt_records(domain):
    """Check DNS TXT records for vendor verification."""
    txt_records = get_txt_records(domain)

    vendor_keywords = {
        'zendesk': 'Zendesk',
        'freshdesk': 'Freshdesk',
        'servicenow': 'ServiceNow',
        'atlassian': 'Jira Service Management',
    }

    for txt in txt_records:
        txt_lower = txt.lower()
        for key, vendor in vendor_keywords.items():
            if key in txt_lower:
                return vendor, f"TXT record: {txt[:50]}"

    return None, None


def analyze_target_url(url):
    """Deep analysis of a specific URL using multiple detection methods.

    Returns (vendor, method, evidence, confidence) where confidence is an
    integer 1–3:
      1 = single low-confidence indicator (HTML pattern, TXT record)
      2 = moderate evidence (header, cookie, asset path, redirect)
      3 = high-confidence (CNAME, URL pattern, favicon hash match)
    """
    detections = []  # Collect all detections for confidence

    try:
        parsed = urlparse(url)
        hostname = parsed.netloc

        # 1. Check CNAME
        cname = get_cname(hostname)
        if cname:
            vendor, reason = check_domain_signatures(cname)
            if vendor:
                return vendor, "DNS (CNAME)", f"{hostname} -> {reason}", 3

        # 2. Check URL string
        vendor, reason = check_domain_signatures(hostname)
        if vendor:
            return vendor, "URL Pattern", reason, 3

        # 3. Check TXT records (for root domain)
        root_domain = '.'.join(hostname.split('.')[-2:])
        vendor, reason = check_txt_records(root_domain)
        if vendor:
            detections.append((vendor, "DNS (TXT)", reason, 2))

        # 4. Check Favicon Hash
        vendor, reason = check_favicon_hash(url)
        if vendor:
            return vendor, "Favicon Hash", reason, 3

        # 5. Fetch content (with retry)
        response = requests_get_with_retry(url, allow_redirects=True)

        # 6. Check Redirects
        final_host = urlparse(response.url).netloc
        vendor, reason = check_domain_signatures(final_host)
        if vendor:
            return vendor, "HTTP Redirect", f"Redirected to {reason}", 3

        # 7. Check HTTP Headers
        vendor, reason = check_headers(response)
        if vendor:
            return vendor, "HTTP Headers", reason, 2

        # 8. Check Cookies
        vendor, reason = check_cookies(response)
        if vendor:
            return vendor, "Cookies", reason, 2

        # 9. Parse HTML for deeper inspection
        soup = BeautifulSoup(response.text, 'html.parser')

        # 10. Check Asset Paths (JS/CSS)
        vendor, reason = check_asset_paths(soup)
        if vendor:
            return vendor, "Asset Paths", reason, 2

        # 11. Check Meta Tags
        vendor, reason = check_meta_tags(soup)
        if vendor:
            return vendor, "Meta Tags", reason, 2

        # 12. Check Form Fields
        vendor, reason = check_form_fields(soup)
        if vendor:
            return vendor, "Form Analysis", reason, 2

        # 13. Check HTML Source (regex patterns)
        vendor, reason = check_text_signatures(response.text)
        if vendor:
            return vendor, "HTML Source", reason, 1

        # Return any earlier detections (like TXT records)
        if detections:
            return detections[0]

    except requests.exceptions.SSLError:
        # Try without SSL verification as fallback
        try:
            response = requests_get_with_retry(url, verify=False, allow_redirects=True)
            vendor, reason = check_text_signatures(response.text)
            if vendor:
                return vendor, "HTML Source (SSL bypass)", reason, 1
        except Exception:
            pass
    except Exception:
        pass

    return None, None, None, 0


def process_company(url):
    """Main logic: Scans homepage and hunts for portal links."""
    # Normalize URL
    original_url = url
    if not url.startswith('http'):
        url = 'https://' + url.strip()

    result_row = {
        'Input URL': original_url,
        'Detected Software': 'Not Detected',
        'Category': 'N/A',
        'Method': 'N/A',
        'Confidence': 0,
        'Evidence': 'No clear indicators found'
    }

    # Categorize detected software
    def get_category(vendor):
        psa = ['HaloPSA', 'Syncro', 'ConnectWise Manage', 'Autotask', 'Kaseya BMS', 'Accelo', 'Tigerpaw']
        rmm = ['NinjaOne', 'Datto RMM', 'Kaseya VSA', 'Atera', 'Pulseway', 'Action1', 'Level', 'N-able', 'SuperOps', 'Addigy']
        remote = ['ConnectWise Control', 'TeamViewer', 'Splashtop', 'GoTo Resolve', 'AnyDesk']
        helpdesk = ['Zendesk', 'Freshdesk', 'ServiceNow', 'Jira Service Management', 'ManageEngine', 'Spiceworks']

        if vendor in psa:
            return 'PSA'
        elif vendor in rmm:
            return 'RMM'
        elif vendor in remote:
            return 'Remote Access'
        elif vendor in helpdesk:
            return 'Helpdesk/ITSM'
        return 'Unknown'

    try:
        # Step 1: Direct Analysis
        vendor, method, evidence, confidence = analyze_target_url(url)
        if vendor:
            result_row.update({
                'Detected Software': vendor,
                'Category': get_category(vendor),
                'Method': method,
                'Confidence': confidence,
                'Evidence': evidence
            })
            return result_row

        # Step 2: Scrape for Portal Links
        response = requests_get_with_retry(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        potential_links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            text = a.get_text().lower()

            # Check link text and href for portal keywords
            if any(k in text or k in href.lower() for k in PORTAL_KEYWORDS):
                full_url = urljoin(url, href)

                # Filter out social media and other false positives
                excluded = ['facebook', 'twitter', 'linkedin', 'instagram', 'youtube',
                           'mailto:', 'tel:', 'javascript:', '#']
                if full_url != url and not any(x in full_url.lower() for x in excluded):
                    potential_links.append(full_url)

        # Step 3: Analyze discovered links (limit to first 10 unique)
        for link in list(set(potential_links))[:10]:
            vendor, method, evidence, confidence = analyze_target_url(link)
            if vendor:
                result_row.update({
                    'Detected Software': vendor,
                    'Category': get_category(vendor),
                    'Method': f"Portal Discovery ({method})",
                    'Confidence': confidence,
                    'Evidence': f"Found via '{link}': {evidence}"
                })
                return result_row

    except Exception as e:
        result_row['Evidence'] = f"Error during scan: {str(e)[:100]}"

    return result_row


def main():
    global MAX_RETRIES  # allow --retries CLI flag to override module default

    parser = argparse.ArgumentParser(
        description="Enhanced RMM/PSA/Helpdesk Detector - Detect software platforms from a list of URLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Detected Platforms:
  PSA:          HaloPSA, Syncro, ConnectWise Manage, Autotask, Kaseya BMS, Accelo, Tigerpaw
  RMM:          NinjaOne, Datto RMM, Kaseya VSA, Atera, Pulseway, Action1, Level, N-able, SuperOps, Addigy
  Remote:       ConnectWise Control, TeamViewer, Splashtop, GoTo Resolve, AnyDesk
  Helpdesk:     Zendesk, Freshdesk, ServiceNow, Jira Service Management, ManageEngine, Spiceworks

Detection Methods:
  DNS CNAME/TXT, URL patterns, HTTP headers, cookies, favicon hashing,
  HTML source analysis, JS/CSS paths, meta tags, form fingerprinting

Confidence Scores (1-3):
  3 = High    (CNAME, direct URL match, favicon hash)
  2 = Medium  (HTTP headers/cookies, asset paths, meta tags)
  1 = Low     (HTML source pattern, TXT record)
  0 = Unknown (not detected or error)

Exit Codes:
  0 = No detections
  1 = One or more platforms detected
        """
    )
    parser.add_argument('input_file', help="Path to input file (CSV or TXT)")
    parser.add_argument('output_file', help="Path to output file (CSV or JSON, depending on --format)")
    parser.add_argument('--column', default='URL', help="Name of the URL column in input file (default: 'URL')")
    parser.add_argument('--threads', type=int, default=MAX_THREADS,
                        help=f"Number of concurrent threads (default: {MAX_THREADS})")
    parser.add_argument('--format', choices=['csv', 'json'], default='csv',
                        help="Output format: csv (default) or json")
    parser.add_argument('--retries', type=int, default=MAX_RETRIES,
                        help=f"Max HTTP retries per URL (default: {MAX_RETRIES})")

    args = parser.parse_args()

    # Override module-level retry default from CLI arg
    MAX_RETRIES = args.retries

    print(f"[*] Enhanced RMM/PSA Detector")
    print(f"[*] Reading from {args.input_file}...")

    if HAS_MMH3:
        print("[*] MMH3 available - Favicon hashing enabled")
    else:
        print("[!] MMH3 not installed - Favicon hashing disabled (pip install mmh3)")

    urls_to_scan = []

    # Detect file type and read input
    try:
        with open(args.input_file, 'r', encoding='utf-8-sig') as f:
            first_line = f.readline().strip()
            f.seek(0)  # Reset to beginning

            # Determine file format
            is_csv = ',' in first_line or args.input_file.lower().endswith('.csv')

            if is_csv:
                # CSV format: comma-delimited with header row
                reader = csv.DictReader(f)
                if args.column not in reader.fieldnames:
                    print(f"[!] Error: Column '{args.column}' not found. Available: {reader.fieldnames}")
                    return

                for row in reader:
                    if row[args.column] and row[args.column].strip():
                        urls_to_scan.append(row[args.column].strip())
                print(f"[*] Detected CSV format")
            else:
                # TXT format: one URL per line, first line is header
                lines = f.readlines()
                if not lines:
                    print("[!] Error: Input file is empty.")
                    return

                header = lines[0].strip()
                print(f"[*] Detected TXT format (header: '{header}')")

                for line in lines[1:]:  # Skip header
                    url = line.strip()
                    if url:  # Skip empty lines
                        urls_to_scan.append(url)

    except FileNotFoundError:
        print(f"[!] Error: File {args.input_file} not found.")
        return

    print(f"[*] Loaded {len(urls_to_scan)} URLs. Starting scan with {args.threads} threads...")

    results = []
    completed = 0
    detected_count = 0
    total = len(urls_to_scan)

    # Process with ThreadPool
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(process_company, url): url for url in urls_to_scan}

        for future in concurrent.futures.as_completed(future_to_url):
            data = future.result()
            results.append(data)
            completed += 1

            status = data['Detected Software']
            if status != 'Not Detected':
                detected_count += 1
                confidence_label = CONFIDENCE_LABELS.get(data.get('Confidence', 0), 'Unknown')
                print(f"[{completed}/{total}] + {data['Input URL']} -> {status} "
                      f"({data['Category']}, confidence: {confidence_label})")
            else:
                print(f"[{completed}/{total}] - {data['Input URL']} -> Not Detected")

    # Write Output
    try:
        if args.format == 'json':
            with open(args.output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        else:
            keys = ['Input URL', 'Detected Software', 'Category', 'Method', 'Confidence', 'Evidence']
            with open(args.output_file, 'w', newline='', encoding='utf-8') as f:
                # extrasaction='ignore' drops fields not in keys (e.g. future additions
                # to process_company that are not yet in the CSV schema).
                writer = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(results)

        print(f"\n[*] Scan complete!")
        if total > 0:
            print(f"[*] Detected: {detected_count}/{total} ({100*detected_count/total:.1f}%)")
        print(f"[*] Results saved to {args.output_file} (format: {args.format})")
    except Exception as e:
        print(f"[!] Error writing output file: {e}")
        raise SystemExit(1)

    raise SystemExit(1 if detected_count > 0 else 0)


if __name__ == "__main__":
    main()
