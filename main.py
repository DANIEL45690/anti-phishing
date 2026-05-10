i
#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import shutil
import json
import re
import urllib.request
import urllib.parse
import urllib.error
import ssl
import socket
from datetime import datetime
from typing import Dict, List, Tuple

def install_requirements():
    required = ['requests', 'colorama', 'tldextract', 'python-whois']
    missing = []
    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)

    if missing:
        print("[!] Installing missing packages: " + ', '.join(missing))
        for package in missing:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        print("[✓] All packages installed successfully!")
        return True
    return False

if install_requirements():
    for _ in range(2):
        print()
    time.sleep(1)

import requests
from colorama import init, Fore, Back, Style, AnsiToWin32
import tldextract
import whois

init(autoreset=True)

def ascii_header():
    gradient = [
        (0, 255, 0), (50, 205, 50), (100, 155, 50),
        (150, 105, 50), (200, 55, 50), (255, 0, 0)
    ]
    header = r"""
          ___       ___    __               __      __   __  ___
 /\  |\ |  |  | __ |__  | /__` |__| | |\ | / _`    |__) /  \  |
/~~\ | \|  |  |    |    | .__/ |  | | | \| \__>    |__) \__/  |
    """
    lines = header.split('\n')
    for i, line in enumerate(lines):
        if line.strip():
            color = gradient[i % len(gradient)]
            print(f"\033[38;2;{color[0]};{color[1]};{color[2]}m{line}\033[0m")
    print()

def loading_animation(text, duration=1.5):
    chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f'\r{Fore.CYAN}[{chars[i % len(chars)]}] {text}...{Style.RESET_ALL}')
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write(f'\r{Fore.GREEN}[✓] {text} done!   \n{Style.RESET_ALL}')

def progress_bar(percent, width=40):
    filled = int(width * percent // 100)
    empty = width - filled
    bar = '█' * filled + '░' * empty
    gradient_intensity = int(100 - percent)
    r = min(255, gradient_intensity * 2)
    g = min(255, 255 - gradient_intensity * 2)
    color = f"\033[38;2;{r};{g};0m"
    sys.stdout.write(f'\r{color}[{bar}] {percent:.1f}%{Style.RESET_ALL}')
    sys.stdout.flush()

def check_url_safety(url: str) -> Dict:
    results = {
        'url': url,
        'is_phishing': False,
        'risk_score': 0,
        'reasons': [],
        'whois_info': {}
    }

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc

    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}"

    suspicious_keywords = [
        'secure', 'login', 'signin', 'verify', 'account', 'update',
        'confirm', 'banking', 'paypal', 'appleid', 'microsoft',
        'password', 'credential', 'authenticate', 'validation'
    ]

    domain_lower = domain.lower()
    keyword_matches = sum(1 for kw in suspicious_keywords if kw in domain_lower)
    if keyword_matches > 0:
        results['risk_score'] += keyword_matches * 15
        results['reasons'].append(f"Contains {keyword_matches} suspicious keyword(s)")

    special_chars = sum(1 for c in domain if c in '-_~')
    if special_chars > 3:
        results['risk_score'] += 20
        results['reasons'].append("Unusual number of special characters in domain")

    if len(domain.split('.')) > 4:
        results['risk_score'] += 15
        results['reasons'].append("Multiple subdomains detected")

    try:
        loading_animation("Checking WHOIS data", 0.5)
        w = whois.whois(registered_domain)
        results['whois_info'] = {
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'name_servers': w.name_servers
        }

        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date

            age_days = (datetime.now() - creation_date).days

            if age_days < 30:
                results['risk_score'] += 35
                results['reasons'].append(f"Domain is very young ({age_days} days old)")
            elif age_days < 90:
                results['risk_score'] += 15
                results['reasons'].append(f"Domain is relatively new ({age_days} days old)")

        if w.registrar and any(
            term in str(w.registrar).lower()
            for term in ['privacy', 'private', 'whoisguard', 'protection']
        ):
            results['risk_score'] += 20
            results['reasons'].append("Domain uses WHOIS privacy protection")

    except Exception as e:
        results['risk_score'] += 25
        results['reasons'].append("Unable to fetch WHOIS data")

    try:
        loading_animation("Analyzing SSL certificate", 0.5)
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

            import ipaddress
            try:
                ipaddress.ip_address(domain)
                results['risk_score'] += 30
                results['reasons'].append("IP address used instead of domain name")
            except:
                pass

    except:
        results['risk_score'] += 25
        results['reasons'].append("Invalid or missing SSL certificate")

    try:
        loading_animation("Checking URL reputation", 0.5)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, timeout=8, verify=False, allow_redirects=True)

        if len(response.history) > 2:
            results['risk_score'] += 15
            results['reasons'].append(f"Multiple redirects ({len(response.history)})")

        final_url = response.url
        if final_url != url:
            final_parsed = urllib.parse.urlparse(final_url)
            if final_parsed.netloc != domain:
                results['risk_score'] += 10
                results['reasons'].append("Redirects to different domain")

        content_lower = response.text.lower()
        login_forms = content_lower.count('<form') if 'password' in content_lower else 0
        if 'password' in content_lower and login_forms > 0:
            results['risk_score'] += 10
            results['reasons'].append("Contains login form requesting password")

        sensitive_words = ['ssn', 'credit card', 'cvv', 'security number', 'routing number']
        for word in sensitive_words:
            if word in content_lower:
                results['risk_score'] += 20
                results['reasons'].append(f"Requests sensitive data: {word}")
                break

    except requests.exceptions.Timeout:
        results['risk_score'] += 30
        results['reasons'].append("Site connection timeout detected")
    except requests.exceptions.ConnectionError:
        results['risk_score'] += 40
        results['reasons'].append("Unable to establish connection")
    except Exception as e:
        results['risk_score'] += 20
        results['reasons'].append("General connection error")

    results['risk_score'] = min(results['risk_score'], 100)
    results['is_phishing'] = results['risk_score'] >= 60

    return results

def print_results(results: Dict):
    print("\n" + "="*60)
    print(f"{Fore.CYAN}📊 ANALYSIS REPORT{Style.RESET_ALL}")
    print("="*60)

    score = results['risk_score']
    if score >= 75:
        color = Fore.RED
        emoji = "🔴"
        status = "CRITICAL"
    elif score >= 60:
        color = Fore.YELLOW
        emoji = "🟡"
        status = "SUSPICIOUS"
    elif score >= 30:
        color = Fore.BLUE
        emoji = "🔵"
        status = "CAUTION"
    else:
        color = Fore.GREEN
        emoji = "🟢"
        status = "SAFE"

    print(f"\n{emoji} {color}Risk Score: {score:.0f}/100")
    print(f"   Status: {color}{status}{Style.RESET_ALL}")

    print(f"\n{Fore.WHITE}📌 URL: {results['url']}{Style.RESET_ALL}")

    if results['reasons']:
        print(f"\n{Fore.YELLOW}⚠️  Warnings:{Style.RESET_ALL}")
        for reason in results['reasons'][:5]:
            print(f"   • {reason}")

    if results['whois_info'] and results['whois_info'].get('registrar'):
        print(f"\n{Fore.CYAN}📋 WHOIS Info:{Style.RESET_ALL}")
        if results['whois_info'].get('registrar'):
            print(f"   Registrar: {results['whois_info']['registrar'][:50]}")
        if results['whois_info'].get('creation_date'):
            print(f"   Created: {results['whois_info']['creation_date']}")
        if results['whois_info'].get('expiration_date'):
            print(f"   Expires: {results['whois_info']['expiration_date']}")

    print(f"\n{Fore.CYAN}💡 Recommendation:{Style.RESET_ALL}")
    if score >= 70:
        print(f"   {Fore.RED}DO NOT PROCEED - This site is likely a phishing attempt{Style.RESET_ALL}")
    elif score >= 50:
        print(f"   {Fore.YELLOW}Exercise caution - Do not enter sensitive information{Style.RESET_ALL}")
    elif score >= 25:
        print(f"   {Fore.BLUE}Use with care - Verify site authenticity before sharing data{Style.RESET_ALL}")
    else:
        print(f"   {Fore.GREEN}Site appears safe - Always maintain general awareness{Style.RESET_ALL}")

    print("\n" + "="*60 + "\n")

def interactive_mode():
    os.system('cls' if os.name == 'nt' else 'clear')
    ascii_header()
    print(f"{Fore.CYAN}┌─────────────────────────────────────────────────────────┐")
    print(f"│           🔒 PHISHING DETECTION SYSTEM v1.0 🔒        │")
    print(f"└─────────────────────────────────────────────────────────┘{Style.RESET_ALL}\n")

    while True:
        print(f"{Fore.WHITE}┌─[{Fore.GREEN}phish-scan{Fore.WHITE}]───[{Fore.CYAN}~/check{Fore.WHITE}]")
        url = input(f"└──$ {Fore.YELLOW}Enter URL to scan: {Style.RESET_ALL}").strip()

        if not url:
            print(f"{Fore.RED}Please enter a valid URL{Style.RESET_ALL}")
            continue

        if url.lower() in ['exit', 'quit', 'q']:
            print(f"\n{Fore.GREEN}Goodbye! Stay safe online! 👋{Style.RESET_ALL}\n")
            break

        print(f"\n{Fore.CYAN}🔍 Analyzing {url}...{Style.RESET_ALL}\n")

        for percent in range(0, 101, 5):
            progress_bar(percent)
            time.sleep(0.02)
        print()

        results = check_url_safety(url)
        print_results(results)

        print(f"{Fore.CYAN}Press Enter to continue or type 'exit' to quit...{Style.RESET_ALL}")
        choice = input().strip().lower()
        if choice == 'exit':
            print(f"\n{Fore.GREEN}Stay vigilant! Goodbye! 🔐{Style.RESET_ALL}\n")
            break

        os.system('cls' if os.name == 'nt' else 'clear')
        ascii_header()

def batch_mode():
    print(f"\n{Fore.CYAN}📁 Batch Scan Mode{Style.RESET_ALL}")
    file_path = input(f"{Fore.YELLOW}Enter file path with URLs (one per line): {Style.RESET_ALL}")

    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"\n{Fore.GREEN}✓ Loaded {len(urls)} URLs{Style.RESET_ALL}\n")
        time.sleep(1)

        report = []
        for i, url in enumerate(urls, 1):
            print(f"{Fore.CYAN}[{i}/{len(urls)}] Scanning: {url}{Style.RESET_ALL}")
            result = check_url_safety(url)
            report.append(result)

            status_icon = "⚠️" if result['is_phishing'] else "✅"
            score_color = Fore.RED if result['risk_score'] >= 60 else Fore.YELLOW if result['risk_score'] >= 30 else Fore.GREEN
            print(f"   {status_icon} Score: {score_color}{result['risk_score']:.0f}/100{Style.RESET_ALL}\n")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"phishing_report_{timestamp}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"{Fore.GREEN}✓ Report saved to: {report_file}{Style.RESET_ALL}")

        suspicious = [r for r in report if r['risk_score'] >= 60]
        if suspicious:
            print(f"\n{Fore.RED}⚠️ Found {len(suspicious)} suspicious sites:{Style.RESET_ALL}")
            for site in suspicious:
                print(f"   • {site['url']} - Score: {site['risk_score']:.0f}")

    except FileNotFoundError:
        print(f"{Fore.RED}✗ File not found: {file_path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")

    input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

def main():
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            ascii_header()

            print(f"{Fore.CYAN}┌─────────────────────────────────────────────────────────┐")
            print(f"│  [1] Single URL Scan                                    │")
            print(f"│  [2] Batch Scan (from file)                             │")
            print(f"│  [3] About & Help                                       │")
            print(f"│  [4] Exit                                               │")
            print(f"└─────────────────────────────────────────────────────────┘{Style.RESET_ALL}\n")

            choice = input(f"{Fore.YELLOW}Select option [1-4]: {Style.RESET_ALL}").strip()

            if choice == '1':
                interactive_mode()
            elif choice == '2':
                batch_mode()
            elif choice == '3':
                os.system('cls' if os.name == 'nt' else 'clear')
                ascii_header()
                print(f"{Fore.CYAN}┌─────────────────────────────────────────────────────────┐")
                print(f"│                    ABOUT PHISH-SCAN                         │")
                print(f"├─────────────────────────────────────────────────────────┤")
                print(f"│  This tool analyzes websites for phishing indicators:   │")
                print(f"│  • Domain age & WHOIS data                              │")
                print(f"│  • Suspicious keywords in URL                           │")
                print(f"│  • SSL certificate validity                             │")
                print(f"│  • HTTP redirect patterns                               │")
                print(f"│  • Content analysis for login forms                     │")
                print(f"│                                                         │")
                print(f"│  Risk Score:                                            │")
                print(f"│    🟢 0-30   - Safe                                     │")
                print(f"│    🔵 31-50  - Caution                                  │")
                print(f"│    🟡 51-75  - Suspicious                               │")
                print(f"│    🔴 76-100 - Critical                                 │")
                print(f"│                                                         │")
                print(f"│  Warning: Not 100% accurate. Use common sense online!   │")
                print(f"└─────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
                input(f"\n{Fore.CYAN}Press Enter to return...{Style.RESET_ALL}")
            elif choice == '4':
                print(f"\n{Fore.GREEN}🔐 Stay safe online! Exiting...{Style.RESET_ALL}\n")
                sys.exit(0)
            else:
                print(f"{Fore.RED}Invalid option!{Style.RESET_ALL}")
                time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Interrupted by user. Goodbye!{Style.RESET_ALL}\n")
        sys.exit(0)

if __name__ == "__main__":
    if not install_requirements:
        print(f"{Fore.GREEN}✓ All dependencies ready{Style.RESET_ALL}")
    main()
