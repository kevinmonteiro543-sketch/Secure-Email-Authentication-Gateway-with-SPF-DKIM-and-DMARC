#!/usr/bin/env python3
"""
Secure Email Authentication Gateway (SPF, DKIM, DMARC)
------------------------------------------------------
A lightweight, production-grade Command-Line Interface (CLI) gateway tool
for email security infrastructure.

Features:
1. DKIM RSA Key Pair Generation & DNS Record Generation (SPF, DKIM, DMARC)
2. Raw Email Header Parsing & Authentication-Results Analysis
3. Multi-factor Alignment Evaluation (Strict vs Relaxed SPF/DKIM alignment for DMARC)
4. Comprehensive Diagnostic Terminal Summary with Security Directives

Author: Kevin Monteiro
Repository: https://github.com/kevinmonteiro543-sketch/Secure-Email-Authentication-Gateway-with-SPF-DKIM-and-DMARC.git
"""

import os
import sys
import re
import argparse
import base64
from email import policy
from email.parser import HeaderParser
from email.utils import parseaddr
from typing import Dict, Any, List, Optional, Tuple

# Cryptography for RSA key generation
try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Terminal Colors & Styling
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        cls.HEADER = ''
        cls.BLUE = ''
        cls.CYAN = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.RED = ''
        cls.BOLD = ''
        cls.DIM = ''
        cls.UNDERLINE = ''
        cls.RESET = ''


def get_organizational_domain(domain: str) -> str:
    """
    Extracts the organizational (registrable) domain from a fully qualified domain name.
    Handles standard ccTLDs (e.g., .co.uk, .com.au, .gov.in) and generic TLDs.
    """
    if not domain:
        return ""
    domain = domain.strip().lower().rstrip('.')
    parts = domain.split('.')
    if len(parts) <= 2:
        return domain

    # Known multi-part public suffixes
    two_part_tlds = {
        'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'net.uk',
        'com.au', 'net.au', 'org.au', 'edu.au',
        'co.in', 'gov.in', 'net.in', 'org.in', 'gen.in',
        'co.jp', 'ne.jp', 'or.jp', 'ac.jp',
        'com.br', 'net.br', 'org.br',
        'co.za', 'org.za',
    }

    if len(parts) >= 3:
        potential_two_part = f"{parts[-2]}.{parts[-1]}"
        if potential_two_part in two_part_tlds:
            return '.'.join(parts[-3:])

    return '.'.join(parts[-2:])


# =====================================================================
# FUNCTION 1: DKIM KEY GENERATION & DNS RECORD GENERATOR
# =====================================================================

def generate_dkim_keys(
    key_size: int = 2048,
    output_dir: str = "keys",
    selector: str = "default"
) -> Tuple[str, str, str]:
    """
    Generates an RSA private/public key pair for DKIM and saves PEM files.
    Returns: (private_pem_str, public_pem_str, public_base64_dkim_string)
    """
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography library is required for RSA key generation.")

    os.makedirs(output_dir, exist_ok=True)

    # Generate 2048-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Serialize private key to PEM format (PKCS#8 or traditional OpenSSL)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Serialize public key to PEM format (SubjectPublicKeyInfo)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Extract base64 public key for DKIM DNS record (strip headers and newlines)
    pub_lines = [
        line.strip() for line in public_pem.splitlines()
        if not line.startswith("-----") and line.strip()
    ]
    dkim_pub_b64 = "".join(pub_lines)

    # Save to disk
    priv_file = os.path.join(output_dir, f"{selector}.private.key")
    pub_file = os.path.join(output_dir, f"{selector}.public.key")

    with open(priv_file, "w", encoding="utf-8") as f:
        f.write(private_pem)

    with open(pub_file, "w", encoding="utf-8") as f:
        f.write(public_pem)

    return private_pem, public_pem, dkim_pub_b64


def generate_dns_records(
    domain: str,
    selector: str = "mail2026",
    key_size: int = 2048,
    output_dir: str = "keys",
    spf_ips: Optional[List[str]] = None,
    spf_includes: Optional[List[str]] = None,
    rua_email: Optional[str] = None,
    ruf_email: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates exact DNS TXT record specifications for SPF, DKIM, and DMARC.
    Includes both monitoring mode (p=none) and strict enforcement mode (p=reject).
    """
    domain = domain.strip().lower()
    rua = rua_email or f"dmarc-reports@{domain}"
    ruf = ruf_email or f"dmarc-forensics@{domain}"

    # 1. Generate DKIM keys
    priv_pem, pub_pem, dkim_pub_b64 = generate_dkim_keys(
        key_size=key_size,
        output_dir=output_dir,
        selector=selector
    )

    # 2. Construct SPF Record
    # Standard components: v=spf1 mx a ... -all
    spf_parts = ["v=spf1", "mx", "a"]
    if spf_ips:
        for ip in spf_ips:
            spf_parts.append(f"ip4:{ip.strip()}")
    if spf_includes:
        for inc in spf_includes:
            spf_parts.append(f"include:{inc.strip()}")
    else:
        spf_parts.append(f"include:_spf.{domain}")

    # Enforcing strict SPF with -all (fail unauthorized)
    spf_record_strict = " ".join(spf_parts) + " -all"
    # Transition softfail with ~all
    spf_record_softfail = " ".join(spf_parts) + " ~all"

    # 3. Construct DKIM Record
    # Hostname: selector._domainkey.domain.com
    dkim_host = f"{selector}._domainkey.{domain}"
    dkim_value = f"v=DKIM1; k=rsa; p={dkim_pub_b64}"

    # Split for DNS providers requiring 255-character chunks (e.g. BIND)
    chunk_size = 250
    chunks = [dkim_value[i:i + chunk_size] for i in range(0, len(dkim_value), chunk_size)]
    dkim_value_chunked = " ".join(f'"{c}"' for c in chunks)

    # 4. Construct DMARC Records
    dmarc_host = f"_dmarc.{domain}"

    # Phase 1: Monitoring Mode (p=none)
    dmarc_monitoring = (
        f"v=DMARC1; p=none; rua=mailto:{rua}; ruf=mailto:{ruf}; "
        f"pct=100; sp=none; aspf=r; adkim=r"
    )

    # Phase 2: Quarantine Mode (p=quarantine)
    dmarc_quarantine = (
        f"v=DMARC1; p=quarantine; pct=100; rua=mailto:{rua}; "
        f"ruf=mailto:{ruf}; sp=quarantine; aspf=r; adkim=r"
    )

    # Phase 3: Enforcement Mode (p=reject, strict alignment)
    dmarc_enforcement = (
        f"v=DMARC1; p=reject; pct=100; rua=mailto:{rua}; "
        f"ruf=mailto:{ruf}; sp=reject; aspf=s; adkim=s"
    )

    return {
        "domain": domain,
        "selector": selector,
        "key_size": key_size,
        "key_dir": output_dir,
        "private_key_file": os.path.join(output_dir, f"{selector}.private.key"),
        "public_key_file": os.path.join(output_dir, f"{selector}.public.key"),
        "spf": {
            "host": f"@{domain} (Root Domain TXT)",
            "record_strict": spf_record_strict,
            "record_softfail": spf_record_softfail,
            "ttl": 3600
        },
        "dkim": {
            "host": dkim_host,
            "record_single": dkim_value,
            "record_chunked": dkim_value_chunked,
            "public_key_base64": dkim_pub_b64,
            "ttl": 3600
        },
        "dmarc": {
            "host": dmarc_host,
            "monitoring_record": dmarc_monitoring,
            "quarantine_record": dmarc_quarantine,
            "enforcement_record": dmarc_enforcement,
            "ttl": 3600
        }
    }


def print_dns_records(config: Dict[str, Any]):
    """Prints generated DNS records in a clean, publication-quality terminal format."""
    c = Colors
    d = config['domain']
    s = config['selector']

    print(f"\n{c.BOLD}{c.CYAN}{'='*80}{c.RESET}")
    print(f"{c.BOLD}{c.HEADER}   SECURE EMAIL AUTHENTICATION GATEWAY — DNS CONFIGURATION SUITE{c.RESET}")
    print(f"{c.BOLD}{c.CYAN}{'='*80}{c.RESET}")
    print(f"{c.BOLD}Domain Target:{c.RESET}  {c.GREEN}{d}{c.RESET}")
    print(f"{c.BOLD}DKIM Selector:{c.RESET}  {c.YELLOW}{s}{c.RESET}")
    print(f"{c.BOLD}RSA Key Size:{c.RESET}   {config['key_size']} bits")
    print(f"{c.BOLD}Private Key:{c.RESET}    {config['private_key_file']}")
    print(f"{c.BOLD}Public Key:{c.RESET}     {config['public_key_file']}")
    print(f"{c.CYAN}{'-'*80}{c.RESET}")

    # 1. SPF
    print(f"\n{c.BOLD}{c.BLUE}1. SPF (Sender Policy Framework) Record [RFC 7208]{c.RESET}")
    print(f"   {c.DIM}Defines authorized mail transfer agents (MTAs) permitted to send email on behalf of {d}.{c.RESET}")
    print(f"   {c.BOLD}Host / Name:{c.RESET}       @ or {d}")
    print(f"   {c.BOLD}Record Type:{c.RESET}       TXT")
    print(f"   {c.BOLD}TTL:{c.RESET}               3600")
    print(f"   {c.BOLD}Recommended (Strict):{c.RESET}")
    print(f"   {c.GREEN}{config['spf']['record_strict']}{c.RESET}")
    print(f"   {c.BOLD}Transition (Softfail):{c.RESET}")
    print(f"   {c.YELLOW}{config['spf']['record_softfail']}{c.RESET}")
    print(f"   {c.DIM}Directive '-all' hard-rejects unauthorized senders; '~all' marks them as softfail for testing.{c.RESET}")

    # 2. DKIM
    print(f"\n{c.BOLD}{c.BLUE}2. DKIM (DomainKeys Identified Mail) Record [RFC 6376]{c.RESET}")
    print(f"   {c.DIM}Provides cryptographic non-repudiation and transit tamper-proofing via public key.{c.RESET}")
    print(f"   {c.BOLD}Host / Name:{c.RESET}       {c.YELLOW}{config['dkim']['host']}{c.RESET}")
    print(f"   {c.BOLD}Record Type:{c.RESET}       TXT")
    print(f"   {c.BOLD}TTL:{c.RESET}               3600")
    print(f"   {c.BOLD}Standard TXT Value (Single Line):{c.RESET}")
    print(f"   {c.GREEN}{config['dkim']['record_single']}{c.RESET}")
    print(f"   {c.BOLD}BIND / RFC 4408 Chunked Format (<=255 char strings):{c.RESET}")
    print(f"   {c.DIM}{config['dkim']['record_chunked']}{c.RESET}")

    # 3. DMARC
    print(f"\n{c.BOLD}{c.BLUE}3. DMARC (Domain-based Message Auth, Reporting & Conformance) [RFC 7489]{c.RESET}")
    print(f"   {c.DIM}Enforces policy decisions based on SPF/DKIM alignment and commands reporting.{c.RESET}")
    print(f"   {c.BOLD}Host / Name:{c.RESET}       {c.YELLOW}{config['dmarc']['host']}{c.RESET}")
    print(f"   {c.BOLD}Record Type:{c.RESET}       TXT")
    print(f"   {c.BOLD}TTL:{c.RESET}               3600")

    print(f"\n   {c.BOLD}{c.CYAN}[Phase 1: Initial Monitoring Mode]{c.RESET} (Audit without disruption)")
    print(f"   {c.YELLOW}{config['dmarc']['monitoring_record']}{c.RESET}")
    print(f"   {c.DIM}  -> 'p=none' monitors and delivers reports (RUA/RUF) without altering email delivery.{c.RESET}")

    print(f"\n   {c.BOLD}{c.YELLOW}[Phase 2: Quarantine Policy]{c.RESET} (Deliver suspicious mail to Spam)")
    print(f"   {c.YELLOW}{config['dmarc']['quarantine_record']}{c.RESET}")
    print(f"   {c.DIM}  -> 'p=quarantine' diverts unaligned mail to recipient Junk/Spam folder.{c.RESET}")

    print(f"\n   {c.BOLD}{c.GREEN}[Phase 3: Active Enforcement Mode]{c.RESET} (Maximum Security Hardening)")
    print(f"   {c.GREEN}{config['dmarc']['enforcement_record']}{c.RESET}")
    print(f"   {c.DIM}  -> 'p=reject' instructs receiving gateways to outright drop/bounce spoofed emails!{c.RESET}")
    print(f"   {c.DIM}  -> 'aspf=s; adkim=s' enforces strict domain alignment (subdomains must match From exactly).{c.RESET}")

    print(f"\n{c.BOLD}{c.CYAN}{'='*80}{c.RESET}\n")


# =====================================================================
# FUNCTION 2: EMAIL HEADER PARSER & ALIGNMENT ANALYZER
# =====================================================================

class EmailHeaderParser:
    """
    Parses raw RFC 5322 email headers, extracts Authentication-Results (RFC 8601),
    and evaluates SPF, DKIM, and DMARC authentication and alignment status.
    """

    def __init__(self, raw_header_text: str):
        self.raw_text = raw_header_text
        self.headers: Dict[str, Any] = {}
        self.auth_results_raw: List[str] = []
        self.parsed_data: Dict[str, Any] = {}
        self._parse()

    def _parse(self):
        """Extracts key headers using Python standard email parser."""
        parser = HeaderParser(policy=policy.default)
        message = parser.parsestr(self.raw_text)

        # Standard Email Identification Headers
        self.headers['From'] = message.get('From', '')
        self.headers['To'] = message.get('To', '')
        self.headers['Subject'] = message.get('Subject', '')
        self.headers['Date'] = message.get('Date', '')
        self.headers['Message-ID'] = message.get('Message-ID', '')
        self.headers['Return-Path'] = message.get('Return-Path', '')

        # All Authentication-Results headers (RFC 8601 / RFC 7601)
        self.auth_results_raw = message.get_all('Authentication-Results', [])

        # Additional complementary headers
        self.headers['Received-SPF'] = message.get('Received-SPF', '')
        self.headers['DKIM-Signature'] = message.get_all('DKIM-Signature', [])
        self.headers['ARC-Authentication-Results'] = message.get_all('ARC-Authentication-Results', [])

        # Extract From Address and Domain
        from_realname, from_email = parseaddr(self.headers['From'])
        if '@' in from_email:
            from_domain = from_email.split('@')[-1].lower()
        elif '.' in from_email:
            from_domain = from_email.strip('<>').lower()
        else:
            from_domain = ''
        from_org_domain = get_organizational_domain(from_domain)

        # Extract Return-Path (Envelope-From) Address and Domain
        _, rp_email = parseaddr(self.headers['Return-Path'])
        if '@' in rp_email:
            rp_domain = rp_email.split('@')[-1].lower()
        elif '.' in rp_email:
            rp_domain = rp_email.strip('<>').lower()
        else:
            rp_domain = ''
        rp_org_domain = get_organizational_domain(rp_domain)

        self.parsed_data = {
            'from_address': from_email,
            'from_domain': from_domain,
            'from_org_domain': from_org_domain,
            'return_path': rp_email,
            'return_path_domain': rp_domain,
            'return_path_org_domain': rp_org_domain,
            'spf_result': 'none',
            'spf_sender_domain': '',
            'spf_client_ip': '',
            'dkim_result': 'none',
            'dkim_domain': '',
            'dkim_selector': '',
            'dmarc_result': 'none',
            'dmarc_policy': 'none',
            'authserv_id': 'unknown'
        }

        self._parse_authentication_results()
        self._fallback_received_spf()
        self._fallback_dkim_signature()
        self._evaluate_alignment()

    def _parse_authentication_results(self):
        """
        Parses the structured Authentication-Results header lines.
        Example format:
        mx.google.com;
           dkim=pass header.i=@example.com header.s=mail2026 header.b=X9z...;
           spf=pass (google.com: domain of sender@example.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=sender@example.com;
           dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
        """
        combined_auth = " ".join(self.auth_results_raw)
        if not combined_auth:
            return

        # Extract authserv-id (first token before semicolon)
        first_part = combined_auth.split(';')[0].strip()
        self.parsed_data['authserv_id'] = first_part

        # 1. Parse SPF from Authentication-Results
        spf_match = re.search(r'\bspf\s*=\s*([a-zA-Z]+)', combined_auth, re.IGNORECASE)
        if spf_match:
            self.parsed_data['spf_result'] = spf_match.group(1).lower()

        spf_mailfrom_match = re.search(
            r'smtp\.mailfrom\s*=\s*<?([^\s;>]+)>?', combined_auth, re.IGNORECASE
        )
        if spf_mailfrom_match:
            spf_sender = spf_mailfrom_match.group(1)
            self.parsed_data['spf_sender_domain'] = spf_sender.split('@')[-1].lower()

        # Extract IP if present (handles 'designates 1.2.3.4' or 'does not designate 1.2.3.4')
        ip_match = re.search(r'(?:designates?|designate)\s+([0-9a-fA-F\.:]+)', combined_auth, re.IGNORECASE)
        if ip_match:
            self.parsed_data['spf_client_ip'] = ip_match.group(1)

        # 2. Parse DKIM from Authentication-Results
        dkim_match = re.search(r'\bdkim\s*=\s*([a-zA-Z]+)', combined_auth, re.IGNORECASE)
        if dkim_match:
            self.parsed_data['dkim_result'] = dkim_match.group(1).lower()

        dkim_header_i = re.search(r'header\.i\s*=\s*@?([^\s;]+)', combined_auth, re.IGNORECASE)
        if dkim_header_i:
            val = dkim_header_i.group(1).lstrip('@').lower()
            self.parsed_data['dkim_domain'] = val.split('@')[-1]

        dkim_header_s = re.search(r'header\.s\s*=\s*([^\s;]+)', combined_auth, re.IGNORECASE)
        if dkim_header_s:
            self.parsed_data['dkim_selector'] = dkim_header_s.group(1)

        # 3. Parse DMARC from Authentication-Results
        dmarc_match = re.search(r'\bdmarc\s*=\s*([a-zA-Z]+)', combined_auth, re.IGNORECASE)
        if dmarc_match:
            self.parsed_data['dmarc_result'] = dmarc_match.group(1).lower()

        dmarc_pol_match = re.search(r'p\s*=\s*([a-zA-Z]+)', combined_auth, re.IGNORECASE)
        if dmarc_pol_match:
            self.parsed_data['dmarc_policy'] = dmarc_pol_match.group(1).lower()

    def _fallback_received_spf(self):
        """Uses Received-SPF header if Authentication-Results lacks SPF data."""
        if not self.headers['Received-SPF']:
            return

        rec_spf = self.headers['Received-SPF']
        if self.parsed_data['spf_result'] == 'none':
            m = re.match(r'^([a-zA-Z]+)', rec_spf.strip())
            if m:
                self.parsed_data['spf_result'] = m.group(1).lower()

        # Extract client-ip if not yet found
        if not self.parsed_data['spf_client_ip']:
            ip_m = re.search(r'client-ip\s*=\s*([0-9a-fA-F\.:]+)', rec_spf, re.IGNORECASE)
            if ip_m:
                self.parsed_data['spf_client_ip'] = ip_m.group(1)

        # Extract envelope-from if not yet found
        if not self.parsed_data['spf_sender_domain']:
            env_m = re.search(r'envelope-from\s*=\s*<?([^\s;>]+)>?', rec_spf, re.IGNORECASE)
            if env_m:
                env_val = env_m.group(1)
                self.parsed_data['spf_sender_domain'] = env_val.split('@')[-1].lower()

    def _fallback_dkim_signature(self):
        """Extracts d= and s= tags from raw DKIM-Signature if missing from Authentication-Results."""
        if not self.headers['DKIM-Signature']:
            return

        first_sig = self.headers['DKIM-Signature'][0]
        if not self.parsed_data['dkim_domain']:
            d_match = re.search(r'\bd\s*=\s*([^;\s]+)', first_sig)
            if d_match:
                self.parsed_data['dkim_domain'] = d_match.group(1).strip().lower()

        if not self.parsed_data['dkim_selector']:
            s_match = re.search(r'\bs\s*=\s*([^;\s]+)', first_sig)
            if s_match:
                self.parsed_data['dkim_selector'] = s_match.group(1).strip()

    def _evaluate_alignment(self):
        """
        Computes strict and relaxed alignment for SPF and DKIM relative to Header From,
        and derives the definitive DMARC verdict.
        """
        from_dom = self.parsed_data['from_domain']
        from_org = self.parsed_data['from_org_domain']

        # Determine SPF domain to test (Envelope-From / Return-Path or explicit spf_sender_domain)
        spf_dom = self.parsed_data['spf_sender_domain'] or self.parsed_data['return_path_domain']
        spf_org = get_organizational_domain(spf_dom)

        # Determine DKIM domain to test
        dkim_dom = self.parsed_data['dkim_domain']
        dkim_org = get_organizational_domain(dkim_dom)

        # 1. SPF Alignment Evaluation
        # Strict: spf_domain == from_domain
        # Relaxed: OrgDomain(spf_domain) == OrgDomain(from_domain)
        spf_aligned_strict = bool(from_dom and spf_dom and (from_dom == spf_dom))
        spf_aligned_relaxed = bool(from_org and spf_org and (from_org == spf_org))

        # 2. DKIM Alignment Evaluation
        # Strict: dkim_domain == from_domain
        # Relaxed: OrgDomain(dkim_domain) == OrgDomain(from_domain)
        dkim_aligned_strict = bool(from_dom and dkim_dom and (from_dom == dkim_dom))
        dkim_aligned_relaxed = bool(from_org and dkim_org and (from_org == dkim_org))

        # 3. Protocol Success States
        spf_pass = (self.parsed_data['spf_result'] == 'pass')
        dkim_pass = (self.parsed_data['dkim_result'] == 'pass')

        # DMARC requires that either:
        # (SPF passes AND SPF is aligned) OR (DKIM passes AND DKIM is aligned)
        spf_dmarc_valid = spf_pass and spf_aligned_relaxed
        dkim_dmarc_valid = dkim_pass and dkim_aligned_relaxed

        dmarc_overall_pass = spf_dmarc_valid or dkim_dmarc_valid

        # Store evaluation details
        self.parsed_data['evaluation'] = {
            'from_header': from_dom,
            'spf_domain_evaluated': spf_dom,
            'spf_pass': spf_pass,
            'spf_aligned_strict': spf_aligned_strict,
            'spf_aligned_relaxed': spf_aligned_relaxed,
            'spf_dmarc_valid': spf_dmarc_valid,
            'dkim_domain_evaluated': dkim_dom,
            'dkim_pass': dkim_pass,
            'dkim_aligned_strict': dkim_aligned_strict,
            'dkim_aligned_relaxed': dkim_aligned_relaxed,
            'dkim_dmarc_valid': dkim_dmarc_valid,
            'dmarc_overall_pass': dmarc_overall_pass,
            'verdict': 'PASS' if dmarc_overall_pass else 'FAIL'
        }

    def print_terminal_summary(self):
        """Displays a clean, structured diagnostic report in the terminal."""
        c = Colors
        p = self.parsed_data
        ev = p['evaluation']

        print(f"\n{c.BOLD}{c.CYAN}{'='*80}{c.RESET}")
        print(f"{c.BOLD}{c.HEADER}   EMAIL AUTHENTICATION GATEWAY — INBOUND HEADER AUDIT REPORT{c.RESET}")
        print(f"{c.BOLD}{c.CYAN}{'='*80}{c.RESET}")

        # Basic Message Metadata Table
        print(f"{c.BOLD}1. MESSAGE ENVELOPE METADATA:{c.RESET}")
        print(f"   {c.BOLD}Header From:{c.RESET}        {self.headers.get('From', '<none>')}")
        print(f"   {c.BOLD}Envelope From (RP):{c.RESET} {self.headers.get('Return-Path', '<none>')}")
        print(f"   {c.BOLD}Header To:{c.RESET}          {self.headers.get('To', '<none>')}")
        print(f"   {c.BOLD}Subject:{c.RESET}            {self.headers.get('Subject', '<none>')}")
        print(f"   {c.BOLD}Date:{c.RESET}               {self.headers.get('Date', '<none>')}")
        print(f"   {c.BOLD}Message-ID:{c.RESET}         {self.headers.get('Message-ID', '<none>')}")
        print(f"   {c.BOLD}Auth-Serv ID:{c.RESET}       {p['authserv_id']}")

        print(f"\n{c.CYAN}{'-'*80}{c.RESET}")
        print(f"{c.BOLD}2. PROTOCOL AUTHENTICATION SUMMARY:{c.RESET}")

        # SPF Status Row
        spf_col = c.GREEN if p['spf_result'] == 'pass' else (c.YELLOW if p['spf_result'] in ('softfail', 'neutral') else c.RED)
        print(f"   {c.BOLD}SPF Result:{c.RESET}         {spf_col}[{p['spf_result'].upper()}]{c.RESET}")
        print(f"     • Client IP:       {p['spf_client_ip'] or 'Not Specified'}")
        print(f"     • Sender Domain:   {p['spf_sender_domain'] or p['return_path_domain'] or 'N/A'}")

        # DKIM Status Row
        dkim_col = c.GREEN if p['dkim_result'] == 'pass' else c.RED
        print(f"   {c.BOLD}DKIM Result:{c.RESET}        {dkim_col}[{p['dkim_result'].upper()}]{c.RESET}")
        print(f"     • Signing Domain:  {p['dkim_domain'] or 'None'}")
        print(f"     • Selector (s=):   {p['dkim_selector'] or 'None'}")

        # DMARC Status Row
        dmarc_col = c.GREEN if p['dmarc_result'] == 'pass' else c.RED
        print(f"   {c.BOLD}Reported DMARC:{c.RESET}     {dmarc_col}[{p['dmarc_result'].upper()}]{c.RESET} (Policy: {p['dmarc_policy'] or 'none'})")

        print(f"\n{c.CYAN}{'-'*80}{c.RESET}")
        print(f"{c.BOLD}3. DMARC IDENTIFIER ALIGNMENT MATRIX:{c.RESET}")
        print(f"   {c.DIM}RFC 7489 requires alignment between the RFC 5322 From domain and SPF/DKIM domains.{c.RESET}")
        print(f"   Header From Domain: {c.CYAN}{p['from_domain']}{c.RESET} (Org: {p['from_org_domain']})")

        # SPF Alignment Table Row
        spf_al_color = c.GREEN if ev['spf_dmarc_valid'] else c.RED
        print(f"\n   {c.BOLD}[SPF Alignment]{c.RESET}")
        print(f"     • Evaluated Domain: {ev['spf_domain_evaluated'] or 'N/A'}")
        print(f"     • Strict Alignment:  {'YES (Exact Match)' if ev['spf_aligned_strict'] else 'NO (Domain Discrepancy)'}")
        print(f"     • Relaxed Alignment: {'YES (Org Domain Match)' if ev['spf_aligned_relaxed'] else 'NO (Org Mismatch)'}")
        print(f"     • Auth + Aligned:    {spf_al_color}{'ELIGIBLE (PASS & ALIGNED)' if ev['spf_dmarc_valid'] else 'INELIGIBLE (FAILED OR UNALIGNED)'}{c.RESET}")

        # DKIM Alignment Table Row
        dkim_al_color = c.GREEN if ev['dkim_dmarc_valid'] else c.RED
        print(f"\n   {c.BOLD}[DKIM Alignment]{c.RESET}")
        print(f"     • Evaluated Domain: {ev['dkim_domain_evaluated'] or 'N/A'}")
        print(f"     • Strict Alignment:  {'YES (Exact Match)' if ev['dkim_aligned_strict'] else 'NO (Domain Discrepancy)'}")
        print(f"     • Relaxed Alignment: {'YES (Org Domain Match)' if ev['dkim_aligned_relaxed'] else 'NO (Org Mismatch)'}")
        print(f"     • Auth + Aligned:    {dkim_al_color}{'ELIGIBLE (PASS & ALIGNED)' if ev['dkim_dmarc_valid'] else 'INELIGIBLE (FAILED OR UNALIGNED)'}{c.RESET}")

        print(f"\n{c.CYAN}{'-'*80}{c.RESET}")
        print(f"{c.BOLD}4. GATEWAY SECURITY DISPOSITION & VERDICT:{c.RESET}")

        if ev['dmarc_overall_pass']:
            print(f"   {c.BOLD}Final Disposition:{c.RESET}  {c.GREEN}{c.BOLD}[VERIFIED / PASS — ACCEPT MESSAGE]{c.RESET}")
            print(f"   {c.GREEN}Identity authenticity confirmed via valid cryptographic/SPF alignment.{c.RESET}")
        else:
            pol = p['dmarc_policy'].lower()
            if pol == 'reject':
                print(f"   {c.BOLD}Final Disposition:{c.RESET}  {c.RED}{c.BOLD}[REJECTED — DROP / BOUNCE MESSAGE]{c.RESET}")
                print(f"   {c.RED}CRITICAL: Sender domain published p=reject policy. Gateway will drop this transmission.{c.RESET}")
            elif pol == 'quarantine':
                print(f"   {c.BOLD}Final Disposition:{c.RESET}  {c.YELLOW}{c.BOLD}[QUARANTINE — DIVERT TO SPAM/JUNK]{c.RESET}")
                print(f"   {c.YELLOW}WARNING: Sender failed authentication. Redirected to quarantine per policy.{c.RESET}")
            else:
                print(f"   {c.BOLD}Final Disposition:{c.RESET}  {c.YELLOW}{c.BOLD}[MONITORING / FLAG — ACCEPT WITH WARNING]{c.RESET}")
                print(f"   {c.YELLOW}NOTICE: Sender failed DMARC, but policy is p=none (Audit only). Delivery permitted.{c.RESET}")

        print(f"{c.BOLD}{c.CYAN}{'='*80}{c.RESET}\n")


# =====================================================================
# SAMPLE DATASET GENERATOR FOR COMPREHENSIVE TESTING
# =====================================================================

SAMPLE_LEGIT_HEADER = """\
Delivered-To: recipient@company.com
Received: by 2002:a05:6e02:18c4:0:0:0:0 with SMTP id e4csp12345;
        Tue, 24 Nov 2026 14:10:02 -0800 (PST)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@securebank.com header.s=mail2026 header.b=WkL97f;
       spf=pass (google.com: domain of alerts@securebank.com designates 198.51.100.25 as permitted sender) smtp.mailfrom=alerts@securebank.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=securebank.com
Received-SPF: pass (google.com: domain of alerts@securebank.com designates 198.51.100.25 as permitted sender) client-ip=198.51.100.25; envelope-from=alerts@securebank.com;
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=securebank.com; s=mail2026;
       h=from:to:subject:date:message-id;
       bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
       b=WkL97fQ3Xo...==
From: SecureBank Alerts <alerts@securebank.com>
To: recipient@company.com
Subject: Transaction Confirmation Notice #TXN-98421
Date: Tue, 24 Nov 2026 22:10:00 +0000
Message-ID: <20261124-98421-alerts@securebank.com>
Return-Path: <alerts@securebank.com>
Content-Type: text/plain; charset="UTF-8"

Dear Customer,
Your transfer of $250.00 was completed successfully.
"""

SAMPLE_SPOOFED_HEADER = """\
Delivered-To: victim@company.com
Received: by 2002:a05:6e02:18c4:0:0:0:0 with SMTP id rogue8821;
        Tue, 24 Nov 2026 14:22:15 -0800 (PST)
Authentication-Results: mx.google.com;
       dkim=none (no signature);
       spf=fail (google.com: domain of ceo@enterprise.com does not designate 203.0.113.88 as permitted sender) smtp.mailfrom=ceo@enterprise.com;
       dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=enterprise.com
Received-SPF: fail (google.com: domain of ceo@enterprise.com does not designate 203.0.113.88 as permitted sender) client-ip=203.0.113.88; envelope-from=ceo@enterprise.com;
From: Executive Office <ceo@enterprise.com>
To: victim@company.com
Subject: URGENT: Wire Transfer Required Immediately
Date: Tue, 24 Nov 2026 14:20:00 -0800
Message-ID: <spoofed.9841.fake@rogue-server.net>
Return-Path: <ceo@enterprise.com>
Content-Type: text/plain; charset="UTF-8"

Please execute wire transfer to vendor immediately.
"""

SAMPLE_FORWARDED_HEADER = """\
Delivered-To: recipient@company.com
Received: by 2002:a05:6e02:18c4:0:0:0:0 with SMTP id fwd9912;
        Tue, 24 Nov 2026 14:35:40 -0800 (PST)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@newsletter.dev.io header.s=k1 header.b=Ab38Xy;
       spf=softfail (google.com: domain of transitioning dev.io does not designate 192.0.2.77 as permitted sender) smtp.mailfrom=bounces@forwarder.net;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=newsletter.dev.io
Received-SPF: softfail (google.com: transitioning domain of bounces@forwarder.net) client-ip=192.0.2.77; envelope-from=bounces@forwarder.net;
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=newsletter.dev.io; s=k1;
       h=from:to:subject:date:message-id;
       b=Ab38Xy...==
From: Developer Weekly <editor@newsletter.dev.io>
To: recipient@company.com
Subject: Issue #104: Modern Cloud Security & Authentication
Date: Tue, 24 Nov 2026 18:30:00 +0000
Message-ID: <dev-weekly-104@newsletter.dev.io>
Return-Path: <bounces@forwarder.net>
Content-Type: text/plain; charset="UTF-8"

Weekly developer insights and architecture news.
"""

SAMPLE_MISALIGNED_HEADER = """\
Delivered-To: user@target.org
Received: by 2002:a05:6e02:18c4:0:0:0:0 with SMTP id misalign332;
        Tue, 24 Nov 2026 14:45:10 -0800 (PST)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@sendgrid.net header.s=smtpapi header.b=9Yx2;
       spf=pass (google.com: domain of bounces@sendgrid.net designates 167.89.0.1 as permitted sender) smtp.mailfrom=bounces@sendgrid.net;
       dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=paypal.com
Received-SPF: pass (google.com: domain of bounces@sendgrid.net designates 167.89.0.1 as permitted sender) client-ip=167.89.0.1; envelope-from=bounces@sendgrid.net;
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=sendgrid.net; s=smtpapi;
       h=from:to:subject:date:message-id;
       b=9Yx2...==
From: PayPal Security Team <service@paypal.com>
To: user@target.org
Subject: Action Required: Confirm Your Account Credentials
Date: Tue, 24 Nov 2026 22:45:00 +0000
Message-ID: <sg.campaign.88371@sendgrid.net>
Return-Path: <bounces@sendgrid.net>
Content-Type: text/plain; charset="UTF-8"

Suspicious login detected. Click here to verify your identity.
"""


def create_sample_files(target_dir: str = "samples") -> List[str]:
    """Generates realistic sample header files for CLI demonstration and testing."""
    os.makedirs(target_dir, exist_ok=True)
    files = {
        "sample_legit_header.txt": SAMPLE_LEGIT_HEADER,
        "sample_spoofed_header.txt": SAMPLE_SPOOFED_HEADER,
        "sample_forwarded_header.txt": SAMPLE_FORWARDED_HEADER,
        "sample_misaligned_header.txt": SAMPLE_MISALIGNED_HEADER,
    }
    created_paths = []
    for fname, content in files.items():
        fpath = os.path.join(target_dir, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        created_paths.append(fpath)
    return created_paths


# =====================================================================
# CLI ARGUMENT PARSER & ENTRYPOINT
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Secure Email Authentication Gateway (SPF, DKIM, DMARC) CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  1. Generate RSA key pair & complete DNS TXT records:
     python email_auth_gateway.py generate-dns --domain example.com --selector mail2026

  2. Parse and analyze a raw email header text file:
     python email_auth_gateway.py parse-headers --file samples/sample_legit_header.txt

  3. Create realistic test suite files and run comprehensive audit:
     python email_auth_gateway.py run-tests
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational Subcommands")

    # Command 1: generate-dns
    gen_parser = subparsers.add_parser(
        "generate-dns",
        help="Generate DKIM RSA key pair and output exact SPF, DKIM, and DMARC DNS TXT records"
    )
    gen_parser.add_argument(
        "--domain", "-d",
        required=True,
        help="Authoritative domain name (e.g., example.com)"
    )
    gen_parser.add_argument(
        "--selector", "-s",
        default="mail2026",
        help="DKIM key selector identifier (default: mail2026)"
    )
    gen_parser.add_argument(
        "--key-size", "-k",
        type=int,
        default=2048,
        choices=[1024, 2048, 4096],
        help="RSA key bit length (default: 2048)"
    )
    gen_parser.add_argument(
        "--output-dir", "-o",
        default="keys",
        help="Directory to save generated private and public key files (default: keys)"
    )
    gen_parser.add_argument(
        "--ip",
        action="append",
        dest="ips",
        help="Authorized IPv4 address for SPF (can specify multiple)"
    )
    gen_parser.add_argument(
        "--include",
        action="append",
        dest="includes",
        help="Authorized include domain for SPF (e.g., _spf.google.com)"
    )
    gen_parser.add_argument(
        "--rua",
        help="DMARC Aggregate Reporting email address"
    )
    gen_parser.add_argument(
        "--ruf",
        help="DMARC Forensic/Failure Reporting email address"
    )

    # Command 2: parse-headers
    parse_parser = subparsers.add_parser(
        "parse-headers",
        help="Parse raw email header text and evaluate SPF, DKIM, and DMARC authentication/alignment"
    )
    parse_parser.add_argument(
        "--file", "-f",
        required=True,
        help="Path to the raw email header text file"
    )
    parse_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI terminal colors in output"
    )

    # Command 3: run-tests
    test_parser = subparsers.add_parser(
        "run-tests",
        help="Generate sample datasets (Legit, Spoofed, Forwarded, Misaligned) and run batch audit"
    )
    test_parser.add_argument(
        "--output-dir", "-o",
        default="samples",
        help="Directory for sample files"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "generate-dns":
        try:
            config = generate_dns_records(
                domain=args.domain,
                selector=args.selector,
                key_size=args.key_size,
                output_dir=args.output_dir,
                spf_ips=args.ips,
                spf_includes=args.includes,
                rua_email=args.rua,
                ruf_email=args.ruf
            )
            print_dns_records(config)
        except Exception as e:
            print(f"{Colors.RED}Error generating DNS records: {e}{Colors.RESET}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "parse-headers":
        if args.no_color:
            Colors.disable()

        if not os.path.exists(args.file):
            print(f"{Colors.RED}Error: File '{args.file}' not found.{Colors.RESET}", file=sys.stderr)
            sys.exit(1)

        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                header_text = f.read()

            parser_inst = EmailHeaderParser(header_text)
            parser_inst.print_terminal_summary()
        except Exception as e:
            print(f"{Colors.RED}Error parsing email headers: {e}{Colors.RESET}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "run-tests":
        print(f"{Colors.BOLD}{Colors.CYAN}Initializing Test Suite: Generating Realistic Header Scenarios...{Colors.RESET}")
        sample_paths = create_sample_files(args.output_dir)
        print(f"Created {len(sample_paths)} sample header test cases in '{args.output_dir}' directory.\n")

        for sp in sample_paths:
            print(f"{Colors.BOLD}{Colors.HEADER}>>> AUDITING TEST CASE: {os.path.basename(sp)} <<<{Colors.RESET}")
            with open(sp, "r", encoding="utf-8") as f:
                content = f.read()
            p = EmailHeaderParser(content)
            p.print_terminal_summary()


if __name__ == "__main__":
    main()
