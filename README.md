# Secure Email Authentication Gateway (SPF, DKIM, and DMARC)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Email Security](https://img.shields.io/badge/Security-SPF%20%7C%20DKIM%20%7C%20DMARC-green.svg)](#)

A high-performance, lightweight Python Command-Line Interface (CLI) gateway tool engineered for enterprise email authentication, identity verification, and anti-spoofing defense. 

This tool serves two critical operational roles in email security architecture:
1. **Outbound Provisioning & DNS Generation**: Automates 2048-bit RSA key pair generation for DKIM and outputs exact, standards-compliant DNS TXT record formats for SPF (RFC 7208), DKIM (RFC 6376), and DMARC (RFC 7489) across monitoring (`p=none`), quarantine (`p=quarantine`), and strict enforcement (`p=reject`) policies.
2. **Inbound Gateway Header Auditing & Alignment Inspection**: Ingests raw RFC 5322 email headers, extracts RFC 8601 `Authentication-Results`, analyzes identifier alignment (Strict vs. Relaxed), and renders actionable terminal diagnostic summaries with gateway disposition decisions (Accept, Quarantine, Reject).

---

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Core Security Protocols Explained](#core-security-protocols-explained)
  - [1. Sender Policy Framework (SPF)](#1-sender-policy-framework-spf)
  - [2. DomainKeys Identified Mail (DKIM)](#2-domainkeys-identified-mail-dkim)
  - [3. Domain-based Message Authentication, Reporting & Conformance (DMARC)](#3-domain-based-message-authentication-reporting--conformance-dmarc)
- [Identifier Alignment Mechanics](#identifier-alignment-mechanics)
- [Installation & Prerequisites](#installation--prerequisites)
- [CLI Command Reference & Usage](#cli-command-reference--usage)
  - [Command 1: `generate-dns`](#command-1-generate-dns)
  - [Command 2: `parse-headers`](#command-2-parse-headers)
  - [Command 3: `run-tests`](#command-3-run-tests)
- [Test Case Scenarios & Gateway Results](#test-case-scenarios--gateway-results)
- [DNS Record Specification Guide](#dns-record-specification-guide)
- [Project Structure](#project-structure)
- [Author & License](#author--license)

---

## Architecture Overview

The Secure Email Authentication Gateway enforces identity verification through a layered cryptographic and DNS inspection pipeline:

```
                    +---------------------------------------------------------+
                    |                INBOUND EMAIL ARRIVAL                    |
                    +---------------------------------------------------------+
                                                 |
                                                 v
                       +---------------------------------------------------+
                       |    Step 1: RFC 5322 Header Parser & Extraction    |
                       |  - From: (RFC 5322) | Return-Path: (RFC 5321)     |
                       |  - Authentication-Results (RFC 8601)              |
                       |  - Received-SPF & DKIM-Signature (Fallbacks)      |
                       +---------------------------------------------------+
                                                 |
                       +-------------------------+-------------------------+
                       |                                                   |
                       v                                                   v
        +-----------------------------+                     +-----------------------------+
        |     SPF Verification        |                     |      DKIM Verification      |
        |  - Check sending MTA IP     |                     |  - Cryptographic RSA-SHA256 |
        |  - Match vs SPF TXT record  |                     |  - Validate header/body sig |
        |  - Status: Pass/Fail/Soft   |                     |  - Status: Pass/Fail/None   |
        +-----------------------------+                     +-----------------------------+
                       |                                                   |
                       +-------------------------+-------------------------+
                                                 |
                                                 v
                       +---------------------------------------------------+
                       |    Step 2: DMARC Identifier Alignment Engine      |
                       |  - SPF Alignment:  OrgDomain(Return-Path) == From |
                       |  - DKIM Alignment: OrgDomain(DKIM d=)     == From |
                       +---------------------------------------------------+
                                                 |
                                                 v
                       +---------------------------------------------------+
                       |         Step 3: Gateway Policy Evaluation         |
                       |  DMARC PASS = (SPF Auth & Aligned) OR             |
                       |               (DKIM Auth & Aligned)               |
                       +---------------------------------------------------+
                                                 |
                       +-------------------------+-------------------------+
                       |                                                   |
                   [PASS]                                               [FAIL]
                       v                                                   v
        +-----------------------------+                     +-----------------------------+
        |   VERIFIED / ACCEPT MAIL    |                     |   Check Domain DMARC Policy |
        | - Route to Primary Inbox    |                     | - p=none:       Deliver     |
        | - Full Identity Assured     |                     | - p=quarantine: Spam/Junk   |
        +-----------------------------+                     | - p=reject:     DROP/BOUNCE |
                                                            +-----------------------------+
```

---

## Core Security Protocols Explained

### 1. Sender Policy Framework (SPF) — [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208)
SPF allows a domain owner to publish a list of authorized IP addresses or subnets permitted to send emails under their envelope return address (`RFC 5321 Return-Path`).
* **Mechanism**: When receiving an email, the gateway performs a DNS TXT lookup on the sender's envelope domain and checks if the connecting MTA's client IP matches the authorization directives (`ip4`, `ip6`, `a`, `mx`, `include`).
* **Qualifiers**:
  * `+` (Pass): Authorized sender (default).
  * `~` (Softfail): Transition state; sender not explicitly authorized, but do not hard drop.
  * `-` (Fail / Hardfail): Unauthorized sender; receiving gateway should reject.
  * `?` (Neutral): Explicitly no assertion.

### 2. DomainKeys Identified Mail (DKIM) — [RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376)
DKIM provides cryptographic tamper-proofing and non-repudiation for email transmissions.
* **Mechanism**: 
  1. The sending mail server computes an asymmetric digital signature over specified message headers (e.g., `From`, `To`, `Subject`, `Date`) and the message body hash (`bh=`).
  2. The signature is signed using an RSA private key and attached as the `DKIM-Signature` header.
  3. The receiving gateway fetches the sender's public key from DNS at `<selector>._domainkey.<domain>` and validates the digital signature.
  4. If an adversary alters even a single character in transit, the cryptographic verification fails immediately.

### 3. Domain-based Message Authentication, Reporting & Conformance (DMARC) — [RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489)
SPF and DKIM alone have critical gaps:
* SPF only validates the hidden envelope sender (`Return-Path`), leaving the visible `From:` header susceptible to spoofing.
* DKIM signatures can be generated by any valid domain (e.g., an attacker signing with `attacker.com` while forging `From: ceo@bank.com`).
* **DMARC solves both flaws** by requiring **Identifier Alignment** between the visible RFC 5322 `From:` domain and the authenticated SPF/DKIM domains.

---

## Identifier Alignment Mechanics

DMARC enforces strict or relaxed domain alignment:

| Protocol | Alignment Mode | Rule | Example Match | Result |
| :--- | :--- | :--- | :--- | :--- |
| **SPF** | **Relaxed (`aspf=r`)** | Base / Organizational domains match | `mail.bank.com` == `bank.com` | **PASS** |
| **SPF** | **Strict (`aspf=s`)** | Fully Qualified Domain Names must match exactly | `mail.bank.com` != `bank.com` | **FAIL** |
| **DKIM** | **Relaxed (`adkim=r`)** | Base / Organizational domains match | `d=corp.bank.com` == `bank.com` | **PASS** |
| **DKIM** | **Strict (`adkim=s`)** | Exact domain equality required | `d=corp.bank.com` != `bank.com` | **FAIL** |

> **DMARC Decision Logic**: An email passes DMARC if **at least one** underlying protocol (SPF or DKIM) both **passes authentication** and **aligns** with the visible `From:` header domain.

---

## Installation & Prerequisites

### Prerequisites
* Python 3.8 or higher
* Standard Git CLI

### Setup
Clone the repository and install required Python packages:

```cmd
git clone https://github.com/kevinmonteiro543-sketch/Secure-Email-Authentication-Gateway-with-SPF-DKIM-and-DMARC.git
cd "Secure-Email-Authentication-Gateway-with-SPF-DKIM-and-DMARC"
pip install -r requirements.txt
```

---

## CLI Command Reference & Usage

The gateway CLI is structured into three dedicated commands:

```
usage: email_auth_gateway.py [-h] {generate-dns,parse-headers,run-tests} ...
```

### Command 1: `generate-dns`
Generates a cryptographically strong 2048-bit RSA key pair, stores the keys locally, and formats complete, ready-to-publish DNS TXT records for SPF, DKIM, and DMARC across progressive policy stages.

```cmd
python email_auth_gateway.py generate-dns --domain securebank.com --selector mail2026 --ip 198.51.100.25
```

#### Flags:
* `--domain`, `-d` *(required)*: Authoritative sending domain name.
* `--selector`, `-s` *(optional)*: DKIM key selector identifier (default: `mail2026`).
* `--key-size`, `-k` *(optional)*: RSA bit length: `1024`, `2048`, `4096` (default: `2048`).
* `--output-dir`, `-o` *(optional)*: Output directory for PEM key files (default: `keys`).
* `--ip` *(optional)*: Authorized IPv4 address to include in SPF (repeatable).
* `--include` *(optional)*: Third-party SPF include domain (e.g., `_spf.google.com`).
* `--rua` *(optional)*: Aggregate reporting address (default: `dmarc-reports@domain`).
* `--ruf` *(optional)*: Forensic/Failure reporting address (default: `dmarc-forensics@domain`).

---

### Command 2: `parse-headers`
Accepts a raw RFC 5322 email header text file, parses RFC 8601 `Authentication-Results`, evaluates protocol alignment, and outputs a diagnostic terminal audit report.

```cmd
python email_auth_gateway.py parse-headers --file samples/sample_legit_header.txt
```

#### Optional Flags:
* `--no-color`: Disables ANSI color escapes for clean logging or script piping.

---

### Command 3: `run-tests`
Generates a realistic test suite of 4 distinct email authentication scenarios and executes the complete verification pipeline on each.

```cmd
python email_auth_gateway.py run-tests
```

---

## Test Case Scenarios & Gateway Results

The included test suite exercises all edge cases encountered in production email environments:

```
+-------------------------------------------------------------------------------------------------------+
| Test Scenario               | SPF Status  | DKIM Status | Alignment Status      | Gateway Disposition |
+-------------------------------------------------------------------------------------------------------+
| 1. Legit Bank Confirmation  | PASS (IP)   | PASS (RSA)  | SPF & DKIM Aligned    | VERIFIED / ACCEPT   |
| 2. Spoofed CEO Wire Fraud   | FAIL (IP)   | NONE        | Unauthenticated       | REJECT / DROP       |
| 3. Forwarded Tech Newsletter| SOFTFAIL    | PASS (RSA)  | DKIM Aligned          | VERIFIED / ACCEPT   |
| 4. Third-Party Misalignment | PASS (Relay)| PASS (Relay)| From Domain Mismatch  | REJECT / DROP       |
+-------------------------------------------------------------------------------------------------------+
```

### Detailed Breakdown of Scenarios:
1. **Legitimate In-House Email (`sample_legit_header.txt`)**:
   - Both SPF (authorized IP) and DKIM (2048-bit signature) pass and align perfectly with `securebank.com`. Result: **ACCEPT**.
2. **Spoofed Executive Impersonation (`sample_spoofed_header.txt`)**:
   - Attacker attempts to forge `From: ceo@enterprise.com`. SPF fails because the rogue IP is unauthorized. No DKIM signature exists. Result: **REJECT / DROP**.
3. **Mailing List / Forwarded Transmission (`sample_forwarded_header.txt`)**:
   - Forwarding server rewrote `Return-Path` to its own bounce domain (`bounces@forwarder.net`), causing SPF softfail. However, the original DKIM cryptographic signature remained untouched and valid. Under DMARC, **DKIM alignment rescues the message**. Result: **ACCEPT**.
4. **Service Provider Alignment Attack (`sample_misaligned_header.txt`)**:
   - Attacker sends an email through a legitimate SendGrid account (`d=sendgrid.net`), but claims `From: service@paypal.com`. Even though SPF and DKIM pass for SendGrid, they fail DMARC alignment against `paypal.com`. Result: **REJECT / DROP**.

---

## DNS Record Specification Guide

### 1. SPF Record Specification
```dns
;; Host: @ or example.com (Type: TXT, TTL: 3600)
v=spf1 mx a ip4:198.51.100.25 include:_spf.example.com -all
```
* `v=spf1`: Protocol version tag.
* `mx`: Authorizes MX mail servers of the domain.
* `a`: Authorizes the domain's A record IP.
* `ip4:198.51.100.25`: Explicitly authorized outbound gateway IP.
* `-all`: Strict Hardfail. Any unlisted IP is categorically rejected.

### 2. DKIM Record Specification
```dns
;; Host: mail2026._domainkey.example.com (Type: TXT, TTL: 3600)
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8LCym...IDAQAB
```
* `v=DKIM1`: DKIM version.
* `k=rsa`: Cryptographic algorithm used (RSA).
* `p=...`: Base64-encoded SubjectPublicKeyInfo string.

### 3. DMARC Phased Enforcement Strategy
Domains should transition gradually to avoid accidental delivery disruptions:

```dns
;; Phase 1: Monitoring Mode (Audit only)
v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com; ruf=mailto:dmarc-forensics@example.com; pct=100; sp=none; aspf=r; adkim=r

;; Phase 2: Quarantine Mode (Divert failures to Spam)
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@example.com; ruf=mailto:dmarc-forensics@example.com; sp=quarantine; aspf=r; adkim=r

;; Phase 3: Active Enforcement Mode (Outright Drop/Bounce Spoofed Emails)
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@example.com; ruf=mailto:dmarc-forensics@example.com; sp=reject; aspf=s; adkim=s
```

---

## Project Structure

```
Secure-Email-Authentication-Gateway/
├── email_auth_gateway.py          # Primary CLI Gateway Application
├── Email_Auth_Gateway_Report.pdf  # Comprehensive Academic & Technical PDF Report
├── README.md                      # Complete System Documentation & Guide
├── requirements.txt               # Production Python Package Dependencies
├── keys/                          # Generated 2048-bit RSA PEM Keys (Git-ignored)
│   ├── mail2026.private.key
│   └── mail2026.public.key
└── samples/                       # Realistic Test Dataset Headers
    ├── sample_legit_header.txt
    ├── sample_spoofed_header.txt
    ├── sample_forwarded_header.txt
    └── sample_misaligned_header.txt
```

---

## Author & License
* **Author**: Kevin Monteiro
* **Repository**: [kevinmonteiro543-sketch/Secure-Email-Authentication-Gateway-with-SPF-DKIM-and-DMARC](https://github.com/kevinmonteiro543-sketch/Secure-Email-Authentication-Gateway-with-SPF-DKIM-and-DMARC.git)
* **License**: MIT License
