#!/usr/bin/env python3
"""
Publication-Grade PDF Report Generator for:
Secure Email Authentication Gateway (SPF, DKIM, and DMARC)
---------------------------------------------------------
Generates an academic and enterprise technical whitepaper PDF
featuring professional typography, running headers/footers with
dynamic page numbering (Page X of Y), structured data tables,
security callouts, and formatted source code.
"""

import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable, Preformatted
)
from reportlab.pdfgen import canvas

# =====================================================================
# NUMBERED CANVAS FOR RUNNING HEADERS AND FOOTERS (PAGE X OF Y)
# =====================================================================

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#4A5568"))

        # Omit running header on page 1 (cover / title page)
        if self._pageNumber > 1:
            # Header line
            self.setStrokeColor(colors.HexColor("#CBD5E0"))
            self.setLineWidth(0.5)
            self.line(54, 750, 558, 750)
            
            # Header text
            self.drawString(54, 755, "SECURE EMAIL AUTHENTICATION GATEWAY (SPF, DKIM, DMARC)")
            self.drawRightString(558, 755, "TECHNICAL AUDIT & REPORT")

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#CBD5E0"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)

        footer_text = "CONFIDENTIAL & PROPRIETARY — SECURITY ARCHITECTURE SPECIFICATION"
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawString(54, 32, footer_text)
        self.drawRightString(558, 32, page_str)

        self.restoreState()


# =====================================================================
# PDF GENERATION LOGIC
# =====================================================================

def build_pdf(filename="Email_Auth_Gateway_Report.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom Palette
    c_primary = colors.HexColor("#1A365D")    # Deep Navy
    c_secondary = colors.HexColor("#2B6CB0")  # Slate Blue
    c_dark = colors.HexColor("#2D3748")       # Body Charcoal
    c_green = colors.HexColor("#276749")      # Emerald Pass
    c_red = colors.HexColor("#9B2C2C")        # Crimson Fail
    c_amber = colors.HexColor("#B7791F")      # Amber Softfail
    c_bg_light = colors.HexColor("#F7FAFC")   # Shaded Card
    c_border = colors.HexColor("#E2E8F0")

    # Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=c_primary,
        alignment=0, # Left
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=c_secondary,
        alignment=0,
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=19,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=c_secondary,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=c_dark,
        spaceAfter=6
    )

    callout_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#2C5282")
    )

    code_inline = ParagraphStyle(
        'CodeInline',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#805AD5")
    )

    code_block_style = ParagraphStyle(
        'CodeBlock',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#1A202C")
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white,
        alignment=1 # Center
    )

    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=c_dark
    )

    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=c_dark
    )

    story = []

    # -----------------------------------------------------------------
    # TITLE & METADATA HEADER
    # -----------------------------------------------------------------
    story.append(Paragraph("Secure Email Authentication Gateway", title_style))
    story.append(Paragraph("Standards-Compliant SPF, DKIM, and DMARC Architecture & Verification Gateway", subtitle_style))

    # Metadata Banner Table
    meta_data = [
        [
            Paragraph("<b>Author:</b> Kevin Monteiro", body_style),
            Paragraph("<b>Date:</b> November 24, 2026", body_style),
            Paragraph("<b>Status:</b> Production Verified", body_style)
        ],
        [
            Paragraph("<b>Repository:</b> kevinmonteiro543-sketch", body_style),
            Paragraph("<b>Architecture:</b> RFC 7208 / 6376 / 7489", body_style),
            Paragraph("<b>CLI Version:</b> 1.0.0", body_style)
        ]
    ]
    t_meta = Table(meta_data, colWidths=[170, 170, 164])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_bg_light),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('INNERGRID', (0,0), (-1,-1), 0.5, c_border),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------
    # EXECUTIVE SUMMARY & ABSTRACT
    # -----------------------------------------------------------------
    story.append(Paragraph("Executive Summary & Abstract", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceAfter=6, spaceBefore=0))
    story.append(Paragraph(
        "Email remains the foundational protocol of global corporate communications; yet Simple Mail Transfer "
        "Protocol (SMTP, RFC 821/5321) was natively architected without intrinsic sender authentication. Consequently, "
        "threat actors systematically exploit SMTP's decoupled identity architecture to execute Business Email "
        "Compromise (BEC), credential phishing, and domain impersonation attacks. This engineering project designs, "
        "implements, and validates a lightweight, standards-compliant <b>Secure Email Authentication Gateway</b> CLI. "
        "The gateway delivers a dual operational capability: (1) automated cryptographic RSA-2048 key pair generation "
        "and complete DNS TXT record formatting across SPF, DKIM, and progressive DMARC policy phases (<code>p=none</code>, "
        "<code>p=quarantine</code>, <code>p=reject</code>); and (2) an inbound RFC 5322 header auditor that extracts "
        "RFC 8601 <code>Authentication-Results</code>, computes strict and relaxed identifier alignment, and issues deterministic "
        "gateway verdicts (Accept, Quarantine, Reject).",
        body_style
    ))

    # Abstract Highlight Callout Box
    callout_data = [[
        Paragraph(
            "<b>Key Security Takeaway:</b> Neither SPF nor DKIM independently shields organizations from domain "
            "spoofing. SPF validates only the envelope sender (<code>Return-Path</code>), while DKIM validates solely "
            "the cryptographic signer (<code>d=</code>). DMARC bridges this vulnerability by mandating <b>Identifier "
            "Alignment</b> between the authenticated identity and the visible RFC 5322 <code>From:</code> address, "
            "enabling automated enforcement (<code>p=reject</code>) to neutralize forged transmissions.",
            callout_style
        )
    ]]
    t_callout = Table(callout_data, colWidths=[504])
    t_callout.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#EBF8FF")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#BEE3F8")),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_callout)
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------
    # PROTOCOL ARCHITECTURE & SPECIFICATIONS
    # -----------------------------------------------------------------
    story.append(Paragraph("1. Core Security Protocols: Technical Architecture", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceAfter=6, spaceBefore=0))

    story.append(Paragraph("1.1 Sender Policy Framework (SPF) — RFC 7208", h2_style))
    story.append(Paragraph(
        "SPF permits a domain owner to publish authorized Mail Transfer Agent (MTA) IP addresses via DNS TXT records. "
        "When an incoming SMTP connection is initiated, the recipient gateway extracts the RFC 5321 <code>MAIL FROM</code> "
        "(Envelope Return-Path) and queries the authoritative DNS zone for matching <code>v=spf1</code> directives. "
        "Directives evaluate sequentially with prefix qualifiers: <code>+</code> (Pass), <code>-</code> (Fail/Hardfail), "
        "<code>~</code> (Softfail), and <code>?</code> (Neutral). To prevent Denial of Service (DoS) loops, RFC 7208 enforces "
        "a hard limit of <b>10 DNS-modifying lookups</b> (mechanisms: <code>include</code>, <code>a</code>, <code>mx</code>, <code>ptr</code>, <code>exists</code>, <code>redirect</code>).",
        body_style
    ))

    story.append(Paragraph("1.2 DomainKeys Identified Mail (DKIM) — RFC 6376", h2_style))
    story.append(Paragraph(
        "DKIM establishes cryptographic non-repudiation and transit message integrity. An outbound sending gateway computes "
        "a canonicalized hash of the message body (<code>bh=</code>) and specified header fields (<code>h=From:To:Subject:Date</code>). "
        "The resulting digest is signed with the domain's RSA private key (2048-bit recommended) and embedded in the <code>DKIM-Signature</code> "
        "header. The recipient gateway retrieves the corresponding public key from the authoritative DNS zone at "
        "<code>&lt;selector&gt;._domainkey.&lt;domain&gt;</code> and mathematically verifies signature validity. DKIM signatures "
        "survive intermediary forwarding and mailing lists where SPF typically collapses.",
        body_style
    ))

    story.append(Paragraph("1.3 Domain-based Message Authentication, Reporting & Conformance (DMARC) — RFC 7489", h2_style))
    story.append(Paragraph(
        "DMARC unifies SPF and DKIM by establishing policy assertions and reporting mechanisms anchored directly to the "
        "visible RFC 5322 <code>From:</code> domain. DMARC enables sending organizations to monitor fraudulent misuse via aggregate "
        "XML telemetry (<code>rua=</code>) and forensic failure samples (<code>ruf=</code>), while commanding receiving gateways to "
        "quarantine or reject unauthorized transmissions.",
        body_style
    ))

    # Table: Protocol Comparison
    proto_headers = [
        Paragraph("<b>Security Protocol</b>", table_header_style),
        Paragraph("<b>RFC Standard</b>", table_header_style),
        Paragraph("<b>Identity Verified</b>", table_header_style),
        Paragraph("<b>Cryptographic Basis</b>", table_header_style),
        Paragraph("<b>Forwarding Resilience</b>", table_header_style),
    ]
    proto_rows = [
        [
            Paragraph("<b>SPF</b>", table_cell_bold),
            Paragraph("RFC 7208", table_cell_style),
            Paragraph("RFC 5321 Envelope (<code>Return-Path</code>)", table_cell_style),
            Paragraph("None (IP Authorization)", table_cell_style),
            Paragraph("Low (Breaks on relay/forward)", table_cell_style),
        ],
        [
            Paragraph("<b>DKIM</b>", table_cell_bold),
            Paragraph("RFC 6376", table_cell_style),
            Paragraph("Cryptographic Signer (<code>d=</code> tag)", table_cell_style),
            Paragraph("Asymmetric RSA-SHA256", table_cell_style),
            Paragraph("High (Survives if body unedited)", table_cell_style),
        ],
        [
            Paragraph("<b>DMARC</b>", table_cell_bold),
            Paragraph("RFC 7489", table_cell_style),
            Paragraph("Visible RFC 5322 <code>From:</code> Header", table_cell_style),
            Paragraph("Orchestrates SPF + DKIM Alignment", table_cell_style),
            Paragraph("Robust (Maintains DKIM path)", table_cell_style),
        ],
    ]
    t_proto = Table([proto_headers] + proto_rows, colWidths=[74, 60, 140, 110, 120])
    t_proto.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('INNERGRID', (0,0), (-1,-1), 0.5, c_border),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
    ]))
    story.append(t_proto)
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------
    # DMARC ALIGNMENT & POLICY PROGRESSION
    # -----------------------------------------------------------------
    story.append(Paragraph("2. Identifier Alignment & Phased Policy Progression", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceAfter=6, spaceBefore=0))

    story.append(Paragraph(
        "DMARC requires that the domain in the visible <code>From:</code> header aligns with the domain authenticated by "
        "SPF and/or DKIM. Alignment is evaluated under either <b>Relaxed</b> (default) or <b>Strict</b> mode:",
        body_style
    ))

    align_data = [
        [
            Paragraph("<b>Protocol</b>", table_header_style),
            Paragraph("<b>Alignment Mode</b>", table_header_style),
            Paragraph("<b>DNS Tag</b>", table_header_style),
            Paragraph("<b>Rule & Mathematical Condition</b>", table_header_style),
        ],
        [
            Paragraph("<b>SPF</b>", table_cell_bold),
            Paragraph("Relaxed", table_cell_style),
            Paragraph("<code>aspf=r</code>", table_cell_style),
            Paragraph("<code>OrgDomain(Return-Path) == OrgDomain(Header From)</code> (Subdomains permitted)", table_cell_style),
        ],
        [
            Paragraph("<b>SPF</b>", table_cell_bold),
            Paragraph("Strict", table_cell_style),
            Paragraph("<code>aspf=s</code>", table_cell_style),
            Paragraph("<code>Return-Path Domain == Header From Domain</code> (Exact FQDN match mandatory)", table_cell_style),
        ],
        [
            Paragraph("<b>DKIM</b>", table_cell_bold),
            Paragraph("Relaxed", table_cell_style),
            Paragraph("<code>adkim=r</code>", table_cell_style),
            Paragraph("<code>OrgDomain(d=) == OrgDomain(Header From)</code> (Subdomains permitted)", table_cell_style),
        ],
        [
            Paragraph("<b>DKIM</b>", table_cell_bold),
            Paragraph("Strict", table_cell_style),
            Paragraph("<code>adkim=s</code>", table_cell_style),
            Paragraph("<code>DKIM d= Domain == Header From Domain</code> (Exact FQDN match mandatory)", table_cell_style),
        ],
    ]
    t_align = Table(align_data, colWidths=[64, 70, 70, 300])
    t_align.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_secondary),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('INNERGRID', (0,0), (-1,-1), 0.5, c_border),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
    ]))
    story.append(t_align)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Phased DMARC Implementation Lifecycle:", h2_style))
    story.append(Paragraph(
        "Deploying DMARC directly to <code>p=reject</code> risks catastrophic business disruption due to legitimate third-party "
        "senders (e.g., Salesforce, SendGrid, ServiceNow) failing authentication. Enterprise organizations execute a three-phase progression:",
        body_style
    ))

    policy_data = [
        [
            Paragraph("<b>Deployment Phase</b>", table_header_style),
            Paragraph("<b>Policy Tag</b>", table_header_style),
            Paragraph("<b>Gateway Action</b>", table_header_style),
            Paragraph("<b>Operational Objective & Best Practice</b>", table_header_style),
        ],
        [
            Paragraph("<b>Phase 1: Monitoring</b>", table_cell_bold),
            Paragraph("<code>p=none</code>", table_cell_style),
            Paragraph("Deliver Unaltered", table_cell_style),
            Paragraph("Ingest RUA aggregate reports to audit all outbound email streams without delivery risk.", table_cell_style),
        ],
        [
            Paragraph("<b>Phase 2: Quarantine</b>", table_cell_bold),
            Paragraph("<code>p=quarantine</code>", table_cell_style),
            Paragraph("Route to Spam/Junk", table_cell_style),
            Paragraph("Divert unaligned messages away from recipient inboxes; verify false positive ratios.", table_cell_style),
        ],
        [
            Paragraph("<b>Phase 3: Enforcement</b>", table_cell_bold),
            Paragraph("<code>p=reject</code>", table_cell_style),
            Paragraph("Drop / Bounce Message", table_cell_style),
            Paragraph("Total spoofing immunity; gateway drops unaligned emails at the SMTP boundary.", table_cell_style),
        ],
    ]
    t_policy = Table(policy_data, colWidths=[110, 80, 100, 214])
    t_policy.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('INNERGRID', (0,0), (-1,-1), 0.5, c_border),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
    ]))
    story.append(t_policy)
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------
    # GATEWAY PROCESSING LOGIC & DATA FLOW
    # -----------------------------------------------------------------
    story.append(Paragraph("3. Gateway Architecture & Inspection Pipeline", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceAfter=6, spaceBefore=0))

    story.append(Paragraph(
        "The gateway executes a deterministic, multi-stage processing pipeline upon receiving an inbound email stream:",
        body_style
    ))

    # Flowchart / ASCII Table Diagram
    flowchart_text = """+-----------------------------------------------------------------------------------+
|                        INBOUND RFC 5322 EMAIL STREAM                              |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 1. RFC 8601 HEADER EXTRACTION:                                                    |
|    - Parse Authentication-Results (authserv-id, spf, dkim, dmarc results)         |
|    - Extract RFC 5322 'From:' Header Domain & Compute Organizational Root Domain   |
|    - Extract RFC 5321 'Return-Path:' Envelope Domain                              |
|    - Fallback: Extract 'Received-SPF' client-ip and 'DKIM-Signature' d= / s= tags  |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 2. MULTI-FACTOR IDENTIFIER ALIGNMENT ENGINE:                                      |
|    • SPF Condition:  (SPF Result == 'pass') AND (OrgDomain(RP) == OrgDomain(From))|
|    • DKIM Condition: (DKIM Result == 'pass') AND (OrgDomain(d=) == OrgDomain(From))|
+-----------------------------------------------------------------------------------+
                                          |
                    +---------------------+---------------------+
                    |                                           |
       [DMARC PASS: >= 1 Condition Met]             [DMARC FAIL: 0 Conditions Met]
                    v                                           v
+-----------------------------------------+   +-------------------------------------+
| FINAL VERDICT: ACCEPT / VERIFIED        |   | INSPECT SENDER DOMAIN DMARC POLICY: |
| - Message authenticated and aligned     |   | • p=reject:     DROP / BOUNCE (550) |
| - Cryptographic origin guaranteed       |   | • p=quarantine: DIVERT TO SPAM/JUNK |
| - Route directly to Recipient Inbox     |   | • p=none:       FLAG & DELIVER      |
+-----------------------------------------+   +-------------------------------------+"""

    t_flow = Table([[Preformatted(flowchart_text, code_block_style)]], colWidths=[504])
    t_flow.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#2D3748")),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor("#68D391")),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_flow)
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------
    # EXPERIMENTAL VERIFICATION & TEST CASE AUDIT
    # -----------------------------------------------------------------
    story.append(Paragraph("4. Experimental Verification & Test Case Audit", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceAfter=6, spaceBefore=0))

    story.append(Paragraph(
        "To rigorously validate the gateway CLI, four comprehensive test scenarios representing real-world attack vectors "
        "and legitimate routing architectures were executed and audited. The outcomes are detailed below:",
        body_style
    ))

    # Test Results Comparison Table
    test_headers = [
        Paragraph("<b>Scenario & File</b>", table_header_style),
        Paragraph("<b>SPF Status</b>", table_header_style),
        Paragraph("<b>DKIM Status</b>", table_header_style),
        Paragraph("<b>Alignment Matrix</b>", table_header_style),
        Paragraph("<b>Gateway Verdict</b>", table_header_style),
    ]
    test_rows = [
        [
            Paragraph("<b>Case 1: Legitimate</b><br/><code>sample_legit_header.txt</code>", table_cell_style),
            Paragraph("<font color='#276749'><b>PASS</b></font><br/>IP: 198.51.100.25", table_cell_style),
            Paragraph("<font color='#276749'><b>PASS</b></font><br/>d=securebank.com", table_cell_style),
            Paragraph("SPF: Aligned (Strict)<br/>DKIM: Aligned (Strict)", table_cell_style),
            Paragraph("<font color='#276749'><b>[VERIFIED / PASS]</b></font><br/>Accept to Inbox", table_cell_bold),
        ],
        [
            Paragraph("<b>Case 2: Spoofed CEO</b><br/><code>sample_spoofed_header.txt</code>", table_cell_style),
            Paragraph("<font color='#9B2C2C'><b>FAIL</b></font><br/>IP: 203.0.113.88", table_cell_style),
            Paragraph("<font color='#9B2C2C'><b>NONE</b></font><br/>No Signature", table_cell_style),
            Paragraph("SPF: Ineligible (Failed)<br/>DKIM: Ineligible (None)", table_cell_style),
            Paragraph("<font color='#9B2C2C'><b>[REJECTED]</b></font><br/>Drop Message (p=reject)", table_cell_bold),
        ],
        [
            Paragraph("<b>Case 3: Forwarded</b><br/><code>sample_forwarded_header.txt</code>", table_cell_style),
            Paragraph("<font color='#B7791F'><b>SOFTFAIL</b></font><br/>IP: 192.0.2.77", table_cell_style),
            Paragraph("<font color='#276749'><b>PASS</b></font><br/>d=newsletter.dev.io", table_cell_style),
            Paragraph("SPF: Unaligned (Mailing List)<br/>DKIM: Aligned (Strict)", table_cell_style),
            Paragraph("<font color='#276749'><b>[VERIFIED / PASS]</b></font><br/>DKIM Rescued Delivery", table_cell_bold),
        ],
        [
            Paragraph("<b>Case 4: Misaligned</b><br/><code>sample_misaligned_header.txt</code>", table_cell_style),
            Paragraph("<font color='#276749'><b>PASS</b></font><br/>bounces@sendgrid.net", table_cell_style),
            Paragraph("<font color='#276749'><b>PASS</b></font><br/>d=sendgrid.net", table_cell_style),
            Paragraph("SPF: Unaligned (Mismatch)<br/>DKIM: Unaligned (Mismatch)", table_cell_style),
            Paragraph("<font color='#9B2C2C'><b>[REJECTED]</b></font><br/>Drop (From: paypal.com)", table_cell_bold),
        ],
    ]
    t_test = Table([test_headers] + test_rows, colWidths=[120, 85, 95, 104, 100])
    t_test.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('INNERGRID', (0,0), (-1,-1), 0.5, c_border),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
    ]))
    story.append(t_test)
    story.append(Spacer(1, 10))

    # Analytical Deep-Dive on Test Cases
    story.append(Paragraph("Key Empirical Findings from Test Scenarios:", h2_style))
    story.append(Paragraph(
        "<b>1. Resilience in Mailing Lists (Case 3):</b> Traditional SPF fails when an email is re-routed through a "
        "relay or mailing list because the connecting IP becomes that of the forwarder. However, because DKIM signs "
        "the immutable message body and headers, its signature survives unaltered. Under DMARC, DKIM alignment successfully "
        "validates the transmission, ensuring legitimate newsletters and forwarded messages are not lost.<br/>"
        "<b>2. Neutralizing Cloud Relay Spoofing (Case 4):</b> Sophisticated phishing attackers frequently purchase legitimate "
        "cloud relay services (e.g., SendGrid, Mailgun) and forge high-value executive brands in the visible <code>From:</code> header. "
        "While SPF passes for the relay server IP and DKIM passes for the relay provider, DMARC detects the fundamental "
        "discrepancy between <code>d=sendgrid.net</code> and <code>From: service@paypal.com</code>, executing a hard drop.",
        body_style
    ))
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------
    # SCRIPT IMPLEMENTATION & CLI FEATURES
    # -----------------------------------------------------------------
    story.append(Paragraph("5. CLI Gateway Implementation & Operational Usage", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceAfter=6, spaceBefore=0))

    story.append(Paragraph(
        "The gateway CLI application (<code>email_auth_gateway.py</code>) provides an intuitive, high-performance command interface "
        "engineered in pure Python 3 utilizing standard email parsing libraries and <code>cryptography</code> for hardware-accelerated "
        "RSA operations.",
        body_style
    ))

    cmd_guide = [
        [
            Paragraph("<b>CLI Command & Subparser</b>", table_header_style),
            Paragraph("<b>Operational Description & Key Flags</b>", table_header_style),
            Paragraph("<b>Expected Output Artifacts</b>", table_header_style),
        ],
        [
            Paragraph("<code>generate-dns</code>", table_cell_bold),
            Paragraph("Generates 2048-bit RSA key pair and builds ready-to-deploy DNS TXT records.<br/>"
                      "Flags: <code>--domain &lt;domain&gt;</code>, <code>--selector &lt;id&gt;</code>, <code>--ip &lt;ip&gt;</code>", table_cell_style),
            Paragraph("Private/Public PEM files in <code>keys/</code> and standard + BIND chunked TXT formats.", table_cell_style),
        ],
        [
            Paragraph("<code>parse-headers</code>", table_cell_bold),
            Paragraph("Ingests raw email header text, extracts RFC 8601 results, and audits alignment.<br/>"
                      "Flags: <code>--file &lt;path&gt;</code>, <code>--no-color</code>", table_cell_style),
            Paragraph("Diagnostic terminal table with protocol scores, alignment matrix, and verdict.", table_cell_style),
        ],
        [
            Paragraph("<code>run-tests</code>", table_cell_bold),
            Paragraph("Generates all 4 real-world test cases on disk and executes end-to-end verification.<br/>"
                      "Flags: <code>--output-dir &lt;dir&gt;</code>", table_cell_style),
            Paragraph("Automated batch verification of Legit, Spoofed, Forwarded, and Misaligned emails.", table_cell_style),
        ],
    ]
    t_cmd = Table(cmd_guide, colWidths=[100, 254, 150])
    t_cmd.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_secondary),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('INNERGRID', (0,0), (-1,-1), 0.5, c_border),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
    ]))
    story.append(t_cmd)
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------
    # DNS RECORD SPECIFICATIONS GENERATED
    # -----------------------------------------------------------------
    story.append(Paragraph("6. Exact DNS TXT Record Reference Output", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceAfter=6, spaceBefore=0))

    story.append(Paragraph(
        "Below are the actual DNS TXT records generated by the gateway for production deployment on <code>securebank.com</code>:",
        body_style
    ))

    dns_sample_code = """;; 1. SPF Record [RFC 7208] - Host: @ (securebank.com)
;; Recommended Hardfail Enforcement:
v=spf1 mx a ip4:198.51.100.25 include:_spf.securebank.com -all

;; 2. DKIM Record [RFC 6376] - Host: mail2026._domainkey.securebank.com
;; Standard Web Dashboard Single-Line Format:
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8LCym+Jj57Q2XScZ3R884wuB0RkY1tNMVqqWp1/knx7mUH9dMN75lmxydGvgnYjqyXkHpQ1bOva+fvcVy3eS8DGmKgZc7zIB+U/XzKj8oeNByZOBBeoxLjDeVYj/WuihxF5YSvAQZM5ZcymydVpQNNYF+zCoIKJlh6XtbdCGwMaX/7UQjBTWUVItk4Ray0kxCIQnsabniROrj0GRlYo6sMn2w/bQ08Sp/JYcULaroADa54NC+BWIvAeW/0GT+2XiyFVv1BVjHY8wGhypnTzvZTytZXyMgV1VUTBeY1/6T1wY7INsiUVCj/lQtcRBWPKmZfhEJzFGt37sUNJKa8hPzQIDAQAB

;; BIND Zone File Chunked Format (<=255 Characters):
"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8LCym+Jj57Q2XScZ3R884wuB0RkY1tNMVqqWp1/knx7mUH9dMN75lmxydGvgnYjqyXkHpQ1bOva+fvcVy3eS8DGmKgZc7zIB+U/XzKj8oeNByZOBBeoxLjDeVYj/WuihxF5YSvAQZM5ZcymydVpQNNYF+zCoIKJlh6XtbdCGwMaX/7UQjBTWUVItk4Ra" "y0kxCIQnsabniROrj0GRlYo6sMn2w/bQ08Sp/JYcULaroADa54NC+BWIvAeW/0GT+2XiyFVv1BVjHY8wGhypnTzvZTytZXyMgV1VUTBeY1/6T1wY7INsiUVCj/lQtcRBWPKmZfhEJzFGt37sUNJKa8hPzQIDAQAB"

;; 3. DMARC Phased Records [RFC 7489] - Host: _dmarc.securebank.com
;; Phase 1 (Monitoring):
v=DMARC1; p=none; rua=mailto:dmarc-reports@securebank.com; ruf=mailto:dmarc-forensics@securebank.com; pct=100; sp=none; aspf=r; adkim=r

;; Phase 2 (Quarantine):
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@securebank.com; ruf=mailto:dmarc-forensics@securebank.com; sp=quarantine; aspf=r; adkim=r

;; Phase 3 (Strict Enforcement):
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@securebank.com; ruf=mailto:dmarc-forensics@securebank.com; sp=reject; aspf=s; adkim=s"""

    t_dns_box = Table([[Preformatted(dns_sample_code, code_block_style)]], colWidths=[504])
    t_dns_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#EDF2F7")),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_dns_box)
    story.append(Spacer(1, 14))

    # -----------------------------------------------------------------
    # COMPLETE SOURCE CODE APPENDIX
    # -----------------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("7. Complete Source Code: email_auth_gateway.py", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceAfter=8, spaceBefore=0))
    story.append(Paragraph(
        "The following listing contains the full, production-tested source code of the Secure Email Authentication Gateway CLI application:",
        body_style
    ))

    # Read the full source code of email_auth_gateway.py
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "email_auth_gateway.py")
    if os.path.exists(script_path):
        with open(script_path, "r", encoding="utf-8") as f:
            full_code = f.read()
    else:
        full_code = "# Source file email_auth_gateway.py"

    # Chunk source code to prevent ReportLab single-cell overflow
    code_lines = full_code.splitlines()
    chunk_size = 50
    for i in range(0, len(code_lines), chunk_size):
        chunk_text = "\n".join(code_lines[i:i + chunk_size])
        t_chunk = Table([[Preformatted(chunk_text, code_block_style)]], colWidths=[504])
        t_chunk.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F7FAFC")),
            ('BOX', (0,0), (-1,-1), 0.5, c_border),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_chunk)
        story.append(Spacer(1, 4))

    # -----------------------------------------------------------------
    # CONCLUSION & SECURITY DIRECTIVES
    # -----------------------------------------------------------------
    story.append(Spacer(1, 10))
    story.append(Paragraph("8. Conclusion & Future Hardening Recommendations", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceAfter=6, spaceBefore=0))
    story.append(Paragraph(
        "The implementation and evaluation of the Secure Email Authentication Gateway confirm that modern email security "
        "is fundamentally dependent on the synchronized alignment of SPF, DKIM, and DMARC. By migrating from passive "
        "monitoring (<code>p=none</code>) to active rejection (<code>p=reject</code>), organizations completely eradicate "
        "direct-domain spoofing attacks. For defense-in-depth, production enterprise environments should augment this gateway "
        "with <b>MTA-STS (RFC 8461)</b> to mandate TLS encryption in transit, <b>TLS-RPT (RFC 8460)</b> for cipher downgrade telemetry, "
        "and <b>BIMI (Brand Indicators for Message Identification)</b> to render cryptographically verified brand logos directly in recipient clients.",
        body_style
    ))

    # Build Document with NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF successfully generated: {filename}")


if __name__ == "__main__":
    build_pdf()
