# Cybersecurity Portfolio

Welcome to my cybersecurity portfolio. This repository documents my learning journey, hands-on labs, and personal projects as I transition into cybersecurity from a background in architectural design.

---

## About Me

I'm a detail-oriented entry-level cybersecurity professional transitioning from a background in architectural design. I bring over five years of experience solving complex design challenges and working in cross-functional, international teams. I'm currently pursuing the Google Cybersecurity Certificate, with training in threat detection, SIEM tools, and incident response. My architectural work sharpened my skills in compliance, systems thinking, and conflict resolution—strengths I now apply to digital security.

I'm passionate about building thoughtful, security-first solutions to protect users, data, and systems.

---

## Skills and Tools
- Security Frameworks: NIST, CIS Controls  
- Risk Assessment and Auditing: Risk analysis, system hardening, security controls
- Network Analysis: Nmap, tcpdump, traffic analysis  
- Operating Systems & Scripting: Linux (Bash/ Zsh), basic Python for automation
- Databases: SQL for log querying and incident detection
- SIEM & Threat Detection Tools: Splunk, Google SecOps, Suricata
- Web Security Testing: Burp Suite (basic), OWASP Top 10 (concepts)

---

## CTF Challenges
OverTheWire: Bandit - Completed (Level 32)
Linux security fundamentals: file manipulation, SSH authentication, privilege escalation, Git security, and shell scripting. Advanced techniques include cron job exploitation, restricted shell bypasses, and brute-force automation.  
[Read write-up here](/ctf-overthewire-bandit.md)

OverTheWire: Leviathan - Level 2

---

## Web Security Academy:PortSwigger
**SQL injection** -In Progress

Notable Labs:
1. [UNION Attack: Retrieve Data](/PortSwigger-web-security-academy/SQL-injection/05-sqli-union-attack.md)
2. [Database Enumeration & Schema Discovery](/PortSwigger-web-security-academy/SQL-injection/08-sqli-list-contents.md)
3. [Blind SQL Injection with Conditional Responses](/PortSwigger-web-security-academy/SQL-injection/09-blind-sqli.md)

---

## [Google Cybersecurity Professional Certificate](https://www.coursera.org/professional-certificates/google-cybersecurity)

**All Projects & Labs by Domain:**

*Security Assessments & Risk Management*
- [Cybersecurity Audit & Assessment](/Projects-Google-cybersecurity-professional-certificate/01-cybersecurity-audit.md)
- [E-commerce Vulnerability Assessment](/Projects-Google-cybersecurity-professional-certificate/17-vulnerability-assessement.md)
- [Commercial Bank Risk Assessment (NIST CSF-based)](/Projects-Google-cybersecurity-professional-certificate/12-nist-csf-risk-assessment.md)
- [Healthcare USB Drive Threat Vectors & Risk Analysis](/Projects-Google-cybersecurity-professional-certificate/18-usb-threat-vectors-risk-analysis.md)
- [Home Business Asset Inventory & Classification](/Projects-Google-cybersecurity-professional-certificate/11-asset-management.md)
- [Mobile App Threat Modelling- PASTA](/Projects-Google-cybersecurity-professional-certificate/19-threat-modelling-PASTA.md)

*Incident Response & Network Forensics*
- [SYN Flood Attack Investigation & Incident Analysis](/Projects-Google-cybersecurity-professional-certificate/03-syn-flood-incident-report.md)
- [Website Breach Investigation & OS Hardening](/Projects-Google-cybersecurity-professional-certificate/04-os-hardening-brute-force.md)
- [Network Protocol Investigation & Traffic Analysis](/Projects-Google-cybersecurity-professional-certificate/02-dns-icmp-traffic-analysis.md)
- [Social Media Data Breach Investigation & Response](/Projects-Google-cybersecurity-professional-certificate/05-incident-response-network-hardening.md)
- [Data Breach Investigation & Response (NIST CSF-based)](/Projects-Google-cybersecurity-professional-certificate/06-nist-csf-incident-report.md)
- [Multi-Scenario Incident Response & Documentation](/Projects-Google-cybersecurity-professional-certificate/20-incident-response.md)
- [Suricata Log Analysis & Alert Examination](/Projects-Google-cybersecurity-professional-certificate/21-suricata-alert-analysis.md)

*Access Control & Identity Management*
- [Financial Fraud Investigation & Access Control Analysis](/Projects-Google-cybersecurity-professional-certificate/16-AAA-small-business.md)
- [Linux Security Audit & Permission Hardening](/Projects-Google-cybersecurity-professional-certificate/07-linux-authorization-permission-hardening.md)
- [Linux User Management & Access Control](/Projects-Google-cybersecurity-professional-certificate/08-linux-user-management-access-control.md)
- [Data Leak Investigation (NIST CSF-based)](/Projects-Google-cybersecurity-professional-certificate/13-nist-csf-data-handling.md)

*Database Security & Digital Forensics*
- [SQL for Cybersecurity: Filtering and Forensics](/Projects-Google-cybersecurity-professional-certificate/09-sql-filtering.md)
- [SQL for Cybersecurity: Joins and Forensics](/Projects-Google-cybersecurity-professional-certificate/10-sql-joins.md)
- [Decryption with OpenSSL: Caesar to AES](/Projects-Google-cybersecurity-professional-certificate/14-decryption-cipher.md)
- [Digital Forensics & File Integrity Analysis](/Projects-Google-cybersecurity-professional-certificate/15-hash-detect-tampering.md)

*Security Automation & Programming*
- [Python Loops for Security Automation](/Projects-Google-cybersecurity-professional-certificate/22-python-loops.md)
- [Python Functions for Security Analysis](/Projects-Google-cybersecurity-professional-certificate/23-python-function.md)
- [Python String Manipulation for Security Analysis](/Projects-Google-cybersecurity-professional-certificate/24-python-strings.md)
- [Python Algorithm for User-Device Authentication](/Projects-Google-cybersecurity-professional-certificate/25-python-algorithm.md)
- [Python Regular Expressions for Security Analysis](/Projects-Google-cybersecurity-professional-certificate/26-python-regular-expressions.md)
- [Python File Import and Parsing for Security Analysis](/Projects-Google-cybersecurity-professional-certificate/27-python-import-parse-files.md)
- [Python Algorithm for Access Control Management](/Projects-Google-cybersecurity-professional-certificate/28-python-algorithm2.md)

---

## Hands-On Network Security Labs (Unix Terminal)

### 1. Local Network Discovery & Scanning

- __Objective :__ Identify devices on the local network and assess their connectivity.

- __Tools :__ Terminal, `ifconfig`,`ipconfig`,`arp`, `ping`, `nmap`, `lsof`

- __What I Did:__
* Found my own IP and MAC address using `ipconfig` and `ifconfig`.

* Used `arp -a` to list IP–MAC mappings of known devices on the network.

* Verified network connectivity using `ping <IP>`.

* Performed `nmap` scans (`-sS`, `-sV`, `-O`, `-p-`) to detect open ports, running services, and OS info.

* Used `lsof` to inspect open ports.

- __Outcome :__ Gained hands-on experience in internal network mapping and reconnaissance. Learned how to correlate IPs, MACs, and services across multiple tools.

### 2. tcpdump Packet Capture

- __Objective :__ Capture and analyze network packets to understand real-time traffic flow and TCP handshakes.

- __Tools :__ Terminal, `tcpdump`

- __What I Did:__

* Captured live traffic on specific interfaces and filtered by protocol, port, or IP.

* Analyzed SYN, SYN-ACK, ACK, FIN flags to understand the TCP 3-way handshake and session closures.

* Practiced using filters to isolate HTTP, DNS, and ICMP traffic.

- __Outcome :__ Developed a foundational understanding of packet structures and learned to isolate and analyze network issues using tcpdump.

---

## Notes & References
[An introduction to using tcpdump at the Linux command line](https://opensource.com/article/18/10/introduction-tcpdump)

[How to Capture and Analyze Network Traffic with tcpdump?](https://geekflare.com/cloud/tcpdump-examples/)

[Masterclass – Tcpdump – Interpreting Output](https://packetpushers.net/blog/masterclass-tcpdump-interpreting-output/)

---