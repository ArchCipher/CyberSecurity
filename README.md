# Cybersecurity Portfolio

Welcome to my cybersecurity portfolio. This repository documents my learning journey, hands-on labs, and personal projects as I transition into cybersecurity from a background in architectural design.

---

## About Me

I’m a detail-oriented entry-level cybersecurity professional transitioning from a background in architectural design. I bring over five years of experience solving complex design challenges and working in cross-functional, international teams. I'm currently pursuing the Google Cybersecurity Certificate, with training in threat detection, SIEM tools, and incident response. My architectural work sharpened my skills in compliance, systems thinking, and conflict resolution—strengths I now apply to digital security.

I’m passionate about building thoughtful, security-first solutions to protect users, data, and systems.

---

## Skills and Tools
- Security Frameworks: NIST, CIS Controls  
- Risk Analysis & Security Auditing  
- Network Scanning & Analysis: Nmap, tcpdump  
- Operating Systems: Linux (basic)  
- Web Security Testing: Burp Suite (basic), OWASP Top 10 concepts 

---

## CTF Challenges
Linux & Security concepts: OverTheWire - Bandit Level 12 
This challenge covers essential security concepts like file manipulation, encoding/decoding, and using Linux commands for security purposes.  
[Read write-up here](/ctf-overthewire-bandit.md)

---

## [Google Cybersecurity Professional Certificate](https://www.coursera.org/professional-certificates/google-cybersecurity)
**In Progress** - Expected Completion : July 2025

**Focus Areas:**
- Security auditing, network traffic analysis, and risk assessment (completed)  
- Linux & SQL for security operations, Python automation (in progress)  
- SIEM tools and IDS/IPS fundamentals (in progress) 

**Notable Labs & Projects:**
1. [Simulated Cybersecurity Audit](/Projects-Google-cybersecurity-professional-certificate/01-cybersecurity-audit.md)
2. [DNS & ICMP Traffic Analysis](/Projects-Google-cybersecurity-professional-certificate/02-dns-icmp-traffic-analysis.md)
3. [SYN Flood Attack Analysis & Incident Report](/Projects-Google-cybersecurity-professional-certificate/03-syn-flood-incident-report.md)
4. [OS Hardening: Brute Force Mitigation](/Projects-Google-cybersecurity-professional-certificate/04-os-hardening-brute-force.md)
5. [Incident Response & Network Hardening](/Projects-Google-cybersecurity-professional-certificate/05-incident-response-network-hardening.md)
6. [NIST CSF-Based Incident Report](/Projects-Google-cybersecurity-professional-certificate/06-nist-csf-incident-report.md)
7. [Linux Authorization and Least Privilege Hardening](/Projects-Google-cybersecurity-professional-certificate/07-linux-authorization-permission-hardening)
8. [Linux User Management and Access Control](/Projects-Google-cybersecurity-professional-certificate/08-linux-user-management-access-control.md)

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