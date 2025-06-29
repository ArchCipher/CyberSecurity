# <p align="center"> Multi-Scenario Incident Response & Documentation </p>

## Project Overview

This project documents a series of security incidents I reviewed and analyzed using the structured format of an incident handler’s journal. Each entry includes an overview of the event, key investigative findings, and incident response actions.

---

## Scenario 1

A small U.S. health care clinic specializing in delivering primary-care services experienced a security incident on a Tuesday morning, at approximately 9:00 a.m. Several employees reported that they were unable to use their computers to access files like medical records. Business operations shut down because employees were unable to access the files and software needed to do their job.

Additionally, employees also reported that a ransom note was displayed on their computers. The ransom note stated that all the company's files were encrypted by an organized group of unethical hackers who are known to target organizations in healthcare and transportation industries. In exchange for restoring access to the encrypted files, the ransom note demanded a large sum of money in exchange for the decryption key. 

The attackers were able to gain access into the company's network by using targeted phishing emails, which were sent to several employees of the company. The phishing emails contained a malicious attachment that installed malware on the employee's computer once it was downloaded.

Once the attackers gained access, they deployed their ransomware, which encrypted critical files. The company was unable to access critical patient data, causing major disruptions in their business operations. The company was forced to shut down their computer systems and contact several organizations to report the incident and receive technical assistance.

---

## Incident Handler's Journal

**Date:**
26 June 2025

**Entry:**
#1

**Description:**
Ransomware attack through phishing email in a U.S. health care clinic.

**Tool(s) used:**
None

**The 5 W's:**

- **Who:** Unkown cybercriminal group
- **What:** Ransomware attack via phishing email
- **When:** 24 June 2025, 9:00 AM
- **Where:** A small U.S. health care clinic
- **Why:** Financially motivated extortion through data encryption and ransom demand

**Next steps:**
- Determine if recent backups exist and assess recovery options
- Investigate HIPAA compliance implications and initiate breach notification, if applicable
- Implement phishing awareness training and email filtering improvements

**Additional notes:**
- How many critical files were encrypted?
- Should they pay the ransom?

---

## Scenario 2

You are a level one security operations center (SOC) analyst at a financial services company. You have received an alert about a suspicious file being downloaded on an employee's computer. 

You investigate this alert and discover that the employee received an email containing an attachment. The attachment was a password-protected spreadsheet file. The spreadsheet's password was provided in the email. The employee downloaded the file, then entered the password to open the file. When the employee opened the file, a malicious payload was then executed on their computer. 

<details>
<summary><strong>Read full scenario</strong></summary>

You retrieve the malicious file and create a SHA256 hash of the file. Now that you have the file hash, you will use VirusTotal to uncover additional IoCs that are associated with the file.

The following information contains details about the alert:

SHA256 file hash: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b

Here is a timeline of the events leading up to this alert:

1:11 p.m.: An employee receives an email containing a file attachment.
1:13 p.m.: The employee successfully downloads and opens the file.
1:15 p.m.: Multiple unauthorized executable files are created on the employee's computer.
1:20 p.m.: An intrusion detection system detects the executable files and sends out an alert to the SOC.

</details>

---

## Incident Handler's Journal

**Date:**
27 June 2025

**Entry:**
#2

**Description:**
Phishing email - malicious file downloaded

**Tool(s) used:**
VirusTotal

**The 5 W's:**

- **Who:** Unknown threat actor(s)
- **What:** Phishing email conatining a password-protected malicious attachment
- **When:** 27 June 2025, 1:11 PM (email received), 1:13 PM (file opened), 1:15 PM (executables created), 1:20 (IDS alert)
- **Where:** An employee's computer at a financial services company
- **Why:** The intent appears to be reconnaissance or data theft. The malware was a Trojan with backdoor capabilities.

**Malware Analysis Summary:**
- SHA-256: `54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b`
- VirusTotal detection: 60/72
- Community score: –256 (flagged as malicious)
- Malware: FlagPro, associated with BlackTech APT group
- Type: Trojan with backdoor functionality targeting Windows (Intel 386 architecture)
- Target architecture: Intel 386 or compatible (typical for 32-bit Windows PE files).

**Indicators of compromise:**

| IOC/ Behavior | Category | Pyramid of pain |
|---------------|----------|-----------------|
| MD5: `287d612e29b71c90aa54947313810a25` | Hash values | Trivial |
| `104.115.151.81` | IP address | Easy |
| `a.sinkhole.yourtrap.com` | Domain name | Simple |
| User-Agent: `Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko` <br> SNI: `ssl.gstatic.com` <br> JA3 : `28a2c9bd18a11de089ef85a160da29e4`| Network artifacts | Annoying |
| Services created: `GoogleUpdaterService128.0.6597.0` <br> Registry keys set: `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\InstalledWin32AppsRevision` | Host artifacts | Annoying |
| Behaviour similarity hash (CAPE Sandbox): `0a40063e1b34e38376c7fc22513f1153` | Tool/ Behavioural Signature | Challenging |
| Execution, Persistence, Privilege escalation, Defense evasion, credential access, discovery, command and control, impact, data manipulation | Techniques, Tactics & Procedures (TTP) | Tough |

---

Supporting material used: [Phishing Playbook](https://docs.google.com/document/d/1rOSSCtLsiWVjAjTdJtWrSrvqpiXHissEAqiy5KD4Kv4/template/preview)

**Alert ticket:**

| Ticket ID | Alert Message | Severity | Details | Ticket status |
|-----------|---------------|----------|---------|---------------|
| A-2703 | SERVER-MAIL Phishing attempt possible download of malware | Medium | The user may have opened a malicious email and opened attachments or clicked links. | Escalated |

**Ticket comments:**
The phishing email was sent from "76tguyhh6tgrt7tg.su" under the name "Def Communications," while the body was signed “Clyde West.” Numerous grammatical errors were noted. The attachment `bfsvc.exe` was password-protected and launched a backdoor Trojan on execution. The incident was escalated to Level 2 SOC.

Additional information
Known malicious file hash: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b

Email:
From: Def Communications <76tguyhh6tgrt7tg.su> <114.114.114.114>
Sent: Wednesday, July 20, 2022 09:30:14 AM
To: <hr@inergy.com> <176.157.125.93>
Subject: Re: Infrastructure Egnieer role

Dear HR at Ingergy,

I am writing for to express my interest in the engineer role posted from the website.

There is attached my resume and cover letter. For privacy, the file is password protected. Use the password paradise10789 to open.

Thank you,
Clyde West

Attachment: filename="bfsvc.exe"

**Next steps:**

- Isolate the system from the network. Identify if other systems were infected.
- Block related IPs and domains and conduct a full forensic analysis.
- Review mail gateway controls to filter .exe attachments.
- Employee training on phishing attacks.

---

## Scenario 3

You are a security analyst working at the e-commerce store Buttercup Games. You've been tasked with identifying whether there are any possible security issues with the mail server. To do so, you must explore any failed SSH logins for the root account.  

---

## Incident Handler's Journal

**Date:**
29 June 2025

**Entry:**
#3

**Description:**
A coordinated, multi-stage intrusion affected the Buttercup Games' mail server (mailsv1). External brute-force attempts failed, but internal administrative accounts (djohnson, nsharpe, myuan) were used to access the system and escalate privileges to root over an 8-day period.

**Tool(s) used:**
Splunk (log analysis: SSH, sudo, su, session records)

**The 5 W's:**

- **Who:** Unknown threat actor(s). 
- **What:** Unauthorized access and root privilege escalation via internal accounts
- **When:** 27 February – 6 March 2023
- **Where:** Mail server of E-commerce store Buttercup Games (mailsv1)
- **Why:** To gain persistent root access, conduct lateral movement, and possibly exfiltrate sensitive data.

**Key Observations:**

External Brute force attempts (Failed):
- 346 failed SSH login attempts from IPs such as 141.146.8.66, 62.216.64.19, etc. to various accounts such as root, oracle, admin, mail, news, mantis between Feb 27 and Mar 7.

Internal Account Compromise (Successful):

SSH logins from internal IPs:
- djohnson: 10.3.10.46 (47 commands / 54 root sessions)
- nsharpe: 10.2.10.163 (31 commands / 37 root sessions)
- myuan: 10.1.10.172 (5 commands / 8 root sessions)

A total of 99 root sessions across all accounts, with 83 involving command executions. All 3 accounts show idential escaltion behaviour `COMMAND=/bin/su`, and opened root sessions via `su: pam_unix(su:session): session opened for user root by <user>`. 

**Tactics Observed:**
- Consistent use of `su` for escalation and repeated access patterns across all accounts
- Persistent root access
- High frequency privilege escalation
- Lateral movement
- Suspected automation or centralized control

**Next steps:**
- Reset passwords and disable SSH for all affected accounts
- Isolate mail server (mailsv1)
- Investigate home directories, session logs, and sudo history
- Escalate incident for full internal compromise review

**Additional notes:**

- Were the internal IPs compromised devices or VPN-connected hosts?
- How were passwords obtained?
- Was sensitive data accessed or exfiltrated?
- Are the 3 IPs linked to the same attacker infrastructure?
- Were the targeted accounts chosen for their administrative access?

---

## Reflection/Notes

The use of VirusTotal was most exciting, I wanted to learn more about other viruses and malware out there and would like to detect activity of malware in a controlled environment.

The Splunk log analysis helped me detect coordinated attack patterns, including privilege escalation and lateral movement. While timestamps in the sample dataset were artificial, it was still possible to identify suspicious behavior across multiple user accounts — demonstrating how attackers can blend in with legitimate internal activity.

---