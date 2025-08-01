# <p align="center"> Website Breach Investigation & OS Hardening </p>

## Overview

As part of a simulated incident response process, I was provided with network traffic data from a website to analyse an attack. I examined the tcpdump output to identify the network protocols used in the compromise, documented the traffic analysis, and suggested security measures to prevent similar incidents in the future.

## Scenario

A client reported that their website, yummyrecipesforme.com, which sells recipes and cookbooks, had become inaccessible. Users were prompted to download a file which, when executed, redirected them to another website.

<details>
<summary><strong>Read full scenario</strong></summary>

You are a cybersecurity analyst for yummyrecipesforme.com, a website that sells recipes and cookbooks. A former employee has decided to lure users to a fake website with malware. 

The former employee/ hacker executed a brute force attack to gain access to the web host. They repeatedly entered several known default passwords for the administrative account until they correctly guessed the right one. After they obtained the login credentials, they were able to access the admin panel and change the website’s source code. They embedded a JavaScript function in the source code that prompted visitors to download and run a file upon visiting the website. After embedding the malware, the hacker changed the password to the administrative account. When customers download the file, they are redirected to a fake version of the website that contains the malware. 

Several hours after the attack, multiple customers emailed yummyrecipesforme’s helpdesk. They complained that the company’s website had prompted them to download a file to access free recipes. The customers claimed that, after running the file, the address of the website changed and their personal computers began running more slowly. 

In response to this incident, the website owner tries to log in to the admin panel but is unable to, so they reach out to the website hosting provider. You and other cybersecurity analysts are tasked with investigating this security event.

To address the incident, you create a sandbox environment to observe the suspicious website behavior. You run the network protocol analyzer tcpdump, then type in the URL for the website, yummyrecipesforme.com. As soon as the website loads, you are prompted to download an executable file to update your browser. You accept the download and allow the file to run. You then observe that your browser redirects you to a different URL, greatrecipesforme.com, which contains the malware.  

A senior analyst confirms that the website was compromised. The analyst checks the source code for the website. They notice that javascript code had been added to prompt website visitors to download an executable file. Analysis of the downloaded file found a script that redirects the visitors’ browsers from yummyrecipesforme.com to greatrecipesforme.com. 

The cybersecurity team reports that the web server was impacted by a brute force attack. The disgruntled hacker was able to guess the password easily because the admin password was still set to the default password. Additionally, there were no controls in place to prevent a brute force attack. 

Your job is to document the incident in detail, including identifying the network protocols used to establish the connection between the user and the website.  You should also recommend a security action to take to prevent brute force attacks in the future.

</details>

---

<br>

```
14:18:32.192571 IP your.machine.52444 > dns.google.domain: 35084+ A?
yummyrecipesforme.com. (24)
14:18:32.204388 IP dns.google.domain > your.machine.52444: 35084 1/0/0 A
203.0.113.22 (40)

14:18:36.786501 IP your.machine.36086 > yummyrecipesforme.com.http: Flags
[S], seq 2873951608, win 65495, options [mss 65495,sackOK,TS val 3302576859
ecr 0,nop,wscale 7], length 0
14:18:36.786517 IP yummyrecipesforme.com.http > your.machine.36086: Flags
[S.], seq 3984334959, ack 2873951609, win 65483, options [mss 65495,sackOK,TS
val 3302576859 ecr 3302576859,nop,wscale 7], length 0
14:18:36.786529 IP your.machine.36086 > yummyrecipesforme.com.http: Flags
[.], ack 1, win 512, options [nop,nop,TS val 3302576859 ecr 3302576859],
length 0
14:18:36.786589 IP your.machine.36086 > yummyrecipesforme.com.http: Flags
[P.], seq 1:74, ack 1, win 512, options [nop,nop,TS val 3302576859 ecr
3302576859], length 73: HTTP: GET / HTTP/1.1
14:18:36.786595 IP yummyrecipesforme.com.http > your.machine.36086: Flags
[.], ack 74, win 512, options [nop,nop,TS val 3302576859 ecr 3302576859],
length 0
...<a lot of traffic on the port 80>...

14:20:32.192571 IP your.machine.52444 > dns.google.domain: 21899+ A?
greatrecipesforme.com. (24)
14:20:32.204388 IP dns.google.domain > your.machine.52444: 21899 1/0/0 A
192.0.2.17 (40)
14:25:29.576493 IP your.machine.56378 > greatrecipesforme.com.http: Flags
[S], seq 1020702883, win 65495, options [mss 65495,sackOK,TS val 3302989649
ecr 0,nop,wscale 7], length 0
14:25:29.576510 IP greatrecipesforme.com.http > your.machine.56378: Flags
[S.], seq 1993648018, ack 1020702884, win 65483, options [mss 65495,sackOK,TS
val 3302989649 ecr 3302989649,nop,wscale 7], length 0
14:25:29.576524 IP your.machine.56378 > greatrecipesforme.com.http: Flags
[.], ack 1, win 512, options [nop,nop,TS val 3302989649 ecr 3302989649],
length 0
14:25:29.576590 IP your.machine.56378 > greatrecipesforme.com.http: Flags
[P.], seq 1:74, ack 1, win 512, options [nop,nop,TS val 3302989649 ecr
3302989649], length 73: HTTP: GET / HTTP/1.1

14:25:29.576597 IP greatrecipesforme.com.http > your.machine.56378: Flags
[.], ack 74, win 512, options [nop,nop,TS val 3302989649 ecr 3302989649],
length 0
...<a lot of traffic on the port 80>...
```

<details>
<summary><strong>Read tcpdump explanation provided</strong></summary>

The logs show the following process:

1. The browser initiates a DNS request: It requests the IP address of the yummyrecipesforme.com URL from the DNS server.

2. The DNS replies with the correct IP address. 

3. The browser initiates an HTTP request: It requests the yummyrecipesforme.com webpage using the IP address sent by the DNS server.

4. The browser initiates the download of the malware.

5. The browser initiates a DNS request for greatrecipesforme.com.

6. The DNS server responds with the IP address for greatrecipesforme.com.

7. The browser initiates an HTTP request to the IP address for greatrecipesforme.com.

</details>

---

## Security incident report

### Section 1: Identify the network protocol involved in the incident

The logs show
1. A DNS query was initiated from your.machine on port 52444 to resolve the domain yummyrecipesforme.com. The DNS server returned the correct IP address (203.0.113.22) of the domain.
2. A TCP handshake was successfully established between your.machine on port 36086 and yummyrecipesforme.com on port 80 (HTTP).
3. A GET request was made over HTTP/1.1 to retrieve data from the website.
4. A lot of traffic on the port 80 followed, indicating content transfer, possibly including a malicious JavaScript that triggered the download.
5. After the file was executed, another DNS query was made to resolve greatrecipesforme.com. The DNS returned with a new IP 192.0.2.17.
6. A new TCP connection was established with greatrecipesforme.com over port 80 (HTTP).

These logs indicate the use of DNS, TCP and HTTP as the protocols involved in the redirection of the website.

---

### Section 2: Document the incident

The incident occurred at 2:18 PM. 
Several customers emailed yummyrecipesforme’s helpdesk, complaining that the website prompted them to download a file in exchange for free recipes. After running the file, the website address changed, and computers began to slow down. 

The website was tested in a sandbox environment. Packet analysis confirmed that as soon as the yummyrecipesforme.com website loaded, users were prompted to download a file. When the file is downloaded, users were redirected to greatrecipesforme.com, a malicious site.
The source code had been modified to include malicious JavaScript prompting this behaviour. The downloaded file contained a script that redirectwd the browser from yummyrecipesforme.com to greatrecipesforme.com, a malicious website. 

The attacker gained access via a brute-force attack, exploiting the default admin password. No security controls were in place to detect or block repeated login attempts.

The cause of the incident was a weak password and lack of brute-force protection. The attacker altered the site’s source code to inject malware and redirect users to a fake website.

---

### Section 3: Recommended remediation for brute force attacks

- Enforce strict password policies, including minimum length, complexity and expiration requirements.
- Enable Multi-Factor Authentication (MFA) or Two-Factor Authentication (2FA).
- Implement account lockouts or rate limiting after a defined number of failed login attempts.
- Use CAPTCHA or reCAPTCHA to block automated login attempts.

---