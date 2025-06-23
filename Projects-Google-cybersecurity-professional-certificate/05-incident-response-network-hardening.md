# <p align="center"> Social Media Data Breach Investigation & Response </p>

## Overview

As part of a simulated incident response for a social media organization that experienced a major data breach, I reviewed the breach scenario and proposed several network hardening tools and methods to strengthen the organization’s security posture. I also created a security risk assessment report to analyze the vulnerabilities and outline practical steps to prevent future incidents.

## Scenario

A social media company recently experienced a major data breach that compromised customers' personally identifiable information (PII). The breach was caused by undetected vulnerabilities in the network. Upon inspection, four major vulnerabilities were identified. The organization now seeks to implement strong network hardening practices to prevent future breaches.

<details>
<summary><strong>Read full scenario</strong></summary>

You are a security analyst working for a social media organization. The organization recently experienced a major data breach, which compromised the safety of their customers’ personal information, such as names and addresses. Your organization wants to implement strong network hardening practices that can be performed consistently to prevent attacks and breaches in the future. 

After inspecting the organization’s network, you discover four major vulnerabilities. The four vulnerabilities are as follows:

The organization’s employees' share passwords.

The admin password for the database is set to the default.

The firewalls do not have rules in place to filter traffic coming in and out of the network.

Multifactor authentication (MFA) is not used. 

If no action is taken to address these vulnerabilities, the organization is at risk of experiencing another data breach or other attacks in the future. 

In this activity, you will write a security risk assessment to analyze the incident and explain what methods can be used to further secure the network.

</details>

---

## Security risk assessment report

### Part 1: Hardening tools and methods to implement

There were four major vulnerabilities identified: employees' share passwords, the admin password for the database is set to the default, the firewalls lack rules to filter inbound and outbound traffic, multifactor authentication (MFA) is not implemented.

To address these issues, the organization can implement three hardening tools and practices :

- **Enforce strict password policies**
- **Implement Multi-Factor Authentication (MFA)** or Two-Factor Authentication (2FA)
- **Regularly configure and maintain firewalls** 

Password policies should include a minimum length, complexity and expiration requirements, and restrictions on password reuse and sharing. They can also enforce account lockouts or rate limiting after a defined number of failed login attempts.

MFA adds an additional layer to verify a user's identity. Some methods include passwords, PINs, smart ID cards, or biometric scans.

Firewalls should be configured and maintained regularly. Configuration should include port filtering and deny-listing suspicious or spoofed IP addresses. Firewalls should also block any sender address that matches the internal private network, preventing external attacks that attempt to impersonate trusted sources. Wireless protocols should be kept up to date, and outdated or unused protocols should be disabled.

---

### Part 2: Recommendations explained

Enforcing a strict password policy helps prevent reuse and sharing, and ensures all default passwords are replaced. These policies make it more difficult for attackers to gain unauthorized access. Lockouts and delays after failed login attempts can stall or prevent brute force attacks.

MFA or 2FA adds a critical layer of security, making it significantly harder for unauthorized users to gain access, even if a password is compromised. It also discourages password sharing among employees.

Firewalls should be configured to deny suspicious traffic and block spoofed IP addresses attempting to mimic internal network addresses. Network administrators should ensure that firewall rules align with best practices for filtering malicious traffic. All outdated or unused protocols should be disabled to reduce potential attack surfaces.

---

## Supporting materials
[Network hardening tools](https://docs.google.com/spreadsheets/d/1G1gSxuCyKTNmc1zPKzB7ETNdL7HkhB_QIHGZJ8aZkSk/template/preview)

---