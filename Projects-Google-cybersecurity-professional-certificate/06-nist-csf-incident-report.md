# <p align="center"> Data Breach Investigation & Response (NIST CSF-based) </p>

## Overview

As part of a simulated incident response, I analysed a network incident using the National Institute of Standards and Technology's Cybersecurity Framework (NIST CSF), and created an incident report.

## Scenario

A multimedia company experienced an ICMP flood DDoS attack that disrupted its internal network services. The attack exploited an unconfigured firewall, allowing the attacker to send a high volume of ICMP packets. The issue was mitigated by rate-limiting ICMP traffic, enabling IP spoofing checks, and implementing network monitoring tools and an IDS/IPS solution.

<details>
<summary><strong>Read full scenario</strong></summary>

You are a cybersecurity analyst working for a multimedia company that offers web design services, graphic design, and social media marketing solutions to small businesses. Your organization recently experienced a DDoS attack, which compromised the internal network for two hours until it was resolved.

During the attack, your organization’s network services suddenly stopped responding due to an incoming flood of ICMP packets. Normal internal network traffic could not access any network resources. The incident management team responded by blocking incoming ICMP packets, stopping all non-critical network services offline, and restoring critical network services. 

The company’s cybersecurity team then investigated the security event. They found that a malicious actor had sent a flood of ICMP pings into the company’s network through an unconfigured firewall. This vulnerability allowed the malicious attacker to overwhelm the company’s network through a distributed denial of service (DDoS) attack. 

To address this security event, the network security team implemented: 

- A new firewall rule to limit the rate of incoming ICMP packets

- Source IP address verification on the firewall to check for spoofed IP addresses on incoming ICMP packets

- Network monitoring software to detect abnormal traffic patterns

- An IDS/IPS system to filter out some ICMP traffic based on suspicious characteristics

As a cybersecurity analyst, you are tasked with using this security event to create a plan to improve your company’s network security, following the National Institute of Standards and Technology (NIST) Cybersecurity Framework (CSF). You will use the CSF to help you navigate through the different steps of analyzing this cybersecurity event and integrate your analysis into a general security strategy. We have broken the analysis into different parts in the template below. You can explore them here:

- **Identify** security risks through regular audits of internal networks, systems, devices, and access privileges to identify potential gaps in security. 

- **Protect** internal assets through the implementation of policies, procedures, training and tools that help mitigate cybersecurity threats. 

- **Detect** potential security incidents and improve monitoring capabilities to increase the speed and efficiency of detections. 

- **Respond** to contain, neutralize, and analyze security incidents; implement improvements to the security process. 

- **Recover** affected systems to normal operation and restore systems data and/or assets that have been affected by an incident. 

</details>

---

## Incident report analysis

**Summary :** The company experienced a significant network disruption when all services stopped responding. The cybersecurity team identified the cause as a distributed denial of service (DDoS) attack using a flood of incoming ICMP packets. The team responded by blocking the attack and disabling all non-critical services to restore critical network operations.

**Identify :** The company suffered a two-hour outage caused by an ICMP flood DDoS attack. The entire internal network was impacted, and all critical network services required immediate restoration. Upon investigation, the cybersecurity team discovered that the attacker exploited an unconfigured firewall to send a large volume of ICMP packets, overwhelming the network infrastructure.

**Protect :** To prevent similar incidents, the security team implemented a firewall rule to limit the rate of incoming ICMP packets. In addition, an intrusion detection and prevention system (IDS/IPS) was deployed to filter out suspicious ICMP traffic based on defined characteristics and behavior patterns.

**Detect :** The team configured the firewall with source IP address verification to identify and block IP spoofed packets. They also implemented network monitoring software, such as a Security Information and Event Management (SIEM) system, to identify abnormal traffic patterns and ensure early detection of future threats.

**Respond :** In the event of future incidents, the cybersecurity team will isolate affected systems from the network to prevent further damage. They will prioritize restoring critical systems, analyse network logs for evidence of malicious activity, and document the incident for reporting to senior management and relevant legal authorities, as required.

**Recover :** Recovery efforts involve restoring full access to network services and ensuring systems are functioning normally. Non-critical network services should remain offline during recovery to minimize internal traffic. Once the DDoS traffic subsides and the firewall blocks are confirmed effective, services will be restored in stages—starting with critical systems—followed by non-critical services once the environment is stable.

**Reflections/ Notes :** This incident highlights the importance of regular security audits to ensure firewall configurations and all devices align with baseline security standards. Proactive monitoring and layered defense mechanisms, such as IDS/IPS and SIEM tools, are critical to mitigating threats and reducing incident response times.

---
## Supporting materials provided

[Applying the NIST CSF](https://docs.google.com/document/d/15yCDbDCOAcJw-LTz2DeCA7UeLRfvsf176T6MA6ku6ok/template/preview)

[Example of an incident report analysis](https://docs.google.com/document/d/11eTIo1igTRFrY279DG9tHTO3tB3bugSGyknZxsvY5vI/template/preview?resourcekey=0-97MA-eOwoGtqcfqky0vjmg)

---