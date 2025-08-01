# <p align="center"> Network Protocol Investigation & Traffic Analysis </p>

## Overview

As a part of simulated incident response process, I was provided with DNS and ICMP traffic data from a network protocol analyser to investigate a website availability issue. I examined the tcpdump output, how the server responded to the DNS request, identified the affected network protocol, and documented the traffic analysis.

---

## Scenario

A client reports their website is inaccessible, and users receive a “destination port unreachable” error. A network protocol analyser was used to analyse traffic and identify the cause of the issue.

<details>
<summary><strong>Read full scenario</strong></summary>

You are a cybersecurity analyst working at a company that specializes in providing IT services for clients. Several customers of clients reported that they were not able to access the client company website www.yummyrecipesforme.com, and saw the error “destination port unreachable” after waiting for the page to load. 
You are tasked with analyzing the situation and determining which network protocol was affected during this incident. To start, you attempt to visit the website and you also receive the error “destination port unreachable.” To troubleshoot the issue, you load your network analyzer tool, tcpdump, and attempt to load the webpage again. To load the webpage, your browser sends a query to a DNS server via the UDP protocol to retrieve the IP address for the website's domain name; this is part of the DNS protocol. Your browser then uses this IP address as the destination IP for sending an HTTPS request to the web server to display the webpage  The analyzer shows that when you send UDP packets to the DNS server, you receive ICMP packets containing the error message: “udp port 53 unreachable.” 

Now that you have captured data packets using a network analyzer tool, it is your job to identify which network protocol and service were impacted by this incident. Then, you will need to write a follow-up report. 
As an analyst, you can inspect network traffic and network data to determine what is causing network-related issues during cybersecurity incidents. 
This event, in the meantime, is being handled by security engineers after you and other analysts have reported the issue to your direct supervisor. 

</details>

---

<br>

```sh
13:24:32.192571 IP 192.51.100.15.52444 > 203.0.113.2.domain: 35084+ A?
yummyrecipesforme.com. (24)
13:24:32.098564 IP 203.0.113.2 > 192.51.100.15: ICMP 203.0.113.2
udp port 53 unreachable length 254

13:26:32.192571 IP 192.51.100.15.52444 > 203.0.113.2.domain: 35084+ A?
yummyrecipesforme.com. (24)
13:24:32.098564 IP 203.0.113.2 > 192.51.100.15: ICMP 203.0.113.2
udp port 53 unreachable length 320

13:28:32.192571 IP 192.51.100.15.52444 > 203.0.113.2.domain: 35084+ A?
yummyrecipesforme.com. (24)
13:24:32.098564 IP 203.0.113.2 > 192.51.100.15: ICMP 203.0.113.2
udp port 53 unreachable length 150
```
<details>
<summary><strong>Read tcpdump explanation provided</strong></summary>

In the tcpdump log, you find the following information:
1. The first two lines of the log file show the initial outgoing request from your computer to the DNS server requesting the IP address of yummyrecipesforme.com. This request is sent in a UDP packet.

2. The third and fourth lines of the log show the response to your UDP packet. In this case, the ICMP 203.0.113.2 line is the start of the error message indicating that the UDP packet was undeliverable to port 53 of the DNS server.

3. In front of each request and response, you find timestamps that indicate when the incident happened. In the log, this is the first sequence of numbers displayed: 13:24:32.192571. This means the time is 1:24 p.m., 32.192571 seconds.

4. After the timestamps, you will find the source and destination IP addresses. In the first line, where the UDP packet travels from your browser to the DNS server, this information is displayed as: 192.51.100.15 > 203.0.113.2.domain. The IP address to the left of the greater than (>) symbol is the source address, which in this example is your computer’s IP address. The IP address to the right of the greater than (>) symbol is the destination IP address. In this case, it is the IP address for the DNS server: 203.0.113.2.domain. For the ICMP error response, the source address is 203.0.113.2 and the destination is your computers IP address 192.51.100.15.

5. After the source and destination IP addresses, there can be a number of additional details like the protocol, port number of the source, and flags. In the first line of the error log, the query identification number appears as: 35084. The plus sign after the query identification number indicates there are flags associated with the UDP message. The "A?" indicates a flag associated with the DNS request for an A record, where an A record maps a domain name to an IP address. The third line displays the protocol of the response message to the browser: "ICMP," which is followed by an ICMP error message.

6. The error message, "udp port 53 unreachable" is mentioned in the last line. Port 53 is a port for DNS service. The word "unreachable" in the message indicates the UDP message requesting an IP address for the domain "www.yummyrecipesforme.com" did not go through to the DNS server because no service was listening on the receiving DNS port.

7. The remaining lines in the log indicate that ICMP packets were sent two more times, but the same delivery error was received both times. 

</details>

---

## Cybersecurity Incident Report: Network Traffic Analysis

__Part 1: Summary of the DNS and ICMP traffic log__

The tcpdump log shows an outgoing request from 192.51.100.15 to 203.0.113.2 on UDP port 53 (DNS server) attempting to resolve the domain yummyrecipesforme.com.
The DNS query ID is 35084, and "+" symbol indicates recursion desired (RD) flag set to the query.
"A?" is a query requesting IPv4 Address record of the website yummyrecipesforme.com.
The DNS server does not send a standard response to this query. Instead, it sends an ICMP error message to 192.51.100.15, stating the packet sent to 203.0.113.2 on UDP port 53 was unreachable.
This indicated that the DNS server was not available on port 53 to receive the query.

---

__Part 2: Analysis and cause of the incident__

The incident occurred at 1:24 PM. 
Users reported they were unable to access the website yummyrecipesforme.com., and received an error message: “destination port unreachable”.
Packet analysis revealed that the DNS server at 203.0.113.2 is not responding on UDP port 53. Instead, it returned ICMP "port 53 unreachable" error messages.
The issue is currently being addressed by the security engineering team.
The likely cause is the DNS server is down or unresponsive. A possible could be a Denial of Service (DoS) or Distributed Denial of Service (DDoS) attack targeting the DNS service.

---