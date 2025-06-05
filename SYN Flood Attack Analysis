# <p align="center"> SYN Flood Attack Analysis </p>

## Overview



## Scenario

You work as a security analyst for a travel agency that advertises sales and promotions on the company’s website. The employees of the company regularly access the company’s sales webpage to search for vacation packages their customers might like. 
One afternoon, you receive an automated alert from your monitoring system indicating a problem with the web server. You attempt to visit the company’s website, but you receive a connection timeout error message in your browser.
You use a packet sniffer to capture data packets in transit to and from the web server. You notice a large number of TCP SYN requests coming from an unfamiliar IP address. The web server appears to be overwhelmed by the volume of incoming traffic and is losing its ability to respond to the abnormally large number of SYN requests. You suspect the server is under attack by a malicious actor. 
You take the server offline temporarily so that the machine can recover and return to a normal operating status. You also configure the company’s firewall to block the IP address that was sending the abnormal number of SYN requests. You know that your IP blocking solution won’t last long, as an attacker can spoof other IP addresses to get around this block. You need to alert your manager about this problem quickly and discuss the next steps to stop this attacker and prevent this problem from happening again. You will need to be prepared to tell your boss about the type of attack you discovered and how it was affecting the web server and employees.

## Cybersecurity Incident Report

__Section 1: Identify the type of attack that may have caused this network interruption__

The potential reason for website’s timeout is that the server is overloaded with SYN packets and is unable to respond to requests. This appears to be a DoS SYN attack by IP 203.0.113.0 with port 54770

Logs show that until item 72, the server is still able to process the requests although it has many ports open waiting for ACK acknowledgment from but source IP 203.0.113.0 with port 54770. However, at item 73, it struggles to respond to legitimate requests from users and sends a “RST ACK” which forcefully resets the connection and sends a “Gateway timeout” error message. 
After item 122, the server seems to be frozen and stops responding to legitimate requests.


__Section 2: Explain how the attack is causing the website to malfunction__

When website visitors try to establish a connection with the web server, a three-way handshake occurs using the TCP protocol. Explain the three steps of the handshake:
1. SYN (synchronise) request is sent from the source to the destination.
2. The destination returns with a SYN-ACK acknowledgment to the source.
3. Finally, ACK packet acknowledging the connection is sent from the source to the destination.
This establishes a TCP handshake, the two devices connect and can send data. 
The TCP handshake and the HTTP request is received and responded in around 0.2ms usually as in log item 47 to 51.
The malicious actor sent a large number of SYN packets all at once without responding with an ACK which caused the server to overload and freeze. 

The DoS SYN attack could affect the organisation financially as it restricts the organization from performing normal business operations.

Some of ways to solve this issue would be to have-
Configure the firewall to block the IP address IP 203.0.113.0.
Reduce the number of SYN request per user.
Shorter SYN request timeout.
Configure Firewall to block multiple requests from the same user if ACK is not returned.