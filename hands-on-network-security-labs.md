# Hands-On Network Security Labs (Unix Terminal)

**Platform:** Unix Terminal  
**Objective:** Network discovery and packet analysis

---

## Skills Demonstrated
- **Network Discovery**: Device identification, topology mapping, service enumeration
- **Packet Analysis**: TCP handshake understanding, traffic pattern recognition

## Tools Used
- **Network Discovery**: `ifconfig`, `ipconfig`, `arp`, `ping`, `nmap`, `lsof`
- **Packet Analysis**: `tcpdump`

---

## Lab 1 - Local Network Discovery & Scanning
**Goal**: Identify devices on the local network and assess their connectivity.

I started by identifying my own network configuration using `ipconfig` and `ifconfig`. Used `arp -a` to list IP–MAC mappings of known devices on the network. Verified network connectivity using `ping <IP>` for each discovered device.

Performed `nmap` scans with various flags (`-sS`, `-sV`, `-O`, `-p-`) to detect open ports, running services, and OS information. Used `lsof` to inspect open ports on local system.

**Outcome**: Gained hands-on experience in internal network mapping and reconnaissance.

---

## Lab 2 - tcpdump Packet Capture
**Goal**: Capture and analyze network packets to understand real-time traffic flow and TCP handshakes.

Captured live traffic on specific interfaces using `tcpdump`, applying filters by protocol, port, or IP address. Analyzed SYN, SYN-ACK, ACK, FIN flags to understand the TCP 3-way handshake process.

Practiced using filters to isolate specific traffic types (HTTP, DNS, ICMP) and identified normal vs. suspicious traffic patterns.

**Outcome**: Developed a foundational understanding of packet structures and network traffic analysis.

---

## References

- [An introduction to using tcpdump at the Linux command line](https://opensource.com/article/18/10/introduction-tcpdump)
- [How to Capture and Analyze Network Traffic with tcpdump?](https://geekflare.com/cloud/tcpdump-examples/)
- [Masterclass – Tcpdump – Interpreting Output](https://packetpushers.net/blog/masterclass-tcpdump-interpreting-output/) 