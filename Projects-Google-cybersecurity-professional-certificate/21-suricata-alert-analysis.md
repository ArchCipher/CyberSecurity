# <p align="center"> Suricata Log Analysis & Alert Examination </p>

## Project Overview

I explored how Suricata detects network activity based on pre-written custom rules. I simulated an alert scenario by running Suricata on a sample .pcap file and observed how specific rule matches generate alerts. I then examined the generated logs—fast.log and eve.json—to extract relevant alert details using tools like jq. This lab demonstrated how analysts inspect alerts in a real-world intrusion detection environment.

---

## Process

1. Examine a custom rule

```bash
cat custom.rules  # review predefined rules
# Output:
# alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"GET on wire"; flow:established,to_server; content:"GET"; http_method; sid:12345; rev:3;)
```
Note: Actions differ across network intrusion detection system (NIDS) rule languages, but some common actions are alert, drop, pass, and reject. 
Note that the drop action also generates an alert, but it drops the traffic. A drop action only occurs when Suricata runs in IPS mode. 
The pass action allows the traffic to pass through the network interface. The pass rule can be used to override other rules. An exception to a drop rule can be made with a pass rule. 

```bash
pass http 172.17.0.77 any -> $EXTERNAL_NET any (msg:"BAD USER-AGENT";flow:established,to_server;content:!”Mozilla/5.0”; http_user_agent; sid: 12365; rev:1;)
```
This rule has an identical signature to the previous example, except that it singles out a specific IP address to allow only traffic from that address to pass.

2. Trigger a custom rule

```bash
ls -l /var/log/suricata
# Output:
# total 0

# Note: before running suricata there are no files in /var/log/suricata directory

sudo suricata -r sample.pcap -S custom.rules -k none    # run suricata using the custom.rules and sample.pcap files
# Output:
# 28/6/2025 -- 14:37:39 - <Notice> - This is Suricata version 4.1.2 RELEASE
# 28/6/2025 -- 14:37:40 - <Notice> - all 2 packet processing threads, 4 management threads initialized, engine started.
# 28/6/2025 -- 14:37:40 - <Notice> - Signal Received.  Stopping engine.
# 28/6/2025 -- 14:37:42 - <Notice> - Pcap-file module read 1 files, 200 packets, 54238 bytes

# The -r sample.pcap option specifies an input file to mimic network traffic. In this case, the sample.pcap file. The -S custom.rules option instructs Suricata to use the rules defined in the custom.rules file. The -k none option instructs Suricata to disable all checksum checks.

ls -l /var/log/suricata     # list all files in /var/log/suricata
# Output:
# total 16
# -rw-r--r-- 1 root root 1431 Jun 28 14:37 eve.json
# -rw-r--r-- 1 root root  292 Jun 28 14:37 fast.log
# -rw-r--r-- 1 root root 2911 Jun 28 14:37 stats.log
# -rw-r--r-- 1 root root  353 Jun 28 14:37 suricata.log

cat /var/log/suricata/fast.log      # read fast.log
# Output:
# 11/23/2022-12:38:34.624866  [**] [1:12345:3] GET on wire [**] [Classification: (null)] [Priority: 3] {TCP} 172.21.224.2:49652 -> 142.250.1.139:80
# 11/23/2022-12:38:58.958203  [**] [1:12345:3] GET on wire [**] [Classification: (null)] [Priority: 3] {TCP} 172.21.224.2:58494 -> 142.250.1.102:80
```

3. Examine eve.json output

```bash
cat /var/log/suricata/eve.json  # read eve.json
# Output:
# {"timestamp":"2022-11-23T12:38:34.624866+0000","flow_id":143589687064725,"pcap_cnt":70,"event_type":"alert","src_ip":"172.21.224.2","src_port":49652,"dest_ip":"142.250.1.139","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":12345,"rev":3,"signature":"GET on wire","category":"","severity":3},"http":{"hostname":"opensource.google.com","url":"\/","http_user_agent":"curl\/7.74.0","http_content_type":"text\/html","http_method":"GET","protocol":"HTTP\/1.1","status":301,"redirect":"https:\/\/opensource.google\/","length":223},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":357,"bytes_toclient":788,"start":"2022-11-23T12:38:34.620693+0000"}}
# {"timestamp":"2022-11-23T12:38:58.958203+0000","flow_id":190497173968116,"pcap_cnt":151,"event_type":"alert","src_ip":"172.21.224.2","src_port":58494,"dest_ip":"142.250.1.102","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":12345,"rev":3,"signature":"GET on wire","category":"","severity":3},"http":{"hostname":"opensource.google.com","url":"\/","http_user_agent":"curl\/7.74.0","http_content_type":"text\/html","http_method":"GET","protocol":"HTTP\/1.1","status":301,"redirect":"https:\/\/opensource.google\/","length":223},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":357,"bytes_toclient":797,"start":"2022-11-23T12:38:58.955636+0000"}}

jq . /var/log/suricata/eve.json | less      # use jq to display the entries in an improved format
# Output:
{
  "timestamp": "2022-11-23T12:38:34.624866+0000",
  "flow_id": 143589687064725,
  "pcap_cnt": 70,
  "event_type": "alert",
  "src_ip": "172.21.224.2",
  "src_port": 49652,
  "dest_ip": "142.250.1.139",
  "dest_port": 80,
  "proto": "TCP",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 12345,
    "rev": 3,
    "signature": "GET on wire",
    "category": "",
    "severity": 3
  },
  "http": {
    "hostname": "opensource.google.com",
    "url": "/",
    "http_user_agent": "curl/7.74.0",
    "http_content_type": "text/html",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 301,
    "redirect": "https://opensource.google/",
    "length": 223
  },
  "app_proto": "http",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 3,
:
# Q to exit less command

jq -c "[.timestamp,.flow_id,.alert.signature,.proto,.dest_ip]" /var/log/suricata/eve.json # extract specific fields from the eve.json file
# ["2022-11-23T12:38:34.624866+0000",143589687064725,"GET on wire","TCP","142.250.1.139"]
# ["2022-11-23T12:38:58.958203+0000",190497173968116,"GET on wire","TCP","142.250.1.102"]

jq "select(.flow_id==143589687064725)" /var/log/suricata/eve.json   # filtered logs by specific flow_id from the eve.json file
# Output:
{
  "timestamp": "2022-11-23T12:38:34.624866+0000",
  "flow_id": 143589687064725,
  "pcap_cnt": 70,
  "event_type": "alert",
  "src_ip": "172.21.224.2",
  "src_port": 49652,
  "dest_ip": "142.250.1.139",
  "dest_port": 80,
  "proto": "TCP",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 12345,
    "rev": 3,
    "signature": "GET on wire",
    "category": "",
    "severity": 3
  },
  "http": {
    "hostname": "opensource.google.com",
    "url": "/",
    "http_user_agent": "curl/7.74.0",
    "http_content_type": "text/html",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 301,
    "redirect": "https://opensource.google/",
    "length": 223
  },
  "app_proto": "http",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 3,
    "bytes_toserver": 357,
    "bytes_toclient": 788,
    "start": "2022-11-23T12:38:34.620693+0000"
  }
}

```

---

## Reflection
This project improved my understanding of how Suricata operates as a signature-based intrusion detection system. I practiced parsing raw and structured log outputs, and learned how Suricata rules operate in a real-time or replay scenario. These techniques are essential for detecting suspicious activity and validating IDS performance in a security operations center (SOC) environment.

---

## Notes:
[Suricata User Guide](https://docs.suricata.io/en/latest/quickstart.html#eve-json)

---