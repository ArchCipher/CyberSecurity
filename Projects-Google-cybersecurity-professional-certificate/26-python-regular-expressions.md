# <p align="center"> Python Regular Expressions for Security Analysis </p>

## Project Overview

I simulated the role of a security analyst and developed Python scripts using regular expressions to analyze security logs and identify patterns in device IDs and IP addresses. This project demonstrated practical applications of regex patterns in cybersecurity contexts, including log parsing, device identification, and network traffic analysis.

---

## Process

1. Device ID Pattern Matching

I used regular expressions to identify devices requiring system updates:

```python
from re import findall

# String containing device IDs
devices = "r262c36 67bv8fy 41j1u2e r151dm4 1270t3o 42dr56i r15xk9h 2j33krk 253be78 ac742a1 r15u9q5 zh86b2l ii286fq 9x482kt 6oa6m6u x3463ac i4l56nq g07h55q 081qc9t r159r1u"

# Pattern to match devices starting with "r15"
target_pattern = "r15\w+"
findall(target_pattern, devices)
```

**Regex Pattern Used:** `r15\w+`
- `\w` matches any word character (letters, digits, underscore)
- `\w+` matches one or more word characters (the `+` means "one or more")
- This pattern matches device IDs starting with "r15" followed by one or more word characters, identifying devices that require operating system updates.

2. IP Address Validation and Extraction

I implemented regex patterns to extract valid IP addresses from security logs:

```python
# Security log with IP addresses
log_file = "eraab 2022-05-10 6:03:41 192.168.152.148 \niuduike 2022-05-09 6:46:40 192.168.22.115 \nsmartell 2022-05-09 19:30:32 192.168.190.178 \narutley 2022-05-12 17:00:59 1923.1689.3.24 \nrjensen 2022-05-11 0:59:26 192.168.213.128 \naestrada 2022-05-09 19:28:12 1924.1680.27.57 \nasundara 2022-05-11 18:38:07 192.168.96.200 \ndkot 2022-05-12 10:52:00 1921.168.1283.75 \nabernard 2022-05-12 23:38:46 19245.168.2345.49 \ncjackson 2022-05-12 19:36:42 192.168.247.153 \njclark 2022-05-10 10:48:02 192.168.174.117 \nalevitsk 2022-05-08 12:09:10 192.16874.1390.176 \njrafael 2022-05-10 22:40:01 192.168.148.115 \nyappiah 2022-05-12 10:37:22 192.168.103.10654 \ndaquino 2022-05-08 7:02:35 192.168.168.144"

# Refined pattern for valid IP addresses
pattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
valid_ip_addresses = re.findall(pattern, log_file)
print(valid_ip_addresses)
```

**Regex Pattern Used:** `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`
- `\d` matches any digit (0-9)
- `\d{1,3}` matches between 1 and 3 digits (ensures each octet is valid)
- `\.` matches literal dots (escaped because dot is a special character)
- This pattern validates IP address format by ensuring each octet contains only 1-3 digits

**Learning Experience:** Initially, I used the pattern `\d+\.\d+\.\d+\.\d+` which included invalid IP addresses like `1923.1689.3.24` and `19245.168.2345.49`. I learned that this pattern was too permissive and didn't validate the octet ranges. I refined the pattern to `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` to ensure each octet contains only 1-3 digits, properly filtering out invalid addresses.

3. Flagged IP Address Analysis

I implemented a loop to analyze IP addresses against a flagged list:

```python
# Previously flagged IP addresses
flagged_addresses = ["192.168.190.178", "192.168.96.200", "192.168.174.117", "192.168.168.144"]

# Check each IP against flagged list
for address in valid_ip_addresses:
    if address in flagged_addresses:
        print("The IP address", address, "has been flagged for further analysis.")
    else:
        print("The IP address", address, "does not require further analysis")
```

The loop iterates through each valid IP address and checks if it exists in the flagged addresses list, providing immediate feedback for security investigation.

---

## Summary

I created Python scripts using regular expressions that demonstrate practical applications in cybersecurity log analysis. The project involved pattern matching for device identification, IP address validation using regex constraints, and automated analysis of flagged network addresses. These skills are directly applicable to security operations including log parsing, threat detection, and network monitoring systems.

---