# <p align="center"> Python File Import and Parsing for Security Analysis </p>

## Project Overview

I simulated the role of a security analyst and developed Python scripts to import, parse, and manipulate security log files. This project demonstrated practical applications of file handling in cybersecurity contexts, including log analysis, data extraction, and access control list management.

---

## Process

1. Security Log File Import and Reading

I implemented file handling to import and read security log data:

```python
# Security log file name
import_file = "login.txt"

# Read file content
with open(import_file, "r") as file:
    text = file.read()

print(text)
```

The `with` statement automatically handles file opening and closing, while the `"r"` parameter opens the file in read mode. The `.read()` method converts the entire file content into a string.

2. Log Data Parsing and Splitting

I used string methods to parse the log data into manageable components:

```python
# Split log into separate lines
print(text.split())
```

The `.split()` method converts the single string into a list of strings, with each line of the log file becoming a separate list element for easier processing.

3. Log File Appending

I implemented file appending to add missing log entries:

```python
# Missing log entry to add
missing_entry = "jrafael,192.168.243.140,4:56:27,2022-05-09"

# Append to log file
with open(import_file, "a") as file:
    file.write(missing_entry)
```

The `"a"` parameter opens the file in append mode, allowing new data to be added without overwriting existing content.

4. Access Control List Creation

I created a new file to store allowed IP addresses:

```python
# Create allowlist file
import_file = "allow_list.txt"

# IP addresses for allowlist
ip_addresses = "192.168.218.160 192.168.97.225 192.168.145.158 192.168.108.13 192.168.60.153 192.168.96.200 192.168.247.153 192.168.3.252 192.168.116.187 192.168.15.110 192.168.39.246"

# Write IP addresses to file
with open(import_file,"w") as file:
    file.write(ip_addresses)

# Read and verify file content
with open("allow_list.txt","r") as file:
    text = file.read()

print(text)
```

The `"w"` parameter opens the file in write mode, creating a new file or overwriting existing content. This creates an access control list for security management.

---

## Summary

I created Python scripts that demonstrate practical file handling techniques in cybersecurity contexts. The project involved importing and reading security log files, parsing log data into structured formats, appending missing entries to log files, and creating access control lists for security management. These skills are directly applicable to security operations including log analysis, data management, and access control system implementation.

---