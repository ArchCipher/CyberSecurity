# <p align="center"> Python Loops for Security Automation </p>

## Project Overview

I simulated the role of a security analyst and developed Python automation scripts to handle network connection monitoring, IP address allowlist validation, and employee ID generation for a Sales department. This project demonstrated practical applications of Python loops in cybersecurity contexts, including network security monitoring and access control systems.

---

## Process

1. Network Connection Attempt Monitoring

I created automation scripts to track and display network connection failures. This involved implementing both `for` and `while` loops to handle connection attempt logging.

```python
# Create variable to store connection attempts
connection_attempts = 5

# Display connection failure message multiple times using for loop
for i in range(connection_attempts):
    print("Connection could not be established")
```

The `for` loop in Python repeats code for a specified sequence. The `range()` function generates a sequence of numbers starting from 0 up to the specified number. In this case, it will iterate 5 times, displaying the connection failure message each time.

```python
# Initialize counter for while loop
connection_attempts = 0

# Display message until condition is met
while connection_attempts < 5:
    print("Connection could not be established")
    connection_attempts = connection_attempts + 1
```

The `while` loop continues executing as long as the condition `connection_attempts < 5` is true. Each iteration increments the counter and displays the message until the condition becomes false.

2. IP Address Allowlist Validation

I developed an automated system to validate IP addresses against an allowlist:

```python
# List of approved IP addresses
allow_list = ["192.168.243.140", "192.168.205.12", "192.168.151.162", "192.168.178.71", 
              "192.168.86.232", "192.168.3.24", "192.168.170.243", "192.168.119.173"]

# IP addresses attempting to connect
ip_addresses = ["192.168.142.245", "192.168.109.50", "192.168.86.232", "192.168.131.147",
                "192.168.205.12", "192.168.200.48"]

# Check each IP against allowlist
for i in ip_addresses:
    if i in allow_list:
        print("IP address is allowed")
    else:
        print("IP address is not allowed. Further investigation of login activity required")
        break
```

The `for` loop iterates through each IP address in the `ip_addresses` list. The `in` operator checks if the current IP address exists in the `allow_list`. If an unauthorized IP is detected, the `break` statement terminates the loop immediately.

3. Employee ID Generation System

I created an automated employee ID generation system for a Sales department with specific business requirements:

```python
# Assign loop variable i to the first employee ID
i = 5000

# Generate IDs divisible by 5
while i <= 5150: 
    print(i)
    # for loop to display the number of IDs remaining when employee ID reaches 5100
    if i == 5100:
        print("Only 10 valid employee IDs remaining")
    i = i + 5
```

The `while` loop generates employee IDs that are divisible by 5, starting from 5000 and ending at 5150. The conditional statement checks if the current ID is 5100 and displays an alert message when only 10 IDs remain.

---

## Summary

I created automation scripts that demonstrate the practical application of Python loops in cybersecurity contexts. The project involved implementing `for` and `while` loops for network connection monitoring, IP address validation against allowlists, and automated employee ID generation. These skills are directly applicable to security operations including automated log analysis, access control system implementation, and security alert generation.

---

