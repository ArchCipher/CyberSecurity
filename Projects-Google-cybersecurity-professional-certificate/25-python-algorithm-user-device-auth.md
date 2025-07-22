# <p align="center"> Python Algorithm for User-Device Authentication </p>

## Project Overview

I simulated the role of a security analyst and developed a Python algorithm to automate user-device authentication processes. This project demonstrated practical applications of algorithmic thinking in cybersecurity contexts, including user access control, device assignment validation, and automated login verification systems.

---

## Process

1. User and Device Management

I implemented list operations to manage approved users and their assigned devices:

```python
# Approved users list
approved_users = ["elarson", "bmoreno", "tshah", "sgilmore", "eraab"]

# List of device IDs that correspond to the usernames in `approved_users`
approved_devices = ["8rp2k75", "hl0s5o1", "2ye3lzg", "4n482ts", "a307vir"]

# New user and device to add
new_user = "gesparza"
new_device = "3rcv4w6"

# Add `new_user` and `new_device` to respective lists
approved_users.append(new_user)
approved_devices.append(new_device)
```

The `.append()` method adds new users and devices to their respective lists, maintaining the parallel relationship between users and their assigned devices.

```python
# User and device to remove
removed_user = "tshah"
removed_device = "2ye3lzg"

# Remove `removed_user` and `removed_device` from respective lists
approved_users.remove(removed_user)
approved_devices.remove(removed_device)
```

The `.remove()` method eliminates users and their devices from the system when they leave the organization.

2. User Authentication Verification

I created conditional statements to verify user access permissions:

```python
# Test username
username = "sgilmore"

# Check if user is approved
if username in approved_users:
    print("The username", username, "is approved to access the system.")
else:
    print("The user", username, "is not approved to access the system")
```

The `in` operator checks if the username exists in the approved users list, providing immediate feedback on access status.

3. Device Assignment Validation

I implemented index-based matching to verify device assignments:

```python
# Test credentials
username = "sgilmore"
device_id = "4n482ts"

# Find user's position (username) in approved_users list
ind = approved_users.index(username)

# Verify both user and device
if username in approved_users and device_id == approved_devices[ind]:
    print("The user", username, "is approved to access the system.")
    print(device_id, "is the assigned device for", username)
```

The `.index()` method finds the position of the username in the approved users list, which corresponds to the same position of their assigned device in the devices list.

4. Comprehensive Authentication Algorithm

I developed a complete login function that handles all authentication scenarios:

```python
# Define a function that takes in two parameters, and handles all authentication scenarios
def login(username, device_id):
    # Check if user is approved
    if username in approved_users:
        print("The user", username, "is approved to access the system.")
        
        # Get user's device index
        ind = approved_users.index(username)
        
        # Verify device assignment
        if device_id == approved_devices[ind]:
            print(device_id, "is the assigned device for", username)
        else:
            print(device_id, "is not their assigned device.")
    else:
        print("The username", username, "is not approved to access the system.")

# Test different scenarios by calling the function defined
login("elarson", "8rp2k75")
login("elarson", "k758rp")
login("telarson", "k758rp")
```

The nested conditional structure handles three scenarios: approved user with correct device, approved user with incorrect device, and unapproved user.

---

## Summary

I created a comprehensive Python algorithm that demonstrates practical applications in cybersecurity authentication systems. The project involved managing user and device lists, implementing user verification, validating device assignments using index-based matching, and developing a complete login function with nested conditionals. These skills are directly applicable to security operations including access control systems, user management, and automated authentication processes.

---