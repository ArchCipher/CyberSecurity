# <p align="center"> Python Algorithm for Access Control Management </p>

## Project Overview

I simulated the role of a security professional at a healthcare company and developed a Python algorithm to manage access control for restricted patient records. The system uses IP address allowlists to control access to sensitive data, and I created an automated process to remove unauthorized IP addresses from the allowlist.

---

## Process

1. File Reading and Data Preparation

I opened and processed the allowlist file containing authorized IP addresses:

```python
# Assign file name to variable
import_file = "allow_list.txt"

# Read file and convert to list
with open(import_file, "r") as file:
    allow_list = (file.read()).split()
```

The `with` statement manages file resources automatically, opening the file in read mode and closing it after use. The `.read()` method converts file content to a string, and `.split()` converts it to a list for easier manipulation.

2. IP Address Removal Algorithm

I implemented a loop to identify and remove unauthorized IP addresses:

```python
# Remove addresses that match the remove list
for address in allow_list:
    if address in remove_list:
        allow_list.remove(address) 
```

The `for` loop iterates through each IP address in the allowlist. The conditional statement checks if the address exists in the remove list, and if so, removes it using the `.remove()` method.

3. File Update Process

I converted the updated list back to a string and wrote it to the file:

```python
# Convert list back to string with line breaks
allow_list = ("\n".join(allow_list))

# Write updated allowlist to file
with open(import_file, "w") as file:
    file.write(allow_list)
```

The `.join()` method combines list elements into a string with newline separators. The file is opened in write mode (`"w"`) to replace existing content with the updated allowlist.

4. Complete Function Implementation

I created a reusable function that combines all steps:

```python
def update_file(import_file, remove_list):
    # Read and convert file to list
    with open(import_file, "r") as file:
        allow_list = (file.read()).split()
    
    # Remove unauthorized addresses
    for address in allow_list:
        if address in remove_list:
            allow_list.remove(address)
    
    # Convert back to string and update file
    allow_list = ("\n".join(allow_list))
    with open(import_file, "w") as file:
        file.write(allow_list)

# Execute the function
update_file("allow_list.txt", ["192.168.25.60", "192.168.140.81", "192.168.203.198"])
```

The function encapsulates the entire process, making it reusable for different files and remove lists. This demonstrates understanding of function design and parameter passing.

---

## Summary

I developed a comprehensive Python algorithm for access control management that demonstrates file handling, list manipulation, and automated security processes. The algorithm efficiently removes unauthorized IP addresses from allowlists, ensuring only authorized users can access sensitive healthcare data. This project showcases practical application of Python programming in cybersecurity contexts, including data validation, automated file updates, and security policy enforcement.

---