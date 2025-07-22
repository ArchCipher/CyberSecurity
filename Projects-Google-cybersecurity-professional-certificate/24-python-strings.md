# <p align="center"> Python String Manipulation for Security Analysis </p>

## Project Overview

I simulated the role of a security analyst and developed Python scripts to manipulate string data for security applications. This project demonstrated practical applications of string operations in cybersecurity contexts, including employee ID standardization, device ID parsing, and URL component extraction for security analysis.

---

## Process

1. Employee ID Data Type Conversion and Validation

I worked with employee ID data to ensure proper formatting and validation:

```python
# Initialize employee ID as integer
employee_id = 4186

# Display the data type of `employee_id`
print(type(employee_id))

# Convert to string format
employee_id = str(employee_id)

# Display the data type of `employee_id`
print(type(employee_id))
```

The first print displays the datatype of employee_id as an integer, whereas the second one displays it as a string.
The `str()` function converts the integer employee ID to a string format. This conversion is necessary for string operations and validation.

```python
# Validate ID length requirement
if len(employee_id) < 5:
    print("This employee ID has less than five digits. It does not meet length requirements.")
```

The `len()` function determines the length of the string, and the conditional statement validates compliance with the five-digit requirement.

2. Employee ID Standardization

I implemented string concatenation to standardize employee IDs:

```python
# Display the `employee_id`
print(employee_id)

# Add prefix if ID is too short
if len(employee_id) < 5:
    employee_id = "E" + employee_id
    
# Display the `employee_id` after the update
print(employee_id)
```

String concatenation using the `+` operator adds the prefix "E" to four-digit IDs, creating standardized five-character employee IDs. The first print function displays the employee_id as "4186". The second one prints it as "E4186" and hence does not create an error for ID length requirement (5 digits).

3. Device ID Character Extraction

I extracted specific characters and substrings from device IDs for analysis:

```python
# Device ID for analysis
device_id = "r262c36"

# Extract the fourth character in `device_id` and display it
print(device_id[3])

# Extract the first through the third characters in `device_id` and display the result
print(device_id[0:3])
```

Indexing with `device_id[3]` extracts the fourth character (index 3). Slicing with `device_id[0:3]` extracts characters from index 0 to 2, providing the first three characters.

4. URL Component Extraction

I parsed URL components for security analysis:

```python
# URL for component extraction
url = "https://exampleURL1.com"

# Extract the protocol of `url` along with the syntax following it, display the result
print(url[0:8])

# Find domain extension position in `url` (starting position of .com)
ind = url.index(".com")

# Extract domain extension
print(url[ind:ind+4])

# Extract the website name in `url`
print(url[8:ind])
```

The `.index()` method finds the position of ".com" in the URL. String slicing extracts the protocol (`https://`), domain extension (`.com`), and website name (`exampleURL1`) for security analysis and validation.

---

## Summary

I created Python scripts that demonstrate practical string manipulation techniques in cybersecurity contexts. The project involved converting data types, validating string lengths, implementing string concatenation for standardization, extracting specific characters and substrings from device IDs, and parsing URL components for security analysis. These skills are directly applicable to security operations including data validation, log parsing, and network traffic analysis.

---
    