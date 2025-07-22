# <p align="center"> Python Functions for Security Analysis </p>

## Project Overview

I simulated the role of a security analyst and developed Python functions to automate security alert systems and analyze login attempt patterns. This project demonstrated practical applications of function definition, parameter passing, and return statements in cybersecurity contexts, including security monitoring and user behavior analysis.

---

## Process

1. Basic Function Definition and Calling

I created a simple function to display security alerts:

```python
# Define security alert function
def alert():
    print("Potential security issue. Investigate further.")

# Call the `alert()` function
alert()
```

The `def` keyword defines a function named `alert()`. The function body contains the code that executes when the function is called. Calling `alert()` displays the security message.

```python
# Define `alert()` function that displays the alert multiple times
def alert(): 
    for i in range(3):
        print("Potential security issue. Investigate further.")

# Call the `alert()` function
alert()
```

This enhanced function uses a `for` loop to display the security alert three times, demonstrating how functions can contain other programming constructs.

2. List Processing Function

I developed a function to convert a list of approved usernames into a formatted string:

```python
# Define a function to convert a list of approved usernames into a formatted string`
def list_to_string():
    # Approved usernames list
    username_list = ["elarson", "bmoreno", "tshah", "sgilmore", "eraab", "gesparza", "alevitsk", "wjaffrey"]

    # Initialize empty string for concatenation
    sum_variable = ""

    # Concatenate usernames with separators using a foor loop
    for i in username_list:
        sum_variable = sum_variable + i + ", "

  # Display the value of `sum_variable`
  print(sum_variable)

# Call the `list_to_string()` function
list_to_string()
```

The function iterates through the username list and concatenates each username with a comma and space separator. This creates a formatted string suitable for file output or display.

3. Built-in Functions for Data Analysis

I used built-in Python functions to analyze failed login attempt data:

```python
# Failed login attempts per month
failed_login_list = [119, 101, 99, 91, 92, 105, 108, 85, 88, 90, 264, 223]

# Sort and find maximum
print(sorted(failed_login_list))
print(max(failed_login_list))
```

The `sorted()` function returns a new list with elements in ascending order. The `max()` function identifies the highest value in the list, which can indicate potential security incidents requiring investigation.

4. Advanced Function with Parameters and Return Values

I created a comprehensive function to analyze user login patterns:

```python
# Define a function that takes in three parameters to analyze user login patterns
def analyze_logins(username, current_day_logins, average_day_logins):
    # Display current day login information
    print("Current day login total for", username, "is", current_day_logins)
    print("Average logins per day for", username, "is", average_day_logins)

    # Calculate login ratio and return it
    login_ratio = current_day_logins / average_day_logins
    return login_ratio

# Test the function (call the function and store the output in a variable named `login_analysis`)
login_analysis = analyze_logins("ejones", 9, 3)

# Conditional statement to check for unusual activity
if login_analysis >= 3:
    print("Alert! This account has more login activity than normal.")
```

The function takes three parameters: username, current day logins, and average day logins. It calculates the login ratio and returns this value. The returned value is then used in a conditional statement to determine if the login activity requires investigation.

---

## Summary

I created Python functions that demonstrate practical applications in cybersecurity analysis. The project involved defining functions for security alerts, processing user lists, analyzing login patterns using built-in functions, and implementing conditional logic based on function return values. These skills are directly applicable to security operations including automated monitoring, user behavior analysis, and incident detection.

---    

