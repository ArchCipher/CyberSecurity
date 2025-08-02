# SQL Injection - Login bypass

## Goal:
This lab contains a SQL injection vulnerability in the login function.

To solve the lab, perform a SQL injection attack that logs in to the application as the `administrator` user.

---

## Vulnerability Analysis

### Attack Vector Identification
- **Entry Point**: `username` and `password` parameters in POST request
- **Vulnerability Type**: T1190.001 - SQL Injection: Authentication Bypass (CWE-89)
- **Security Flaw:** User input is embedded directly into SQL queries

### Vulnerability Assessment & Exploitation

**Initial Approach:**
- Intercepted HTTP requests using Burp Suite
- Identified login parameters as potential injection points
- Performed systematic input validation testing

**Step 1: Testing Normal Login**

Attempted login with random credentials:
Username: user
Password: password

The intercepted POST request contained:
- CSRF token
- Username and password parameters
- Login form data

**Intercepted Request:**
```http
csrf=xyz&username=user&password=password
```

**Step 2: Testing SQL Injection**

```http
csrf=xyz&username=administrator'--&password=''
```

**Step 3: Understanding the Injection**

`username=administrator` attempts to log in as administrator, `'` closes the string in the SQL query. `--` comments out the rest of the query and bypasses the password check.

**The SQL query becomes:**
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = '" + password + "'
```

This results in a successful login without verifying the password.

---

## Security Assessment

### Root Cause Analysis
- Application concatenates user input directly into SQL queries
- No input validation or sanitization implemented
- Parameterized queries (prepared statements) are not used

### Risk Assessment
| Category | Impact |
|----------|--------|
| Authentication | High – Complete login bypass achieved |
| Authorization | High – Unauthorized access to administrator account |
| Confidentiality | High – Sensitive data accessible |

---

## Mitigation

**Parameterized Queries (Prepared Statements):** Parameterized queries treat user input as data and not as part of SQL code, which prevents injection. Never build SQL statements by directly concatenating user input. 

Vulnerable SQL query:
```sql
SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'
```

Safe version using prepared statements (Python):
```py
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

`?` is a parameter placeholder. It tells the database, "Expect a value here." The value is safely passed as a separate argument to `cursor.execute()`. This prevents it from being executed as SQL. Some DBs like MySQL or Oracle use `%s` or `$1` instead. Check [notes](./01-sqli-where-clause.md#notes) for more info.

---

## Reflection

This lab demonstrated how SQL injection can bypass authentication by manipulating input and commenting out the password check. The `--` comment technique proved highly effective in bypassing the password verification. Learned the critical importance of using prepared statements and proper input validation to secure authentication systems.

---

## Notes