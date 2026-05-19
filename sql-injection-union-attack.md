# SQL Injection UNION Attack — Lab Writeup

## Challenge

> Perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.

**Vulnerability location:** Product category filter  
**Type:** SQL Injection — UNION-based data extraction

---

## Approach

### Step 1 — Confirm the Vulnerability

Tested the product category filter for SQL injection by injecting a basic payload. Confirmed the parameter was vulnerable and that query results are reflected in the application's response.

### Step 2 — Identify String-Compatible Columns

Used a UNION SELECT with NULL values to probe column count and data types. The following payload confirmed that the second column accepts string data:

```sql
'+UNION+SELECT+NULL,'a'--
```

### Step 3 — Extract Credentials

With column structure confirmed, used string concatenation to retrieve both `username` and `password` from the `users` table in a single column:

```sql
' UNION SELECT NULL,username||'~'||password FROM users--
```

The response returned all user credentials, including the `administrator` account.

### Step 4 — Login

Used the extracted administrator credentials to log in and solve the lab. ✅

---

## Key Concepts

| Concept | Description |
|---|---|
| UNION Attack | Appends a second SELECT to the original query to pull data from other tables |
| Column probing | NULLs are used to match column count; `'a'` tests for string compatibility |
| String concatenation | `||` operator (PostgreSQL/Oracle) combines multiple fields into one column |

---

## Takeaway

SQL Injection continues to rank among the most critical web vulnerabilities (OWASP Top 10). Even a single unsanitized input can expose an entire database. Always use **parameterized queries / prepared statements** to prevent SQLi.

---

*Lab from: [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)*
