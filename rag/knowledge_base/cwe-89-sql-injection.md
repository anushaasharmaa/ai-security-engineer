---
title: SQL Injection
cwe: CWE-89
owasp: A03:2021 - Injection
source: https://cwe.mitre.org/data/definitions/89.html ; https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
---

## What it is
SQL injection happens when an application builds a SQL statement by inserting untrusted input directly into the query text, for example with string concatenation, f-strings, the % operator or str.format. The database cannot tell which part of the statement was written by the developer and which part came from the user, so input containing quotes or SQL keywords changes the meaning of the query.

## Why it is dangerous
An attacker who controls part of a query can read data they are not authorised to see, such as other users' records or password hashes, bypass login checks, modify or delete rows, and in some database configurations execute administrative operations or commands on the database host. A single injectable query is often enough to expose the whole database, which is why SQL injection is treated as a high severity weakness.

## CWE and OWASP mapping
CWE-89 is "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)". It belongs to the OWASP Top 10 2021 category A03 Injection. Related weaknesses are CWE-564 (SQL injection through Hibernate) and CWE-943 (improper neutralization in data query logic, which covers NoSQL injection).

## Secure coding practice
Use parameterized queries (prepared statements) for every database call: keep the SQL text constant and pass values separately, for example cursor.execute("SELECT * FROM users WHERE name = ?", (name,)). An ORM or query builder that binds parameters achieves the same result. Identifiers that cannot be bound, such as table or column names, must come from a fixed allow-list. Give the database account only the privileges the application needs, and never rely on escaping or input filtering alone as the main defence.
