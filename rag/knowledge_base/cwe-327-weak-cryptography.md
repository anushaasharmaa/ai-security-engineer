---
title: Weak Cryptographic Hash (MD5 and SHA-1)
cwe: CWE-327
owasp: A02:2021 - Cryptographic Failures
source: https://cwe.mitre.org/data/definitions/327.html ; https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
---

## What it is
This weakness is the use of a broken or risky cryptographic algorithm. The most common example is hashing with MD5 or SHA-1 for a security purpose such as password storage, digital signatures or integrity checks. Practical collision attacks exist for both algorithms.

## Why it is dangerous
Because collisions can be produced, an attacker can create two different inputs with the same MD5 or SHA-1 hash and defeat integrity or signature checks. For passwords the problem is speed: fast hashes like MD5, SHA-1 and even plain SHA-256 allow billions of guesses per second on commodity hardware, so leaked password hashes are cracked quickly, especially when no salt is used.

## CWE and OWASP mapping
CWE-327 is "Use of a Broken or Risky Cryptographic Algorithm". Related entries are CWE-328 (use of weak hash) and CWE-916 (use of password hash with insufficient computational effort). These belong to the OWASP Top 10 2021 category A02 Cryptographic Failures.

## Secure coding practice
For integrity checks and fingerprints use SHA-256 or SHA-3. For password storage use a dedicated, slow, salted password hashing function: Argon2id is the preferred choice, with scrypt, bcrypt or PBKDF2 as alternatives. Use a maintained library such as argon2-cffi or bcrypt instead of writing the scheme yourself. MD5 is acceptable only for non-security uses such as cache keys or detecting accidental corruption.
