---
title: Hardcoded Credentials and Secrets
cwe: CWE-798
owasp: A07:2021 - Identification and Authentication Failures
source: https://cwe.mitre.org/data/definitions/798.html ; https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
---

## What it is
A hardcoded credential is a password, API key, token or private key written directly in source code, configuration files or scripts that are committed to version control. The secret is then shipped with every copy of the code instead of being supplied to the application at runtime.

## Why it is dangerous
Everyone who can read the repository, including former team members, CI systems and anyone who obtains a leaked or public copy, gains the access the secret grants. The secret stays in git history even after the line is deleted. Hardcoded secrets are hard to rotate because changing them requires a code change and redeployment, and automated scanners continuously search public repositories for exposed keys.

## CWE and OWASP mapping
CWE-798 is "Use of Hard-coded Credentials". Its children are CWE-259 (hard-coded password) and CWE-321 (hard-coded cryptographic key). CWE-798 is mapped to the OWASP Top 10 2021 category A07 Identification and Authentication Failures.

## Secure coding practice
Keep secrets out of source code. Load them at runtime from environment variables or from a secrets manager such as HashiCorp Vault, AWS Secrets Manager or GitHub Actions secrets, and keep local .env files out of version control. If a secret has been committed, treat it as compromised: revoke and rotate it first, then remove it from the code. Deleting the line is not enough because it remains in history. Run a secret scanner such as Gitleaks in pre-commit hooks and in CI to stop new secrets from being committed.
