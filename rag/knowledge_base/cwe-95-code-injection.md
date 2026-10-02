---
title: Code Injection (eval and exec)
cwe: CWE-95
owasp: A03:2021 - Injection
source: https://cwe.mitre.org/data/definitions/95.html ; https://cwe.mitre.org/data/definitions/94.html ; https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
---

## What it is
Code injection occurs when an application passes untrusted input to a function that interprets text as program code. In Python the usual causes are eval, exec and compile. The attacker's input is executed as code inside the running application.

## Why it is dangerous
Evaluated input has the full power of the language. An attacker can import modules, read files and environment variables, open network connections and start processes, which amounts to remote code execution with the privileges of the application. Attempts to restrict eval by removing builtins or filtering keywords are regularly bypassed.

## CWE and OWASP mapping
CWE-95 is "Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)". Its parent is CWE-94, "Improper Control of Generation of Code (Code Injection)". Both belong to the OWASP Top 10 2021 category A03 Injection.

## Secure coding practice
Do not evaluate user input as code. To read literal values such as numbers, lists or dictionaries use ast.literal_eval or json.loads. For calculations use a dedicated expression parser, or map allowed operation names to functions with a dictionary instead of executing text. If dynamic behaviour is required, select from a fixed allow-list of predefined operations rather than accepting arbitrary expressions.
