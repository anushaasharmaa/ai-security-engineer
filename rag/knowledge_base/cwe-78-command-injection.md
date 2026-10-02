---
title: OS Command Injection
cwe: CWE-78
owasp: A03:2021 - Injection
source: https://cwe.mitre.org/data/definitions/78.html ; https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
---

## What it is
OS command injection happens when an application builds an operating system command from untrusted input and runs it through a shell, for example with os.system, os.popen or subprocess called with shell=True. Shell metacharacters such as ; | & $( ) and backticks let the input end the intended command and start another one.

## Why it is dangerous
The injected command runs with the same privileges as the application process. An attacker can read or delete files, steal credentials and environment variables, install malware, open a reverse shell, or move to other systems on the network. In practice command injection usually means full compromise of the server, so it is treated as a critical weakness.

## CWE and OWASP mapping
CWE-78 is "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)". It belongs to the OWASP Top 10 2021 category A03 Injection. The closely related CWE-77 covers command injection in general, and CWE-88 covers injection of extra arguments into a command.

## Secure coding practice
Avoid running OS commands when a library function can do the job. When a command is required, pass the program and its arguments as a list and do not use a shell, for example subprocess.run(["ping", "-c", "1", host]) with the default shell=False, so input is never parsed as shell syntax. Validate the input against a strict allow-list (for example a hostname pattern) and place "--" before user-supplied arguments so they cannot be read as options. Run the process with the lowest privileges possible.
