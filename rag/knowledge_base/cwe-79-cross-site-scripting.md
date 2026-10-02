---
title: Cross-Site Scripting (XSS)
cwe: CWE-79
owasp: A03:2021 - Injection
source: https://cwe.mitre.org/data/definitions/79.html ; https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
---

## What it is
Cross-site scripting occurs when an application includes untrusted data in a web page without encoding it for the place where it is inserted. The browser then interprets the data as HTML or JavaScript. Reflected XSS returns the payload straight from the current request, stored XSS saves it and serves it to other users later, and DOM-based XSS happens when client-side script writes untrusted data into the page.

## Why it is dangerous
Injected script runs in the victim's browser with the privileges of the vulnerable site. It can steal session cookies or tokens, perform actions as the victim, read page content, log keystrokes, or redirect the user to a phishing page. Stored XSS affects every user who views the infected page, including administrators.

## CWE and OWASP mapping
CWE-79 is "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)". In the OWASP Top 10 2021 it is part of category A03 Injection (in the 2017 edition it was a separate category, A7 Cross-Site Scripting).

## Secure coding practice
Encode output for its context: HTML-escape data placed in HTML, and use the correct encoding for attributes, JavaScript and URLs. Prefer a template engine with automatic escaping, such as Jinja2 templates rendered through Flask's render_template, instead of building HTML with string formatting. Do not disable auto-escaping or mark user data as safe. When users must submit rich HTML, clean it with a maintained sanitizer library. Add a Content Security Policy and set the HttpOnly flag on session cookies as defence in depth.
