---
title: Insecure Deserialization
cwe: CWE-502
owasp: A08:2021 - Software and Data Integrity Failures
source: https://cwe.mitre.org/data/definitions/502.html ; https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
---

## What it is
Insecure deserialization happens when an application rebuilds objects from serialized data that an attacker can control, using a format that is able to create arbitrary objects. In Python the common cases are pickle.load and pickle.loads, and yaml.load used without a safe loader.

## Why it is dangerous
Formats such as pickle can instruct the interpreter to call arbitrary functions while the data is being loaded. A crafted payload therefore leads to remote code execution as soon as it is deserialized, before the application looks at the result. Other outcomes include denial of service and tampering with application state or access control data.

## CWE and OWASP mapping
CWE-502 is "Deserialization of Untrusted Data". It belongs to the OWASP Top 10 2021 category A08 Software and Data Integrity Failures (in the 2017 edition it was a separate category, A8 Insecure Deserialization).

## Secure coding practice
Never unpickle data from an untrusted or unauthenticated source. Exchange data in a format that only describes data, such as JSON, and validate it against a schema. For YAML use yaml.safe_load. If a native serialization format cannot be avoided, sign the serialized data with an HMAC and verify the signature before loading, and accept it only from authenticated parties.
