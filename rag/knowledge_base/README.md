# Security knowledge base

Small, controlled document set for the midterm RAG demo. Each file is a short
summary written for this project, organised around one weakness, with links to
the primary sources (MITRE CWE, OWASP Top 10 2021, OWASP Cheat Sheet Series).

Format: a front-matter block (`title`, `cwe`, `owasp`, `source`) followed by
`##` sections. `rag/ingestion.py` turns every section into one or more chunks.

To extend the knowledge base, add a file in the same format and re-run
`python -m rag.ingestion`.
