# AI-Powered Security Engineer for CI/CD

Academic major project, **midterm prototype**. It runs security scanners on every push or pull request, converts their different outputs into one schema, stores the findings, retrieves relevant OWASP/CWE knowledge for each one, and shows an advisory explanation in a dashboard.

> Status: the midterm pipeline below is implemented and tested. Autonomous remediation (patches, pull requests, re-validation) is **not** implemented. See [Scope](#scope).

## Architecture

```
GitHub push / PR ──► GitHub Actions ──┐
                                      ├─► Semgrep ──► semgrep.json ─┐
Local run (scripts/run_pipeline.py) ──┘   Gitleaks ─► gitleaks.json ┤
                                                                    ▼
                                                    Normalizer (one schema)
                                                                    ▼
                                                     FastAPI  POST /findings
                                                                    ▼
                                             PostgreSQL  (findings + pgvector)
                                                                    ▼
                  GET /findings/{id}/analysis ──► RAG retrieval (pgvector similarity)
                                                                    ▼
                                             Advisory explanation (LLM or fallback)
                                                                    ▼
                                                        Streamlit dashboard
```

| Folder | Responsibility |
|---|---|
| `scanners/` | Semgrep rules, Gitleaks config, `run_scans.py` (runs both, writes raw JSON) |
| `normalizer/` | One parser per scanner, a parser registry, the shared `NormalizedFinding` schema |
| `database/` | SQLAlchemy models, engine/session, table creation |
| `backend/` | FastAPI app: `routes/` (HTTP), `services/` (logic), `models/` (Pydantic) |
| `rag/` | Knowledge base, chunking + ingestion, embeddings, retrieval |
| `dashboard/` | Streamlit app (talks to the API over HTTP only) |
| `test-repo/` | Intentionally vulnerable scan target with a fake secret |
| `scripts/` | `run_pipeline.py`: scan, normalize and store in one command |
| `tests/` | 81 tests: parsers, normalization, database, API, RAG, analysis, dashboard, end-to-end |

## Technologies

Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, PostgreSQL 16 with pgvector, Semgrep, Gitleaks, Streamlit, httpx, pytest, GitHub Actions.

## Installation

Prerequisites: Python 3.10+ (developed and tested on 3.12), Docker (for PostgreSQL), Git.

```bash
# 1. Python dependencies
python -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 2. Scanners (standalone tools, not in requirements.txt)
pipx install semgrep                # or: pip install semgrep  in a SEPARATE virtualenv
# Gitleaks v8.19+ : https://github.com/gitleaks/gitleaks/releases
#   macOS: brew install gitleaks    Windows: scoop install gitleaks  (or download the release zip)

# 3. Configuration
cp .env.example .env                # Windows: copy .env.example .env
```

Semgrep is installed separately because it pins OpenTelemetry versions that conflict with FastAPI's. Installing both into one environment makes pip silently downgrade Semgrep.

On Windows, Semgrep's native support is recent. If it gives trouble, use WSL, or rely on the GitHub Actions run and `--skip-scan` (see [GitHub Actions workflow](#github-actions-workflow)).

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection (required) | matches `docker-compose.yml` |
| `TEST_DATABASE_URL` | Separate database used by pytest | `.../security_test_db` |
| `API_URL` | Where the dashboard and pipeline find the API | `http://localhost:8000` |
| `EMBEDDING_PROVIDER` | `hash` or `sentence-transformers` | `hash` |
| `EMBEDDING_MODEL` | Model for sentence-transformers (must be 384-dimensional) | `all-MiniLM-L6-v2` |
| `LLM_API_KEY`, `LLM_MODEL` | Enable the AI explanation. Empty means fallback | empty |
| `LLM_BASE_URL` | Any OpenAI-compatible chat-completions endpoint | `https://api.openai.com/v1` |

No credentials are hardcoded. `.env` is git-ignored. The database password in `.env.example` is a local development default only.

## Database setup

```bash
docker compose up -d db
```

This starts PostgreSQL 16 with pgvector and creates `security_db` plus `security_test_db`. Tables are created automatically when the API (or ingestion) starts. To use an existing PostgreSQL instead, install the `vector` extension and point `DATABASE_URL` at it.

## Running the scanners

```bash
python -m scanners.run_scans --target test-repo --out reports
python -m normalizer --semgrep reports/semgrep.json --gitleaks reports/gitleaks.json \
    --source-root . --output reports/normalized-findings.json
```

- **Semgrep** uses the local rules in `scanners/semgrep/rules/` (6 Python rules: SQL injection, command injection, eval/exec, insecure deserialization, reflected XSS, weak hash). Local rules keep the demo deterministic and need no Semgrep login.
- **Gitleaks** uses its default rules plus one extra rule for the fake placeholder in `test-repo/config.py`. It runs with `--redact`, so secret values never reach reports, the database or the dashboard.

## Running RAG

```bash
python -m rag.ingestion
```

Reads `rag/knowledge_base/*.md` (7 documents: CWE-89, 79, 78, 798, 95, 502, 327), splits each into section chunks, embeds them and stores them in the `knowledge_chunks` table (pgvector). Re-running replaces the table.

Retrieval for a finding:

1. Take the finding's CWE.
2. Embed a query built from the finding's type, CWE, title and description.
3. If that CWE is in the knowledge base, rank its chunks by cosine similarity.
4. Otherwise (no CWE, or a CWE not in the knowledge base) run a similarity search over all chunks and keep only those above a threshold.

Every retrieved chunk is labelled `cwe` or `semantic` so the dashboard shows how it was matched.

**Embeddings.** The default `hash` embedder is a feature-hashing bag of words. It works offline with no model download, but it measures word overlap, not meaning. For semantic embeddings: `pip install sentence-transformers`, set `EMBEDDING_PROVIDER=sentence-transformers`, re-run ingestion.

## Running FastAPI

```bash
uvicorn backend.main:app --reload
```

Interactive docs: http://localhost:8000/docs

| Endpoint | Description |
|---|---|
| `POST /findings` | Store one normalized finding or a list. Known IDs are ignored |
| `GET /findings` | List findings, most severe first. Filters: `severity`, `scanner`, `limit`, `offset` |
| `GET /findings/{id}` | One finding |
| `GET /findings/{id}/analysis` | Retrieved security context plus the explanation |
| `GET /summary` | `{"total", "critical", "high", "medium", "low"}` |
| `GET /health` | API and database status, number of knowledge chunks |

**Explanation.** With `LLM_API_KEY` and `LLM_MODEL` set, the analysis endpoint makes one LLM call with the finding and the retrieved context. Without them (or if the call fails) it uses an extractive fallback that copies the matching sections of the retrieved document. The response field `generated_by` is `llm` or `fallback`, and the dashboard labels which one produced the text. This is a single LLM call, not an agent.

## Running Streamlit

```bash
streamlit run dashboard/app.py
```

Shows the five counts, the findings table (Scanner, Severity, Finding Type, File, Line, Status) and, for the selected finding, the description, evidence, CWE, retrieved context and explanation.

## GitHub Actions workflow

`.github/workflows/security.yml` runs on every `push` and `pull_request`.

- **scan job:** checkout, install Semgrep and Gitleaks, run both with JSON output, normalize, write a findings table to the job summary, upload `semgrep.json`, `gitleaks.json` and `normalized-findings.json` as the `security-reports` artifact.
- **test job:** starts a pgvector PostgreSQL service and runs the full test suite, including the end-to-end test.

Getting CI results into the application:

- **Artifact (default):** download `security-reports` from the workflow run, unzip into `reports/`, then run `python -m scripts.run_pipeline --skip-scan`.
- **Direct (optional):** set the repository secret `SECURITY_API_URL` to a backend reachable from GitHub; the workflow then POSTs the findings itself.

The scan job does not fail when findings exist, because `test-repo/` is vulnerable on purpose.

## End-to-end demo

Four terminals, or run the first three in the background:

```bash
docker compose up -d db                      # 1. database
python -m rag.ingestion                      # 2. load the knowledge base
uvicorn backend.main:app                     # 3. API            (terminal A)
python -m scripts.run_pipeline               # 4. scan + normalize + store (terminal B)
streamlit run dashboard/app.py               # 5. dashboard      (terminal C)
```

Expected output of step 4:

```
[1/3] Scanning test-repo/ with Semgrep and Gitleaks ...
[2/3] Normalizing findings ...
      9 finding(s) {'Semgrep': 8, 'Gitleaks': 1} -> reports/normalized-findings.json
[3/3] Sending findings to http://localhost:8000/findings ...
      received=9 created=9 duplicates=0
Summary: {'total': 9, 'critical': 2, 'high': 5, 'medium': 1, 'low': 1}
```

Suggested walkthrough for the evaluation:

1. Show `test-repo/app.py` and `config.py`: planted vulnerabilities and the fake secret.
2. Push a commit or open a PR; show the Actions run, its job summary table and the artifact.
3. Show `reports/semgrep.json` next to `reports/gitleaks.json` (different structures), then `normalized-findings.json` (one structure).
4. Run the pipeline locally; show `GET /findings` and `GET /summary` in `/docs`.
5. Open the dashboard, select the SQL injection finding: evidence, retrieved CWE-89 context, explanation.
6. Select the Gitleaks finding: the secret is redacted, context comes from CWE-798.
7. Run the pipeline again: `created=0 duplicates=9` (deterministic IDs, no duplicates).
8. Show `test-repo/safe_examples.py`: secure versions of the same code produce no findings.

## Tests

```bash
python -m pytest
```

Parser and normalization tests need nothing external. Database, API, RAG, analysis and dashboard tests need PostgreSQL (`docker compose up -d db`) and use `TEST_DATABASE_URL`, never the demo database. The end-to-end test also needs Semgrep and Gitleaks. Tests that cannot run are skipped with a reason. Tests never call a real LLM.

No accuracy or performance figures are claimed. The tests check that each planted vulnerability is detected and that retrieval returns the matching document for those findings; that is a functional check on a small controlled set, not an evaluation.

## Scope

### IMPLEMENTED FOR MIDTERM

- GitHub Actions workflow (push and pull_request) producing JSON reports
- Semgrep scanning with local rules; Gitleaks secret detection with redaction
- Controlled vulnerable test repository with a fake secret
- Finding normalization: common schema, per-scanner parsers, extensible registry
- FastAPI backend with the five required endpoints plus the analysis endpoint
- PostgreSQL storage, configured through `DATABASE_URL`, started with docker-compose
- RAG foundation: knowledge base, chunking, embeddings, pgvector, similarity retrieval
- Advisory explanation: LLM provider interface plus labelled extractive fallback
- Basic Streamlit dashboard
- Local one-command pipeline and automated tests

### PLANNED FOR FINAL (not implemented, no code pretends otherwise)

- Trivy and Checkov (add a parser class and register it in `normalizer/`)
- LangGraph-based autonomous agent
- AI-generated patches and automatic code modification
- Automatic GitHub pull request creation
- CI re-validation of generated fixes
- Finding lifecycle (status changes, triage), merge gating on severity
- Larger knowledge base, semantic embeddings by default, retrieval evaluation
- Final performance evaluation, polished dashboard, API authentication, schema migrations

## Known limitations

- The default embedder is lexical. Findings worded very differently from the knowledge base may retrieve nothing unless they carry a CWE that is in it.
- The knowledge base documents are short summaries written for this project with links to MITRE CWE and OWASP. OWASP categories refer to the Top 10 2021 edition. Review them against the sources before citing them in a report.
- Semgrep rules cover six Python patterns chosen for the demo; they are not a complete ruleset.
- Finding IDs include the line number, so a finding that moves to another line is treated as new.
- The API has no authentication and is intended for local use.
