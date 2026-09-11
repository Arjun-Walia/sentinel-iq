# SentinalIQ

A security intelligence workspace with connected telemetry, clear investigations, and evidence-grounded AI.

[Open SentinalIQ](https://sentinaliq.tech)

## What it does

- **Overview:** filter risk, activity, departments, and source coverage.
- **Explore:** search events, inspect source records, and export evidence.
- **Investigate:** connect hosts across IAM, firewall, and endpoint activity.
- **Ask AI:** ask DeepSeek V4 Flash questions, follow up, and inspect cited results.
- **Data quality:** see normalization decisions and unresolved records.

Responsive layouts, light/dark themes, and a guided dashboard tour are included.

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
Copy-Item .env.example .env
.venv\Scripts\python app.py
```

Open **http://localhost:5000**. Set `DEEPSEEK_API_KEY` in `.env` for AI answers. The model defaults to `deepseek-v4-flash`; set `DEEPSEEK_MODEL` to override it. Never commit `.env`.

## How AI answers work

DeepSeek reads the schema and recent conversation, then plans up to three data queries. The server validates fields and operations, executes parameterized, read-only queries in DuckDB, and retrieves matching event examples. DeepSeek generates its answer from those results.

Charts use the same retrieved data. **Q** citations open query results; **E** citations open source events. No predefined answer catalog or silent fallback exists. Missing credentials, provider failures, and invalid answers are shown explicitly.

This is structured RAG over tabular telemetry, without a vector database. Questions are limited by the available schema and retrieval operations. The question, recent conversation, query results, and selected event examples are sent to DeepSeek. Model interpretations still need analyst review.

## Project map

| File | Purpose |
| --- | --- |
| `app.py` | Flask routes, analytics, exports, investigations |
| `rag.py` | Retrieval planning, validation, and answer generation |
| `pipeline.py` | Source cleanup and DuckDB build |
| `templates/` + `static/` | Dashboard UI, styles, scripts, fonts |
| `public/` | Social preview, favicon, manifest, robots, sitemap |
| `data/` | Bundled analytical database and quality report |

Rebuild the included synthetic dataset with `python pipeline.py`. There are **58,000 telemetry events**. Time windows end at the latest dataset observation, **September 9, 2026**. Risk scores are prioritization heuristics, not proof of compromise.

## Check and deploy

```powershell
.venv\Scripts\python -m pytest -q
node --check static/app.js
```

GitHub pushes deploy to Vercel. Set the DeepSeek key in the project's production environment. Vercel Web Analytics is enabled on Hobby; no paid Vercel plan is required. DeepSeek usage is billed separately by the model provider.

Investigation notes persist locally in SQLite. On Vercel they are temporary per server instance; a durable shared store is needed for permanent notes. The demo uses synthetic data and has no authentication.
