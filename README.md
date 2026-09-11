# Sentinel IQ

A security intelligence workspace for the TransOrg AgentIQ Datathon. Built with Flask, DuckDB, and a small vanilla JavaScript frontend. All telemetry is the organizers' supplied synthetic educational data.

## Run

Requires Python 3.12 or newer.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python pipeline.py
.venv\Scripts\python app.py
```

Open http://localhost:5000. The first application start builds the database if absent.

Implementation and metric documentation will be completed alongside the application.
