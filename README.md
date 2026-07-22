# SecureGate AI — AI-Powered Network Security Gateway & Analytics Platform

A locally deployable, privacy-preserving LAN security monitor. It captures
network traffic, scores it for anomalies with an Isolation Forest model,
explains the risk in plain English (GPT-3.5 or an offline rule-based
engine), and lets you allow/block devices from a dark-themed web dashboard.
Everything runs on a single machine with zero cloud dependency (the OpenAI
call is optional).

Architecture (five layers, data flows top to bottom):

```
capture/    -> pipeline/   -> ml/            -> ai_engine/     -> backend/ (Flask API) -> frontend/ (dashboard)
(Scapy)        (pandas)       (IsolationForest)  (GPT/rules)       (PostgreSQL)             (HTML/JS/Chart.js)
```

## Project structure

```
securegate_ai/
├── .env.example          Environment template — copy to .env
├── .gitignore
├── requirements.txt
├── start_project.sh       One-click startup (Linux/macOS)
├── start_project.bat      One-click startup (Windows)
├── .vscode/               Run/debug configs for VS Code
├── capture/               Phase 3  — Scapy sniffer, parser, DB handler
├── pipeline/              Phase 5  — 5-stage data engineering pipeline
├── ml/                    Phase 6  — dataset generation, training, prediction
├── ai_engine/             Phase 7  — risk scorer, GPT + rule-based explainers
├── backend/               Phase 8/10 — Flask app, models, decision engine
├── frontend/              Phase 9/11 — HTML/CSS/JS dashboard (5 pages)
├── database/              Phase 4  — schema.sql, indexes.sql, seed.py
├── reports/               Phase 11 — PDF report builder, data collectors, scheduler
├── tests/                 Phase 12 — pytest suite
└── models/, logs/         Generated artifacts (git-ignored)
```

## Prerequisites

- Python 3.11+ (3.12 also works)
- PostgreSQL 16 (running locally, or update `.env` to point elsewhere)
- Node not required — the frontend is plain HTML/CSS/JS, no build step
- Optional: Npcap (Windows) or libpcap (Linux/macOS) if you want **live**
  packet capture. Without it, use `--simulate` mode (see below) — this
  works everywhere, including inside VS Code dev containers.

## Quick start

### Option A — one-click script

```bash
# Linux/macOS
./start_project.sh

# Windows
start_project.bat
```

### Option B — step by step (recommended the first time, and in VS Code)

1. **Open the folder in VS Code**: `File > Open Folder... > securegate_ai/`.
   The `.vscode/launch.json` already has run configurations for every
   phase — open the Run and Debug panel and pick one, or follow the
   manual steps below in the integrated terminal.

2. **Create and activate a virtual environment**

   ```bash
   python3 -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   ```

   In VS Code, once `venv/` exists, use **Python: Select Interpreter**
   (Ctrl+Shift+P) and pick `./venv/bin/python` so the integrated terminal
   and test runner use it automatically.

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**

   ```bash
   cp .env.example .env
   ```

   Edit `.env` and set `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` to
   match your PostgreSQL instance. Add `OPENAI_API_KEY` only if you want
   GPT-3.5 explanations — everything works without it (rule-based
   fallback engine).

5. **Create the database and schema**

   ```bash
   python -m database.seed --seed
   ```

   This creates the `network_security` database (if missing), applies
   `database/schema.sql` and `database/indexes.sql`, and loads a few
   sample devices so the dashboard isn't empty on first load.

6. **Generate the training dataset and train the ML model**

   ```bash
   python -m ml.generate_dataset
   python -m ml.training
   ```

   This writes `models/training_dataset.csv`, `models/model.pkl`,
   `models/scaler.pkl`, and `models/score_range.json`, and prints the
   ROC-AUC score (typically ≥ 0.98 on the synthetic dataset).

7. **Start the Flask API**

   ```bash
   python -m backend.app
   ```

   Verify it's up: open http://localhost:5000/health — you should see
   `{"status": "success", "data": {"backend": "online", ...}}`.

8. **Generate traffic** — either live capture or the built-in simulator:

   ```bash
   # Simulated traffic (works everywhere, no admin/root or Npcap needed)
   python -m capture.capture --simulate --duration 120 --rate 3

   # OR live capture (requires Administrator/root + Npcap/libpcap)
   python -m capture.capture --iface eth0
   ```

9. **Run the AI risk assessment pipeline** (scores captured events):

   ```bash
   curl -X POST http://localhost:5000/assess -H "Content-Type: application/json" -d "{\"limit\": 200}"
   ```

10. **Open the dashboard**: open `frontend/index.html` directly in your
    browser (double-click it, or use the VS Code "Open with Live Server"
    extension if you have it). It talks to the API at
    `http://localhost:5000` by default — change
    `window.SECUREGATE_API_BASE` at the top of `frontend/js/api.js` if
    your API runs elsewhere.

11. **Download a PDF report**: http://localhost:5000/report/download, or
    click "Download Today's Report" on the Security Analytics page.

## Running the test suite

```bash
python -m pytest tests/ -v
```

Unit tests (validators, serializers, ML, pipeline stages 2-4, AI engine,
capture parsing) run with no external dependencies. Tests that touch
`backend.models`/`backend.database` directly need a reachable PostgreSQL
instance matching `.env`; the API route tests use mocks and don't need a
live database.

## Pushing this project to GitHub

```bash
cd securegate_ai
git init                                  # skip if already a git repo
git add .gitignore
git commit -m "Add .gitignore"            # commit .gitignore before the big add, so venv/.env are never staged
git add .
git commit -m "Initial commit: SecureGate AI complete implementation"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

Notes:
- `.gitignore` already excludes `venv/`, `.env`, `models/*.pkl`,
  `models/training_dataset.csv`, and generated PDF reports/logs, so your
  repo stays small and never leaks secrets. `models/.gitkeep`,
  `reports/output/.gitkeep`, and `logs/.gitkeep` keep the empty folders
  tracked.
- If you're re-cloning this repo on another machine, just repeat steps
  2–6 above (venv, install, `.env`, DB init, train model) — the code
  itself needs no changes.

## API reference

Base URL `http://localhost:5000`. Every response follows
`{status, message, data}`. Full endpoint list: `/health`, `/devices`,
`/devices/stats`, `/devices/lookup/<ip>`, `/devices/<device_id>`,
`/events`, `/events/protocols`, `/events/hourly`, `/events/<id>`,
`/risks`, `/risks/top`, `/stats`, `/summary`, `/summary/generate`,
`/decisions`, `/decisions/history`, `/decisions/summary`,
`/decisions/active/<ip>`, `/decide`, `/allow`, `/block`, `/revoke/<ip>`,
`/check/<ip>`, `/permitted/<ip>`, `/assess`, `/report/list`,
`/report/generate`, `/report/download`.

## Troubleshooting

- **`psycopg2.OperationalError` on startup** — PostgreSQL isn't running
  or `.env` credentials are wrong. Check `services.msc` (Windows) or
  `systemctl status postgresql` (Linux).
- **`ModelNotTrainedError`** — run `python -m ml.generate_dataset` then
  `python -m ml.training` before calling `/assess`.
- **Scapy/Npcap errors on capture** — use `--simulate` instead; live
  capture needs Npcap (Windows) or libpcap + root/CAP_NET_RAW
  (Linux/macOS).
- **Dashboard shows no data** — make sure the Flask API is running,
  you've generated some events (`capture.capture --simulate`), and
  you've called `POST /assess` at least once to score them.

## Author
Gutta Harshill
RohithPrasad Vagu
