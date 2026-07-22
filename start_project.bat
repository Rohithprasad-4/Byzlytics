@echo off
REM SecureGate AI — one-click startup (Windows).
REM Requires Python 3.11+, PostgreSQL 16 running, and Npcap installed
REM if you plan to run live packet capture (capture.py without --simulate).

cd /d "%~dp0"
echo == SecureGate AI startup ==

if not exist venv (
    echo [1/6] Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate

echo [2/6] Installing dependencies...
pip install -q --upgrade pip
pip install -q -r requirements.txt

if not exist .env (
    echo [3/6] Creating .env from .env.example - edit DB credentials before continuing.
    copy .env.example .env
) else (
    echo [3/6] .env already exists, skipping.
)

echo [4/6] Initializing database schema (safe to re-run)...
python -m database.seed --seed

if not exist models\model.pkl (
    echo [5/6] Training ML model (first run)...
    python -m ml.generate_dataset
    python -m ml.training
) else (
    echo [5/6] ML model already trained, skipping.
)

echo [6/6] Starting Flask API on http://localhost:5000 ...
echo Open frontend\index.html in your browser once the API is running.
echo In a second Command Prompt run: venv\Scripts\activate ^&^& python -m capture.capture --simulate
python -m backend.app
