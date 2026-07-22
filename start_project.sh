#!/usr/bin/env bash
# SecureGate AI — one-click startup (Linux/macOS).
# For Windows, use start_project.bat instead.
set -euo pipefail
cd "$(dirname "$0")"

echo "== SecureGate AI startup =="

if [ ! -d "venv" ]; then
  echo "[1/6] Creating virtual environment..."
  python3 -m venv venv
fi
source venv/bin/activate

echo "[2/6] Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

if [ ! -f ".env" ]; then
  echo "[3/6] Creating .env from .env.example (edit DB credentials before continuing)..."
  cp .env.example .env
else
  echo "[3/6] .env already exists, skipping."
fi
set -a; source .env; set +a

echo "[4/6] Initializing database schema (safe to re-run)..."
python -m database.seed --seed || echo "  -> Skipped: check PostgreSQL is running and .env credentials are correct."

if [ ! -f "models/model.pkl" ]; then
  echo "[5/6] Training ML model (first run)..."
  python -m ml.generate_dataset
  python -m ml.training
else
  echo "[5/6] ML model already trained, skipping."
fi

echo "[6/6] Starting Flask API on http://localhost:${FLASK_PORT:-5000} ..."
echo "Open frontend/index.html in your browser once the API is running."
echo "In a second terminal you can run: source venv/bin/activate && python -m capture.capture --simulate"
python -m backend.app
