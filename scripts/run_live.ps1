# BrandWatch LIVE server: real providers, separate database + evidence store, port 8766.
# The demo server (DEMO_MODE=true, brandwatch.db, port 8765) is untouched.
#   Run from the project root:   powershell -ExecutionPolicy Bypass -File scripts\run_live.ps1
#   Fresh start (wipe live data): powershell -ExecutionPolicy Bypass -File scripts\run_live.ps1 -Reset
# API keys: Settings -> Provider API keys in the UI (stored encrypted, effective immediately),
# or the *_API_KEY lines in .env (needs a restart of this script).
param([switch]$Reset, [int]$Port = 8766)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$env:DEMO_MODE = "false"
$env:DATABASE_URL = "sqlite:///./brandwatch_live.db"
$env:EVIDENCE_DIR = "./evidence_live"
# free daily newly-registered-domains feed (whoisds.com, no key); the "nrd" stream uses it
if (-not $env:NRD_FEED_PATH) { $env:NRD_FEED_PATH = "whoisds" }
# Automatic scans: the scheduler runs here; each brand switches its own automatic scans on (brand page →
# Automatic scans: how often, when, which tasks). Off for every brand until someone switches it on.
if (-not $env:SCHEDULER_ENABLED) { $env:SCHEDULER_ENABLED = "true" }
# Safety cap for paid providers (SerpAPI, WhoisXML, OpenAI). 0 would mean "unlimited".
if (-not $env:ECONOMIC_LIMITS__MAX_DAILY_SPEND -or $env:ECONOMIC_LIMITS__MAX_DAILY_SPEND -eq "0") {
    $env:ECONOMIC_LIMITS__MAX_DAILY_SPEND = "2"
}

if ($Reset) {
    Remove-Item -Force -ErrorAction SilentlyContinue brandwatch_live.db, brandwatch_live.db-wal, brandwatch_live.db-shm
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue evidence_live
    Write-Host "Live database and evidence wiped."
}

# through python: Windows App Control may block the alembic.exe launcher
& .venv\Scripts\python -m alembic upgrade head
Write-Host "BrandWatch LIVE on http://127.0.0.1:$Port/ui  (DEMO_MODE=false)"
& .venv\Scripts\python -m uvicorn brandwatch.api.main:app --host 127.0.0.1 --port $Port --log-level warning
