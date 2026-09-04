@echo off
cd /d "%~dp0backend"
if not exist venv (
    python -m venv venv
    call venv\Scripts\activate.bat
    pip install -q -r requirements.txt
) else (
    call venv\Scripts\activate.bat
)
start "" http://127.0.0.1:8000
python -m uvicorn main:app --port 8000
