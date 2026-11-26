@echo off
echo Starting Cybersecurity Threat Detection and Analysis...
if not exist venv\Scripts\python.exe (
  echo Creating virtual environment...
  python -m venv venv
)
call venv\Scripts\activate.bat
pip install -r requirements.txt
python app.py
pause
