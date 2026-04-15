@echo off
echo Installing dependencies...
pip install -r requirements.txt --quiet
echo.
echo Starting Network Scanner at http://127.0.0.1:5000
echo Press Ctrl+C to stop.
echo.
python app.py
pause
