# CyberShield Mini SIEM
Beginner-friendly defensive cybersecurity mini project using Python, Flask, SQLite, HTML/CSS and Chart.js.

## Run on Windows
```bat
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 and click **Load sample demo data**.

## Detection rule
5 or more failed logins from the same IP within 60 seconds creates a HIGH alert.

## CSV columns
timestamp, username, ip_address, result

Use only synthetic data or logs you are authorized to analyze. This is an educational prototype, not production SIEM software.
