import sqlite3
from pathlib import Path
from datetime import datetime
DB_PATH = Path(__file__).resolve().parent / "cybershield.db"

def connect():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with connect() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            username TEXT NOT NULL, ip_address TEXT NOT NULL,
            result TEXT NOT NULL, imported_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            ip_address TEXT NOT NULL, severity TEXT NOT NULL,
            title TEXT NOT NULL, details TEXT NOT NULL,
            event_key TEXT UNIQUE NOT NULL)""")

def add_event(e):
    with connect() as c:
        c.execute("INSERT INTO events(timestamp,username,ip_address,result,imported_at) VALUES(?,?,?,?,?)",
                  (e["timestamp"],e["username"],e["ip_address"],e["result"],datetime.now().isoformat(timespec="seconds")))

def add_alert(ip, severity, title, details, key):
    with connect() as c:
        c.execute("INSERT OR IGNORE INTO alerts(created_at,ip_address,severity,title,details,event_key) VALUES(?,?,?,?,?,?)",
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),ip,severity,title,details,key))

def get_dashboard_data():
    with connect() as c:
        total=c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        failed=c.execute("SELECT COUNT(*) FROM events WHERE result='failed'").fetchone()[0]
        success=c.execute("SELECT COUNT(*) FROM events WHERE result='success'").fetchone()[0]
        alerts=c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        ips=c.execute("SELECT COUNT(DISTINCT ip_address) FROM alerts").fetchone()[0]
    return {"total":total,"failed":failed,"success":success,"alert_count":alerts,
            "suspicious_ips":ips,"chart_labels":["Success","Failed"],
            "chart_values":[success,failed]}

def get_alerts(limit=100):
    with connect() as c:
        rows=c.execute("SELECT created_at,ip_address,severity,title,details FROM alerts ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [dict(r) for r in rows]

def clear_demo_data():
    with connect() as c:
        c.execute("DELETE FROM events")
        c.execute("DELETE FROM alerts")
