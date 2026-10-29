from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from pathlib import Path
import csv, io
from database import init_db, add_event, get_dashboard_data, get_alerts, clear_demo_data
from detector import detect_brute_force

app = Flask(__name__)
app.secret_key = "local-demo-secret-change-before-deployment"
BASE_DIR = Path(__file__).resolve().parent
init_db()

def process_rows(rows):
    cleaned = []
    for row in rows:
        timestamp = (row.get("timestamp") or "").strip()
        username = (row.get("username") or "unknown").strip()[:100]
        ip = (row.get("ip_address") or "").strip()[:100]
        result = (row.get("result") or "").strip().lower()
        if timestamp and ip and result in ("success", "failed"):
            cleaned.append({"timestamp": timestamp, "username": username, "ip_address": ip, "result": result})
    for event in cleaned:
        add_event(event)
    detect_brute_force(cleaned)
    return len(cleaned)

@app.route("/")
def index():
    return render_template("index.html", data=get_dashboard_data(), alerts=get_alerts(8))

@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html", alerts=get_alerts(200))

@app.route("/load-sample", methods=["POST"])
def load_sample():
    try:
        with (BASE_DIR/"data"/"sample_logs.csv").open(encoding="utf-8-sig", newline="") as f:
            count = process_rows(csv.DictReader(f))
        flash(f"Loaded {count} sample events and analyzed them.", "success")
    except Exception as e:
        flash(f"Could not load sample data: {e}", "error")
    return redirect(url_for("index"))

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("logfile")
    if not f or not f.filename.lower().endswith(".csv"):
        flash("Please choose a CSV file.", "error")
        return redirect(url_for("index"))
    try:
        text = f.stream.read().decode("utf-8-sig")
        count = process_rows(csv.DictReader(io.StringIO(text)))
        flash(f"Imported {count} valid events.", "success")
    except Exception as e:
        flash(f"Could not read CSV: {e}", "error")
    return redirect(url_for("index"))

@app.route("/export-alerts")
def export_alerts():
    rows = get_alerts(10000)
    out = io.StringIO()
    fields = ["created_at","ip_address","severity","title","details"]
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    writer.writerows({k:r.get(k,"") for k in fields} for r in rows)
    mem = io.BytesIO(out.getvalue().encode("utf-8-sig"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="cybershield_alerts.csv")

@app.route("/reset-demo", methods=["POST"])
def reset_demo():
    clear_demo_data()
    flash("Local demo data cleared.", "success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
