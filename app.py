from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    jsonify,
    send_file
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

import threading
import statistics
import os
import time
import smtplib
import sqlite3
import csv

from datetime import datetime
from email.mime.text import MIMEText
from collections import Counter

import requests

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet

import sniffer
import keylogger


# =========================================================
# APP
# =========================================================

app = Flask(__name__)

app.secret_key = "super_secret_key"


# =========================================================
# DATABASE
# =========================================================

DB_NAME = "users.db"


def init_db():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
        """
    )

    conn.commit()

    conn.close()


init_db()


# =========================================================
# GLOBAL STATUS
# =========================================================

monitoring = False

# KEEP MONITOR STATE AFTER REFRESH

if not hasattr(sniffer, "running"):

    sniffer.running = False

if not hasattr(keylogger, "running"):

    keylogger.running = False

sniffer_started = False

keylogger_started = False

sent_alerts = set()

notifications = []


# =========================================================
# LOGIN PAGE
# =========================================================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[0], password):

            session["user"] = username

            return redirect("/dashboard")

        return "Invalid Credentials"

    return render_template("login.html")


# =========================================================
# REGISTER PAGE
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password)

        try:

            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )

            conn.commit()
            conn.close()

            return redirect("/")

        except:

            return "User already exists"

    return render_template("register.html")


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if "user" not in session:

        return redirect("/")

    return render_template("index.html")


# =========================================================
# START MONITORING
# =========================================================

@app.route("/start")
def start():

    global monitoring
    global sniffer_started
    global keylogger_started

    monitoring = True

    sniffer.running = True
    keylogger.running = True

    print("🟢 Monitoring Started")

    if not sniffer_started:

        threading.Thread(
            target=sniffer.start_sniffer,
            daemon=True
        ).start()

        sniffer_started = True

    if not keylogger_started:

        threading.Thread(
            target=keylogger.start_keylogger,
            daemon=True
        ).start()

        keylogger_started = True

    notifications.append(
    f"🟢 Monitoring Started at {datetime.now()}"
)

    return jsonify({"status": "started"})


# =========================================================
# STOP MONITORING
# =========================================================

@app.route("/stop")
def stop():

    global monitoring

    monitoring = False

    sniffer.running = False
    keylogger.running = False

    notifications.append(
    f"🔴 Monitoring Stopped at {datetime.now()}"
)

    return jsonify({"status": "stopped"})


@app.route("/status")
def status():

    global monitoring

    monitoring = (
        sniffer.running and
        keylogger.running
    )

    return jsonify({
        "monitoring": monitoring
    })    


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# =========================================================
# GEO IP LOOKUP
# =========================================================


def get_geo_ip(ip):

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}"
        ).json()

        return {
            "country": response.get("country", "Unknown"),
            "city": response.get("city", "Unknown"),
            "isp": response.get("isp", "Unknown")
        }

    except:

        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown"
        }


# =========================================================
# AI DETECTION
# =========================================================


def detect_anomaly(ip_counts):

    values = list(ip_counts.values())

    if len(values) < 3:

        return []

    avg = statistics.mean(values)

    alerts = []

    for ip, count in ip_counts.items():

        if count > avg * 2:

            alerts.append(
                f"⚠️ AI anomaly detected from {ip}"
            )

    return alerts


# =========================================================
# EMAIL ALERTS
# =========================================================


def send_email_alert(alerts):

    if not alerts:

        return

    try:

        sender = os.environ.get("EMAIL_USER")
        password = os.environ.get("EMAIL_PASSWORD")
        receiver = os.environ.get("EMAIL_RECEIVER")

        if not sender or not password or not receiver:

            print("⚠️ Email environment variables missing")

            return

        body = "\n\n".join(alerts)

        msg = MIMEText(body)

        msg["Subject"] = "🚨 CyberWatch Alerts"
        msg["From"] = sender
        msg["To"] = receiver

        server = smtplib.SMTP(
            "smtp.gmail.com",
            587
        )

        server.starttls()

        server.login(sender, password)

        server.sendmail(
            sender,
            receiver,
            msg.as_string()
        )

        server.quit()

        print("📧 Alert Email Sent")

    except Exception as e:

        print("❌ Email Error:", e)


# =========================================================
# LIVE DATA API
# =========================================================

@app.route("/live_data")
def live_data():

    packets = []
    keys = []

    if os.path.exists("logs/packets.txt"):

        with open("logs/packets.txt") as f:

            packets = f.readlines()[-20:]

    if os.path.exists("logs/keys.txt"):

        with open("logs/keys.txt") as f:

            keys = f.readlines()[-20:]

    ip_counts = Counter()

    geo_data = []

    for p in packets:

        if "->" in p:

            ip = p.split("->")[0].strip()

            ip_counts[ip] += 1

    labels = list(ip_counts.keys())
    values = list(ip_counts.values())

    for ip in labels:

        geo = get_geo_ip(ip)

        geo_data.append({
            "ip": ip,
            "country": geo["country"],
            "city": geo["city"],
            "isp": geo["isp"]
        })

    return jsonify({

        "packets": packets,
        "keys": keys,
        "labels": labels,
        "values": values,
        "geo": geo_data,
        "notifications": notifications[-10:],
        "monitoring": monitoring
    })


# =========================================================
# EXPORT CSV REPORT
# =========================================================

@app.route("/export/csv")
def export_csv():

    csv_path = "logs/report.csv"

    with open(csv_path, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Type",
            "Data"
        ])

        if os.path.exists("logs/packets.txt"):

            with open("logs/packets.txt") as f:

                for line in f.readlines()[-50:]:

                    writer.writerow([
                        "Packet",
                        line.strip()
                    ])

        if os.path.exists("logs/keys.txt"):

            with open("logs/keys.txt") as f:

                for line in f.readlines()[-50:]:

                    writer.writerow([
                        "Key",
                        line.strip()
                    ])

    return send_file(
        csv_path,
        as_attachment=True
    )


# =========================================================
# EXPORT PDF REPORT
# =========================================================

@app.route("/export/pdf")
def export_pdf():

    pdf_path = "logs/report.pdf"

    doc = SimpleDocTemplate(pdf_path)

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph(
            "CyberWatch Dashboard Report",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 12))

    # PACKETS
    if os.path.exists("logs/packets.txt"):

        elements.append(
            Paragraph(
                "Recent Packets",
                styles["Heading2"]
            )
        )

        with open("logs/packets.txt") as f:

            for line in f.readlines()[-30:]:

                elements.append(
                    Paragraph(
                        line,
                        styles["BodyText"]
                    )
                )

    elements.append(Spacer(1, 12))

    # KEYSTROKES
    if os.path.exists("logs/keys.txt"):

        elements.append(
            Paragraph(
                "Recent Keystrokes",
                styles["Heading2"]
            )
        )

        with open("logs/keys.txt") as f:

            for line in f.readlines()[-30:]:

                elements.append(
                    Paragraph(
                        line,
                        styles["BodyText"]
                    )
                )

    # BUILD PDF
    doc.build(elements)

    # RETURN FILE
    return send_file(
        pdf_path,
        as_attachment=True
    )

# =========================================================
# RUN APP
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get("PORT", 5000)
    )

    print("\n🚀 CyberWatch Dashboard Running")
    print("🌐 http://127.0.0.1:5000/register\n")

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )