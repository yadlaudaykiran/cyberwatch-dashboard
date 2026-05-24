from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

import threading
import statistics
import os
import time
import smtplib

from email.mime.text import MIMEText
from collections import Counter

import sniffer
import keylogger


# APP
app = Flask(__name__)

app.secret_key = "secret123"



# LOGIN
USERNAME = "admin"

PASSWORD_HASH = generate_password_hash("12345678")


# STATUS
monitoring = False

sniffer_started = False

keylogger_started = False

sent_alerts = set()


# LOGIN PAGE
@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        user = request.form["username"]

        pwd = request.form["password"]

        if user == USERNAME and check_password_hash(PASSWORD_HASH, pwd):

            session["user"] = "ok"

            return redirect("/dashboard")

        return "Invalid Credentials"

    return render_template("login.html")


# DASHBOARD
@app.route("/dashboard")
def dashboard():

    if "user" not in session:

        return redirect("/")

    return render_template("index.html")


# STATUS API
@app.route("/status")
def status():

    return {
        "monitoring": monitoring
    }
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

    for p in packets:

        if "->" in p:

            ip = p.split("->")[0].strip()

            ip_counts[ip] += 1

    labels = list(ip_counts.keys())

    values = list(ip_counts.values())

    return {

        "packets": packets,

        "keys": keys,

        "labels": labels,

        "values": values,

        "monitoring": monitoring
    }

# START
@app.route("/start")
def start():

    global monitoring
    global sniffer_started
    global keylogger_started

    monitoring = True

    sniffer.running = True
    keylogger.running = True

    print("🟢 Monitoring Started")

    # START SNIFFER
    if not sniffer_started:

        threading.Thread(
            target=sniffer.start_sniffer,
            daemon=True
        ).start()

        sniffer_started = True

        print("✅ Sniffer Started")

    # START KEYLOGGER
    if not keylogger_started:

        threading.Thread(
            target=keylogger.start_keylogger,
            daemon=True
        ).start()

        keylogger_started = True

        print("✅ Keylogger Started")

    return {
        "status": "started"
    }


# STOP
@app.route("/stop")
def stop():

    global monitoring

    monitoring = False

    sniffer.running = False

    keylogger.running = False

    print("🔴 Monitoring Stopped")

    return {
        "status": "stopped"
    }


# LOGOUT
@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# AI DETECTION
def detect_anomaly(ip_counts):

    values = list(ip_counts.values())

    if len(values) < 3:

        return []

    avg = statistics.mean(values)

    alerts = []

    for ip, count in ip_counts.items():

        if count > avg * 2:

            alerts.append(
                f"⚠️ AI anomaly from {ip}"
            )

    return alerts


# EMAIL ALERT
def send_email_alert(alerts):

    if not alerts:

        return

    try:

        sender = "YOUR_EMAIL@gmail.com"

        app_password = "YOUR_APP_PASSWORD"

        receiver = "YOUR_EMAIL@gmail.com"

        body = "\n\n".join(alerts)

        msg = MIMEText(body)

        msg["Subject"] = "🚨 Cybersecurity Alerts"

        msg["From"] = sender

        msg["To"] = receiver

        server = smtplib.SMTP(
            "smtp.gmail.com",
            587
        )

        server.starttls()

        server.login(
            sender,
            app_password
        )

        server.sendmail(
            sender,
            receiver,
            msg.as_string()
        )

        server.quit()

        print("📧 Email Sent")

    except Exception as e:

        print("❌ Email Error:", e)


# REAL-TIME MONITOR
def monitor():

    while True:

        try:

            packets = []

            keys = []

            # READ PACKETS
            if os.path.exists("logs/packets.txt"):

                with open("logs/packets.txt") as f:

                    packets = f.readlines()[-20:]

            # READ KEYS
            if os.path.exists("logs/keys.txt"):

                with open("logs/keys.txt") as f:

                    keys = f.readlines()[-20:]

            # COUNT IPS
            ip_counts = Counter()

            for p in packets:

                if "->" in p:

                    ip = p.split("->")[0].strip()

                    ip_counts[ip] += 1

            labels = list(ip_counts.keys())

            values = list(ip_counts.values())

            alerts = []

            email_alerts = []

            # 🚨 HIGH TRAFFIC DETECTION
            for ip, count in ip_counts.items():

                if count > 20:

                    msg = f"🚨 High traffic detected from {ip}"

                    if msg not in sent_alerts:

                        alerts.append(msg)

                        email_alerts.append(msg)

                        sent_alerts.add(msg)

            # 🧠 AI DETECTION
            ai_alerts = detect_anomaly(ip_counts)

            for alert in ai_alerts:

                if alert not in sent_alerts:

                    alerts.append(alert)

                    email_alerts.append(alert)

                    sent_alerts.add(alert)

            # 🔐 SUSPICIOUS KEYWORDS
            suspicious_words = [
                "password",
                "otp",
                "bank"
            ]

            for k in keys:

                for word in suspicious_words:

                    if word in k.lower():

                        msg = f"🔐 Sensitive keyword detected: {word}"

                        if msg not in sent_alerts:

                            alerts.append(msg)

                            email_alerts.append(msg)

                            sent_alerts.add(msg)

            # 📧 SEND EMAIL ONLY FOR SUSPICIOUS ALERTS
            if email_alerts:

                unique_alerts = list(set(email_alerts))

                send_email_alert(unique_alerts)

            print("⚡ Sending live updates...")

            # ⚡ LIVE DASHBOARD UPDATE

        except Exception as e:

            print("❌ Monitor Error:", e)

        time.sleep(2)

# START MONITOR THREAD
threading.Thread(
    target=monitor,
    daemon=True
).start()


# RUN SERVER
if __name__ == "__main__":

    port = int(
        os.environ.get("PORT", 5000)
    )

    print("\n🚀 Cyber Dashboard Running")
    print("🌐 Open Browser:")
    print("👉 http://127.0.0.1:5000\n")

    app.run(

        host="0.0.0.0",

        port=port,

        debug=True

    )