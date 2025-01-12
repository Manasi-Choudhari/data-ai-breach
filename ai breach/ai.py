# AI-Driven Data Breach Detection Tool

import os
import time
import hashlib
import smtplib
import socket
from datetime import datetime
from sklearn.ensemble import IsolationForest
from flask import Flask, request, jsonify
import json
import pandas as pd
import logging

# ================== CONFIGURATION ===================
# Email Configuration for Alerts
ADMIN_EMAIL = "admin@example.com"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
EMAIL_USER = "your_email@example.com"
EMAIL_PASSWORD = "your_password"

# Thresholds
FAILED_LOGIN_THRESHOLD = 5
ODD_HOURS_START = 22  # 10 PM
ODD_HOURS_END = 6    # 6 AM
ANOMALY_THRESHOLD = 0.05

# Flask App Setup
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, filename='activity.log', filemode='a', 
                    format='%(asctime)s - %(message)s')

# ================== GLOBAL VARIABLES ===================
data_access_logs = []  # Store data access logs in memory
login_attempts = []  # Track login attempts for anomaly detection
known_ips = set()  # Whitelisted IPs
blocked_ips = set()  # Temporarily blocked IPs
file_hashes = {}  # Track file integrity (filename: hash)

# ================== HELPER FUNCTIONS ===================

# Email Notification
def send_email(subject, body):
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            message = f"Subject: {subject}\n\n{body}"
            server.sendmail(EMAIL_USER, ADMIN_EMAIL, message)
            logging.info(f"Alert email sent to {ADMIN_EMAIL}.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

# Hash File for Integrity Check
def hash_file(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None

# Check Regular Login Timing
def is_odd_hour():
    current_hour = datetime.now().hour
    return ODD_HOURS_START <= current_hour or current_hour < ODD_HOURS_END

# Log Blockchain Data
# Placeholder: Replace with your blockchain API or SDK integration
def log_to_blockchain(event):
    # Simulate blockchain logging (to be replaced by actual blockchain implementation)
    logging.info(f"Blockchain log: {event}")

# ================== FEATURE IMPLEMENTATIONS ===================

# Anomaly Detection for IP Access
@app.route('/log_access', methods=['POST'])
def log_access():
    global known_ips

    data = request.json
    ip = data.get('ip')
    timestamp = data.get('timestamp')

    # Detect unknown IP
    if ip not in known_ips:
        subject = "Unknown IP Access Detected"
        body = f"Data access from unknown IP: {ip} at {timestamp}"
        send_email(subject, body)

    # Log the event
    event = {'ip': ip, 'timestamp': timestamp}
    data_access_logs.append(event)
    log_to_blockchain(event)

    return jsonify({"status": "logged", "event": event})

# Login Failure Tracking
@app.route('/login_attempt', methods=['POST'])
def login_attempt():
    global blocked_ips

    data = request.json
    ip = data.get('ip')
    success = data.get('success')

    # Track login attempts
    login_attempts.append({'ip': ip, 'timestamp': datetime.now(), 'success': success})
    
    if not success:
        failure_count = sum(1 for attempt in login_attempts[-FAILED_LOGIN_THRESHOLD:] if attempt['ip'] == ip and not attempt['success'])
        if failure_count >= FAILED_LOGIN_THRESHOLD:
            blocked_ips.add(ip)
            subject = "Multiple Login Failures Detected"
            body = f"IP {ip} has been temporarily blocked due to {failure_count} failed login attempts."
            send_email(subject, body)
            log_to_blockchain({'action': 'block_ip', 'ip': ip, 'reason': 'multiple_failures'})

    return jsonify({"status": "attempt logged", "ip": ip})

# Timing Tracking
@app.route('/check_timing', methods=['GET'])
def check_timing():
    odd_hour = is_odd_hour()
    if odd_hour:
        subject = "Login During Odd Hours"
        body = "A login was detected during odd hours. Please verify this activity."
        send_email(subject, body)

    return jsonify({"odd_hour": odd_hour})

# File Integrity Check
@app.route('/check_file_integrity', methods=['POST'])
def check_file_integrity():
    global file_hashes

    data = request.json
    filename = data.get('filename')
    current_hash = hash_file(filename)

    if not current_hash:
        return jsonify({"error": "File not found"}), 404

    if filename in file_hashes and file_hashes[filename] != current_hash:
        subject = "File Corruption Detected"
        body = f"The file {filename} has been tampered with. It has been locked for security."
        send_email(subject, body)
        log_to_blockchain({'action': 'lock_file', 'file': filename})
        return jsonify({"status": "file locked", "filename": filename})

    # Update hash if not present
    file_hashes[filename] = current_hash
    return jsonify({"status": "file integrity intact", "filename": filename})

# ================== MAIN APP ===================
if __name__ == '__main__':
    # Preload known IPs (e.g., from a database)
    known_ips = {"192.168.1.1", "127.0.0.1"}

    # Example file hash preload (simulate previous integrity check)
    file_hashes["example.txt"] = hash_file("example.txt")

    # Start Flask App
    app.run(debug=True, port=5000)