
import os
import json
from functools import wraps
from pathlib import Path
from datetime import datetime

import pandas as pd

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory, abort
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from src.analysis_utils import (
    load_data,
    prepare_data,
    run_analysis,
    DATA_DIR,
    GRAPH_DIR,
    OUTPUT_DIR,
    REPORT_DIR,
    resolve_columns,
    protocol_series,
    create_rule_flags
)

app = Flask(__name__)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "change-this-secret-before-deployment"
)

ROOT = Path(__file__).resolve().parent

USER_FILE = ROOT / "users" / "users.json"
USER_FILE.parent.mkdir(parents=True, exist_ok=True)


# ---------------- USER MANAGEMENT HELPERS ----------------

def read_users():
    if not USER_FILE.exists():
        USER_FILE.write_text("{}", encoding="utf-8")

    try:
        data = json.loads(USER_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_users(users):
    USER_FILE.write_text(
        json.dumps(users, indent=2),
        encoding="utf-8"
    )


def get_admin_email():
    return os.getenv(
        "ADMIN_EMAIL",
        "admin@cybersecure.local"
    ).lower()


def is_admin_email(email):
    return email.lower() == get_admin_email()


# ---------------- USER ACTIVITY LOG SYSTEM ----------------

ACTIVITY_FILE = OUTPUT_DIR / "user_activity.json"
ACTIVITY_FILE.parent.mkdir(parents=True, exist_ok=True)


def read_activity_logs():
    if not ACTIVITY_FILE.exists():
        return []

    try:
        with open(ACTIVITY_FILE, "r", encoding="utf-8") as file:
            logs = json.load(file)

        return logs if isinstance(logs, list) else []

    except (json.JSONDecodeError, OSError):
        return []


def log_activity(email, name, role, action):
    logs = read_activity_logs()

    logs.insert(0, {
        "email": email,
        "name": name,
        "role": role,
        "action": action,
        "time": datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")
    })

    with open(ACTIVITY_FILE, "w", encoding="utf-8") as file:
        json.dump(logs[:1000], file, indent=4)


# ---------------- REGISTRATION DATE RECOVERY ----------------

def get_registration_date(email):
    logs = read_activity_logs()

    # Oldest matching Registration entry
    for log in reversed(logs):

        log_email = str(log.get("email", "")).lower()

        if (
            log_email == email.lower()
            and log.get("action") == "Registration"
        ):
            return log.get("time", "Date unavailable")

    return "Date unavailable"


# ---------------- LOGIN SECURITY ----------------

def login_required(role=None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):

            if "email" not in session:
                return redirect(url_for("login"))

            if role and session.get("role") != role:
                flash(
                    "You do not have permission to access that page.",
                    "error"
                )
                return redirect(url_for("dashboard"))

            return view(*args, **kwargs)

        return wrapped
    return decorator


# ---------------- DASHBOARD DATA ----------------

def get_dashboard_data():

    csv_path = DATA_DIR / "cybersecurity_data.csv"
    is_demo = False

    if not csv_path.exists():
        csv_path = DATA_DIR / "demo_cybersecurity_data.csv"
        is_demo = True

    if not csv_path.exists():
        return {
            "available": False,
            "is_demo": False,
            "rows": 0,
            "columns": 0,
            "normal": 0,
            "flagged": 0,
            "labels": [],
            "protocols": [],
            "graphs": [],
            "message": "Dataset not added. Save a CSV file as Dataset/cybersecurity_data.csv."
        }

    df = load_data(csv_path)
    prepared, mapping = prepare_data(df)
    cleaned = prepared.drop_duplicates()

    labels = []
    normal = 0
    flagged = 0

    if "label" in mapping:

        label_series = (
            cleaned[mapping["label"]]
            .fillna("Unknown")
            .astype(str)
            .str.strip()
        )

        labels = [
            {"name": str(k), "count": int(v)}
            for k, v in label_series.value_counts().head(8).items()
        ]

        normal = int(
            label_series.str.lower()
            .str.contains(r"benign|normal", regex=True)
            .sum()
        )

        flagged = int(
            (~label_series.str.lower()
             .str.contains(r"benign|normal|unknown", regex=True)).sum()
        )

    else:

        flags, _, _ = create_rule_flags(cleaned, mapping)

        flagged = int(flags.sum())
        normal = max(0, len(cleaned) - flagged)

        labels = [
            {"name": "Rule flagged for review", "count": flagged},
            {"name": "Not flagged by selected rules", "count": normal}
        ]

    protocols = protocol_series(cleaned, mapping)
    protocol_list = []

    if protocols is not None:
        protocol_list = [
            {"name": str(k), "count": int(v)}
            for k, v in protocols.value_counts().head(6).items()
        ]

    run_analysis(prepared, mapping, csv_path.name)

    graph_files = sorted(p.name for p in GRAPH_DIR.glob("*.png"))

    return {
        "available": True,
        "is_demo": is_demo,
        "rows": int(len(cleaned)),
        "columns": int(cleaned.shape[1]),
        "normal": normal,
        "flagged": flagged,
        "labels": labels,
        "protocols": protocol_list,
        "graphs": graph_files,
        "message": ""
    }


# ---------------- THREAT DETECTION DATA ----------------

def get_threat_detection_data():

    csv_path = DATA_DIR / "cybersecurity_data.csv"
    is_demo = False

    if not csv_path.exists():
        csv_path = DATA_DIR / "demo_cybersecurity_data.csv"
        is_demo = True

    if not csv_path.exists():
        return {
            "available": False,
            "is_demo": False,
            "total": 0,
            "normal": 0,
            "flagged": 0,
            "labels": [],
            "protocols": [],
            "top_sources": [],
            "records": [],
            "columns": [],
            "message": "Cybersecurity dataset not found."
        }

    df = load_data(csv_path)
    prepared, mapping = prepare_data(df)
    cleaned = prepared.drop_duplicates().copy()

    total = len(cleaned)
    labels = []
    records = []
    top_sources = []
    normal = 0
    flagged = 0
    detection_basis = "Dataset labels"

    if "label" in mapping:

        label_col = mapping["label"]

        label_series = (
            cleaned[label_col]
            .fillna("Unknown")
            .astype(str)
            .str.strip()
        )

        lower_labels = label_series.str.lower()

        normal_mask = lower_labels.str.contains(
            r"benign|normal", regex=True
        )

        unknown_mask = lower_labels.isin(
            ["unknown", "", "nan", "none"]
        )

        attack_mask = ~normal_mask & ~unknown_mask

        normal = int(normal_mask.sum())
        flagged = int(attack_mask.sum())

        counts = label_series[attack_mask].value_counts()

        labels = [
            {"name": str(name), "count": int(count)}
            for name, count in counts.head(15).items()
        ]

        threat_data = cleaned.loc[attack_mask].copy()

    else:

        detection_basis = "Rule-based review"

        flags, reasons, rules = create_rule_flags(cleaned, mapping)
        cleaned["Review_Reason"] = reasons

        flagged = int(flags.sum())
        normal = max(0, total - flagged)

        labels = [
            {"name": "Records requiring review", "count": flagged}
        ] if flagged else []

        threat_data = cleaned.loc[flags].copy()

    protocols = protocol_series(cleaned, mapping)
    protocol_list = []

    if protocols is not None:
        protocol_list = [
            {"name": str(name), "count": int(count)}
            for name, count in protocols.value_counts().head(10).items()
        ]

    if "source_ip" in mapping and not threat_data.empty:

        source_col = mapping["source_ip"]

        source_counts = (
            threat_data[source_col].astype(str).value_counts().head(10)
        )

        top_sources = [
            {"ip": str(ip), "count": int(count)}
            for ip, count in source_counts.items()
        ]

    display_fields = [
        "source_ip", "destination_ip",
        "source_port", "destination_port",
        "protocol", "label"
    ]

    columns = []

    for field in display_fields:
        if field in mapping:
            columns.append({
                "key": field,
                "name": field.replace("_", " ").title()
            })

    if "Review_Reason" in threat_data.columns:
        columns.append({
            "key": "reason",
            "name": "Review Reason"
        })

    for _, row in threat_data.head(100).iterrows():

        record = {}

        for field in display_fields:
            if field in mapping:
                record[field] = str(row[mapping[field]])

        if "Review_Reason" in threat_data.columns:
            record["reason"] = str(row["Review_Reason"])

        records.append(record)

    return {
        "available": True,
        "is_demo": is_demo,
        "total": int(total),
        "normal": int(normal),
        "flagged": int(flagged),
        "labels": labels,
        "protocols": protocol_list,
        "top_sources": top_sources,
        "records": records,
        "columns": columns,
        "detection_basis": detection_basis,
        "message": ""
    }


# ---------------- HOME ----------------

@app.route("/")
def home():

    if "email" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not all([name, email, password, confirm]):
            flash("Please fill in all fields.", "error")

        elif password != confirm:
            flash("Passwords do not match.", "error")

        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")

        else:

            users = read_users()

            if email == get_admin_email():
                flash("This email is reserved for the administrator.", "error")

            elif email in users:
                flash("An account with this email already exists.", "error")

            else:

                users[email] = {
                    "name": name,
                    "email": email,
                    "password_hash": generate_password_hash(password),
                    "role": "user",
                    "status": "Active",
                    "created_at": datetime.now().strftime("%d-%m-%Y %I:%M %p")
                }

                save_users(users)

                log_activity(email, name, "user", "Registration")

                flash("Registration successful. Please log in.", "success")

                return redirect(url_for("login"))

    return render_template("register.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")

        admin_email = get_admin_email()
        admin_password = os.getenv("ADMIN_PASSWORD", "ChangeMe123!")

        if (
            role == "admin"
            and email == admin_email
            and password == admin_password
        ):

            session.clear()

            session.update({
                "email": email,
                "name": "Administrator",
                "role": "admin"
            })

            log_activity(email, "Administrator", "admin", "Login")

            return redirect(url_for("dashboard"))

        users = read_users()
        user = users.get(email)

        if (
            role == "user"
            and user
            and user.get("role", "user") == "user"
            and user.get("status", "Active") == "Active"
            and check_password_hash(user["password_hash"], password)
        ):

            session.clear()

            session.update({
                "email": email,
                "name": user["name"],
                "role": "user"
            })

            log_activity(email, user["name"], "user", "Login")

            return redirect(url_for("dashboard"))

        if user and user.get("status", "Active") != "Active":
            flash("Your account is inactive. Contact the administrator.", "error")
        else:
            flash("Invalid login details or selected account type.", "error")

    return render_template("login.html")


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
@login_required()
def dashboard():

    data = get_dashboard_data()

    return render_template("dashboard.html", data=data)


# ---------------- GRAPHS ----------------

@app.route("/graphs")
@login_required()
def graphs():

    data = get_dashboard_data()

    return render_template("graphs.html", data=data)


# ---------------- 3D ANALYTICS ----------------

@app.route("/analytics-3d")
@login_required()
def analytics_3d():

    csv_path = DATA_DIR / "cybersecurity_data.csv"
    is_demo = False

    if not csv_path.exists():
        csv_path = DATA_DIR / "demo_cybersecurity_data.csv"
        is_demo = True

    if not csv_path.exists():

        return render_template(
            "analytics3d.html",
            available=False,
            labels=[],
            protocols=[],
            is_demo=False
        )

    df = load_data(csv_path)
    prepared, mapping = prepare_data(df)
    cleaned = prepared.drop_duplicates()

    labels = []

    if "label" in mapping:

        values = (
            cleaned[mapping["label"]]
            .fillna("Unknown")
            .astype(str)
            .str.strip()
            .value_counts()
            .head(10)
        )

        labels = [
            {"name": str(k), "count": int(v)}
            for k, v in values.items()
        ]

    else:

        flags, _, _ = create_rule_flags(cleaned, mapping)

        labels = [
            {"name": "Flagged for review", "count": int(flags.sum())},
            {"name": "Not flagged", "count": int(len(cleaned) - flags.sum())}
        ]

    protocols = protocol_series(cleaned, mapping)
    protocol_data = []

    if protocols is not None:
        protocol_data = [
            {"name": str(k), "count": int(v)}
            for k, v in protocols.value_counts().head(10).items()
        ]

    return render_template(
        "analytics3d.html",
        available=True,
        labels=labels,
        protocols=protocol_data,
        is_demo=is_demo
    )


# ---------------- GRAPH IMAGE ----------------

@app.route("/graphs/<path:filename>")
@login_required()
def graph_file(filename):

    if Path(filename).name != filename or not (GRAPH_DIR / filename).is_file():
        abort(404)

    return send_from_directory(GRAPH_DIR, filename)


# ---------------- THREAT DETECTION ----------------

@app.route("/threat-detection")
@login_required()
def threat_detection():

    data = get_threat_detection_data()

    return render_template("threat_detection.html", data=data)


# ---------------- NETWORK INSIGHTS ----------------

@app.route("/network-insights")
@login_required()
def network_insights():

    csv_path = DATA_DIR / "cybersecurity_data.csv"
    is_demo = False

    if not csv_path.exists():
        csv_path = DATA_DIR / "demo_cybersecurity_data.csv"
        is_demo = True

    if not csv_path.exists():

        data = {
            "available": False,
            "is_demo": False,
            "total": 0,
            "sources": [],
            "destinations": [],
            "protocols": [],
            "records": [],
            "message": "Cybersecurity dataset not found."
        }

        return render_template("network_insights.html", data=data)

    df = load_data(csv_path)
    prepared, mapping = prepare_data(df)
    cleaned = prepared.drop_duplicates().copy()

    sources = []
    destinations = []
    protocols_list = []
    records = []

    if "source_ip" in mapping:

        counts = (
            cleaned[mapping["source_ip"]]
            .dropna()
            .astype(str)
            .value_counts()
            .head(10)
        )

        sources = [
            {"ip": str(ip), "count": int(count)}
            for ip, count in counts.items()
        ]

    if "destination_ip" in mapping:

        counts = (
            cleaned[mapping["destination_ip"]]
            .dropna()
            .astype(str)
            .value_counts()
            .head(10)
        )

        destinations = [
            {"ip": str(ip), "count": int(count)}
            for ip, count in counts.items()
        ]

    protocols = protocol_series(cleaned, mapping)

    if protocols is not None:

        protocols_list = [
            {"name": str(name), "count": int(count)}
            for name, count in protocols.value_counts().items()
        ]

    display_fields = [
        "source_ip", "destination_ip",
        "source_port", "destination_port", "protocol"
    ]

    for _, row in cleaned.head(100).iterrows():

        record = {}

        for field in display_fields:
            if field in mapping:
                record[field] = str(row[mapping[field]])

        records.append(record)

    data = {
        "available": True,
        "is_demo": is_demo,
        "total": int(len(cleaned)),
        "sources": sources,
        "destinations": destinations,
        "protocols": protocols_list,
        "records": records,
        "message": ""
    }

    return render_template("network_insights.html", data=data)


# ---------------- SECURITY REPORTS ----------------

@app.route("/security-reports")
@login_required()
def security_reports():

    data = get_threat_detection_data()

    return render_template("security_reports.html", data=data)


# ---------------- EVENT TIMELINE ----------------

@app.route("/event-timeline")
@login_required()
def event_timeline():

    csv_path = DATA_DIR / "cybersecurity_data.csv"
    is_demo = False

    if not csv_path.exists():
        csv_path = DATA_DIR / "demo_cybersecurity_data.csv"
        is_demo = True

    if not csv_path.exists():

        data = {
            "available": False,
            "message": "Cybersecurity dataset not found.",
            "total": 0,
            "events": [],
            "daily_events": []
        }

        return render_template("event_timeline.html", data=data)

    df = load_data(csv_path)
    prepared, mapping = prepare_data(df)
    cleaned = prepared.drop_duplicates().copy()

    events = []
    daily_events = []

    timestamp_col = mapping.get("timestamp")

    if timestamp_col:

        cleaned[timestamp_col] = pd.to_datetime(
            cleaned[timestamp_col],
            errors="coerce"
        )

        valid = cleaned.dropna(subset=[timestamp_col]).copy()
        valid = valid.sort_values(timestamp_col, ascending=False)

        daily = (
            valid.groupby(valid[timestamp_col].dt.strftime("%Y-%m-%d"))
            .size()
            .sort_index(ascending=False)
            .head(15)
        )

        daily_events = [
            {"date": str(date), "count": int(count)}
            for date, count in daily.items()
        ]

        for _, row in valid.head(100).iterrows():

            event = {"timestamp": str(row[timestamp_col])}

            for field in ["source_ip", "destination_ip", "protocol", "label"]:
                if field in mapping:
                    event[field] = str(row[mapping[field]])

            events.append(event)

    data = {
        "available": True,
        "is_demo": is_demo,
        "total": len(cleaned),
        "events": events,
        "daily_events": daily_events,
        "has_timestamp": bool(timestamp_col),
        "message": ""
    }

    return render_template("event_timeline.html", data=data)


# ---------------- INCIDENT MANAGEMENT ----------------

INCIDENT_FILE = OUTPUT_DIR / "incidents.json"
INCIDENT_FILE.parent.mkdir(parents=True, exist_ok=True)


def read_incidents():

    if not INCIDENT_FILE.exists():
        return []

    try:
        with open(INCIDENT_FILE, "r", encoding="utf-8") as file:
            incidents = json.load(file)

        return incidents if isinstance(incidents, list) else []

    except (json.JSONDecodeError, OSError):
        return []


def save_incidents(incidents):

    with open(INCIDENT_FILE, "w", encoding="utf-8") as file:
        json.dump(incidents, file, indent=4)


@app.route("/incident-management", methods=["GET", "POST"])
@login_required()
def incident_management():

    incidents = read_incidents()

    if request.method == "POST":

        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "Medium")
        status = request.form.get("status", "Open")

        allowed_severity = ["Critical", "High", "Medium", "Low"]
        allowed_status = ["Open", "In Progress", "Resolved"]

        if not title or not description:

            flash(
                "Please enter the incident title and description.",
                "error"
            )

        elif severity not in allowed_severity or status not in allowed_status:

            flash(
                "Invalid incident severity or status.",
                "error"
            )

        else:

            incident = {
                "id": len(incidents) + 1,
                "title": title,
                "description": description,
                "severity": severity,
                "status": status,
                "reported_by": session.get("email", "Unknown"),
                "created_at": datetime.now().strftime("%d-%m-%Y %I:%M %p")
            }

            incidents.insert(0, incident)
            save_incidents(incidents)

            flash("Incident reported successfully.", "success")

            return redirect(url_for("incident_management"))

    return render_template(
        "incident_management.html",
        incidents=incidents
    )


# ---------------- SECURITY ALERT CENTER ----------------

ALERT_FILE = OUTPUT_DIR / "security_alerts.json"
ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)


def read_alert_status():

    if not ALERT_FILE.exists():
        return {}

    try:
        with open(ALERT_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, dict) else {}

    except (json.JSONDecodeError, OSError):
        return {}


def save_alert_status(status_data):

    with open(ALERT_FILE, "w", encoding="utf-8") as file:
        json.dump(status_data, file, indent=4)


@app.route("/security-alerts", methods=["GET", "POST"])
@login_required()
def security_alerts():

    if request.method == "POST":

        alert_id = request.form.get("alert_id", "")
        new_status = request.form.get("status", "")

        if new_status not in ["New", "Investigating", "Resolved"]:

            flash("Invalid alert status.", "error")

        else:

            status_data = read_alert_status()
            status_data[alert_id] = new_status
            save_alert_status(status_data)

            flash("Alert status updated successfully!", "success")

        return redirect(url_for("security_alerts"))

    csv_path = DATA_DIR / "cybersecurity_data.csv"
    is_demo = False

    if not csv_path.exists():
        csv_path = DATA_DIR / "demo_cybersecurity_data.csv"
        is_demo = True

    if not csv_path.exists():

        return render_template(
            "security_alerts.html",
            alerts=[],
            total=0,
            critical=0,
            high=0,
            medium=0,
            low=0,
            is_demo=False,
            available=False
        )

    df = load_data(csv_path)
    prepared, mapping = prepare_data(df)
    cleaned = prepared.drop_duplicates().copy()

    alerts = []
    status_data = read_alert_status()

    if "label" in mapping:

        label_col = mapping["label"]

        for index, row in cleaned.iterrows():

            label = str(row[label_col]).strip()

            if label.lower() in [
                "benign", "normal", "unknown", "", "nan", "none"
            ]:
                continue

            label_lower = label.lower()

            if any(word in label_lower for word in [
                "ddos", "dos", "ransomware", "malware"
            ]):
                severity = "Critical"

            elif any(word in label_lower for word in [
                "brute", "injection", "botnet", "exploit"
            ]):
                severity = "High"

            elif any(word in label_lower for word in [
                "scan", "suspicious", "attack"
            ]):
                severity = "Medium"

            else:
                severity = "Low"

            alert_id = str(index)

            source_ip = (
                str(row[mapping["source_ip"]])
                if "source_ip" in mapping else "N/A"
            )

            destination_ip = (
                str(row[mapping["destination_ip"]])
                if "destination_ip" in mapping else "N/A"
            )

            protocol = (
                str(row[mapping["protocol"]])
                if "protocol" in mapping else "N/A"
            )

            alerts.append({
                "id": alert_id,
                "name": label,
                "severity": severity,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": protocol,
                "status": status_data.get(alert_id, "New")
            })

    return render_template(
        "security_alerts.html",
        alerts=alerts,
        total=len(alerts),
        critical=sum(a["severity"] == "Critical" for a in alerts),
        high=sum(a["severity"] == "High" for a in alerts),
        medium=sum(a["severity"] == "Medium" for a in alerts),
        low=sum(a["severity"] == "Low" for a in alerts),
        is_demo=is_demo,
        available=True
    )


# ---------------- ADMIN CONTROL PANEL ----------------

@app.route("/admin-control")
@login_required(role="admin")
def admin_control():

    users = read_users()
    user_list = []

    for email, details in users.items():

        user_list.append({
            "email": email,
            "name": details.get("name", "Unknown"),
            "role": details.get("role", "user")
        })

    total_users = len(user_list)

    admin_count = sum(
        1 for user in user_list
        if user["role"] == "admin"
    )

    normal_users = total_users - admin_count

    data = {
        "users": user_list,
        "total_users": total_users,
        "admin_count": admin_count,
        "normal_users": normal_users
    }

    return render_template("admin_control.html", data=data)


# ---------------- USER MANAGEMENT ----------------

@app.route("/user-management", methods=["GET", "POST"])
@login_required(role="admin")
def user_management():

    users = read_users()

    # Recover old registration dates from activity logs
    changed = False

    for email, details in users.items():

        if is_admin_email(email):
            continue

        if not details.get("created_at"):

            recovered_date = get_registration_date(email)

            if recovered_date != "Date unavailable":
                details["created_at"] = recovered_date
                changed = True

    if changed:
        save_users(users)

    # POST ACTIONS
    if request.method == "POST":

        action = request.form.get("action", "")
        email = request.form.get("email", "").strip().lower()

        if not email or email not in users:

            flash("User account not found.", "error")

            return redirect(url_for("user_management"))

        if is_admin_email(email):

            flash(
                "Administrator account cannot be changed here.",
                "error"
            )

            return redirect(url_for("user_management"))

        user = users[email]

        # ACTIVATE / DEACTIVATE
        if action == "toggle_status":

            current_status = user.get("status", "Active")

            if current_status == "Active":

                user["status"] = "Inactive"
                message = "User account deactivated."
                activity = "User Deactivated"

            else:

                user["status"] = "Active"
                message = "User account activated."
                activity = "User Activated"

            save_users(users)

            log_activity(
                session.get("email"),
                session.get("name"),
                "admin",
                activity + ": " + email
            )

            flash(message, "success")

        # DELETE USER
        elif action == "delete":

            if email == session.get("email", "").lower():

                flash(
                    "You cannot delete your own logged-in account.",
                    "error"
                )

                return redirect(url_for("user_management"))

            deleted_name = user.get("name", "Unknown")

            del users[email]
            save_users(users)

            log_activity(
                session.get("email"),
                session.get("name"),
                "admin",
                "User Deleted: " + email
            )

            flash(
                "User " + deleted_name + " deleted successfully.",
                "success"
            )

        else:

            flash("Invalid user management action.", "error")

        return redirect(url_for("user_management"))

    # SEARCH AND FILTERS
    search_text = request.args.get(
        "search", ""
    ).strip().lower()

    role_filter = request.args.get(
        "role", "all"
    ).strip().lower()

    status_filter = request.args.get(
        "status", "all"
    ).strip().lower()

    user_list = []

    for email, details in users.items():

        if is_admin_email(email):
            continue

        name = details.get("name", "Unknown")
        role = details.get("role", "user")
        status = details.get("status", "Active")

        # Created date
        created_at = details.get(
            "created_at",
            "Date unavailable"
        )

        if not created_at:
            created_at = "Date unavailable"

        # Search filter
        if search_text and (
            search_text not in email.lower()
            and search_text not in name.lower()
        ):
            continue

        # Role filter
        if role_filter != "all" and role.lower() != role_filter:
            continue

        # Status filter
        if status_filter != "all" and status.lower() != status_filter:
            continue

        user_list.append({
            "name": name,
            "email": email,
            "role": role,
            "status": status,
            "created_at": created_at
        })

    user_list.sort(
        key=lambda item: item["name"].lower()
    )

    # USER STATISTICS
    all_users = [
        details
        for email, details in users.items()
        if not is_admin_email(email)
    ]

    total_users = len(all_users)

    active_users = sum(
        1 for user in all_users
        if user.get("status", "Active") == "Active"
    )

    inactive_users = total_users - active_users

    data = {
        "users": user_list,
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": inactive_users,
        "search": search_text,
        "role_filter": role_filter,
        "status_filter": status_filter
    }

    return render_template(
        "user_management.html",
        data=data
    )


# ---------------- USER DETAILS ----------------

@app.route("/user-details")
@login_required(role="admin")
def user_details():

    email = request.args.get(
        "email", ""
    ).strip().lower()

    if not email:

        flash("User email is required.", "error")

        return redirect(url_for("user_management"))

    if is_admin_email(email):

        flash(
            "Administrator details are managed separately.",
            "error"
        )

        return redirect(url_for("user_management"))

    users = read_users()
    user = users.get(email)

    if not user:

        flash("User account not found.", "error")

        return redirect(url_for("user_management"))

    # Recover registration date if possible
    if not user.get("created_at"):

        recovered_date = get_registration_date(email)

        if recovered_date != "Date unavailable":
            user["created_at"] = recovered_date
            save_users(users)

    details = {
        "name": user.get("name", "Unknown"),
        "email": email,
        "role": user.get("role", "user"),
        "status": user.get("status", "Active"),
        "created_at": user.get(
            "created_at",
            "Date unavailable"
        )
    }

    return render_template(
        "user_management.html",
        data={
            "details_view": True,
            "selected_user": details,
            "users": [],
            "total_users": len(users),
            "active_users": 0,
            "inactive_users": 0,
            "search": "",
            "role_filter": "all",
            "status_filter": "all"
        }
    )


# ---------------- USER ACTIVITY LOGS ----------------

@app.route("/activity-logs")
@login_required(role="admin")
def activity_logs():

    logs = read_activity_logs()

    data = {
        "logs": logs,
        "total": len(logs),

        "logins": sum(
            1 for item in logs
            if item.get("action") == "Login"
        ),

        "logouts": sum(
            1 for item in logs
            if item.get("action") == "Logout"
        ),

        "registrations": sum(
            1 for item in logs
            if item.get("action") == "Registration"
        )
    }

    return render_template(
        "activity_logs.html",
        data=data
    )


# ---------------- ADMIN REPORT ----------------

@app.route("/report")
@login_required(role="admin")
def report():

    report_path = REPORT_DIR / "analysis_summary.txt"

    if report_path.exists():
        content = report_path.read_text(encoding="utf-8")
    else:
        content = "Run analysis after adding a dataset."

    return render_template(
        "report.html",
        content=content
    )


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():

    if "email" in session:

        log_activity(
            session.get("email", "Unknown"),
            session.get("name", "Unknown"),
            session.get("role", "user"),
            "Logout"
        )

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    app.run(debug=True)
