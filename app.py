"""
VulnShop - a deliberately vulnerable demo web app for learning AppSec.

DO NOT deploy this to the public internet. It is insecure ON PURPOSE,
so that SAST (Semgrep) and DAST (OWASP ZAP) have something to find.

The fixed, secure version of this same app lives in app_fixed.py.
"""

import sqlite3
import os
from flask import Flask, request, render_template, redirect, session, g

app = Flask(__name__)
# VULN: hardcoded secret key committed to source control (Semgrep: secrets)
app.secret_key = "dev-secret-key-12345"

DATABASE = "vulnshop.db"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


@app.route("/")
def index():
    if "user" in session:
        return redirect("/dashboard")
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # FIX: parameterized query, user input is sent as data, never as SQL
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username , password))
    user = cur.fetchone()

    if user:
        session["user"] = user["username"]
        session["user_id"] = user["id"]
        return redirect("/dashboard")
    return render_template("login.html", error="Invalid credentials")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html", user=session["user"])


@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect("/")

    # FIX: user id comes from the session only, never from the URL
    # the logged-in user, so /profile?id=1 shows anyone's profile.
    # Try:  /profile?id=1  while logged in as a different user.
    user_id = session["user_id"]
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return "User not found", 404
    return render_template("profile.html", profile=row)


@app.route("/search")
def search():
    # FIX: template autoescapes the query, so HTML is shown as text
    q = request.args.get("q", "")
    return render_template("search.html", query=q)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    # VULN: debug mode on in "production" leaks stack traces + enables console
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug)
