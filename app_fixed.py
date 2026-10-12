"""
VulnShop (FIXED) - the secure version of app.py.

Every vulnerability in app.py is fixed here, with a comment saying how.
Compare the two files side by side to see what changed.
"""

import os
import sqlite3
from flask import Flask, request, render_template, redirect, session, g, abort
from werkzeug.security import check_password_hash

app = Flask(__name__)
# FIX: secret key comes from the environment, not from source code.
app.secret_key = os.environ["SECRET_KEY"]

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

    # FIX: parameterized query. User input is passed as data, never as SQL.
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()

    # FIX: passwords are hashed; we compare against the hash, not plaintext.
    if user and check_password_hash(user["password"], password):
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

    # FIX: ignore any id from the URL. A user can only see their OWN profile,
    # taken from the session. No IDOR possible.
    user_id = session["user_id"]
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        abort(404)
    return render_template("profile.html", profile=row)


@app.route("/search")
def search():
    # FIX: render with autoescaping (raw=False), so any HTML in the query
    # is shown as text instead of executed. No XSS.
    q = request.args.get("q", "")
    return render_template("search.html", query=q, raw=False)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    # FIX: debug off; host bound explicitly. Run behind a real WSGI server.
    app.run(host="127.0.0.1", port=5000, debug=False)
