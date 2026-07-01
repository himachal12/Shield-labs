"""
vuln_test_app.py

Minimal, intentionally-vulnerable local Flask app — SQLite backend,
raw string-concatenated SQL query. Exists ONLY to give sqlmap a safe,
local, always-available target to validate against. Never expose
this outside localhost; never deploy it anywhere.
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)
DB = "vuln_test.db"


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("DELETE FROM users")
    conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'S3cretPass123')")
    conn.execute("INSERT INTO users (username, password) VALUES ('guest', 'guestpass')")
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return '<html><body><a href="/user?id=1">View user</a></body></html>'

@app.route("/user")
def get_user():
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # Deliberately vulnerable: raw string concatenation, no parameterization
    query = "SELECT id, username FROM users WHERE id = " + user_id
    try:
        cur.execute(query)
        rows = cur.fetchall()
        return {"results": rows}
    except Exception as e:
        return {"error": str(e)}, 500
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5555)