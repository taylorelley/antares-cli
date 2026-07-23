from flask import Flask, request, render_template
import sqlite3
app = Flask(__name__)

@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s" % uid)
    return render_template("user.html", rows=cur.fetchall())
