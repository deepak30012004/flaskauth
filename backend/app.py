import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# Create users table if it doesn't exist
def init_db():
    with sqlite3.connect("users.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        """)
    print("Database initialized.")

init_db()

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    hashed_pw = generate_password_hash(password)

    try:
        with sqlite3.connect("users.db") as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?);", (username, hashed_pw))
            conn.commit()
        return jsonify({"message": "Signup successful"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "User already exists"}), 409

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    with sqlite3.connect("users.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()

        if row and check_password_hash(row[0], password):
            return jsonify({"message": "Login successful"}), 200
        else:
            return jsonify({"message": "Invalid credentials"}), 401

if __name__ == "__main__":
    app.run(debug=True)
