import os
import hashlib
import pickle
import jwt
import requests
from flask import Flask, request, redirect, Response, render_template_string
from Crypto.Cipher import DES

app = Flask(__name__)

# 1. Hardcoded Secret
API_KEY = "sk-live-abc123secretkey"
SECRET_KEY = "supersecretkey123"

# 2. SQL Injection
def search_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)

# 3. Weak Hashing & SQL Injection
def login(username, password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    return db.execute("SELECT * FROM users WHERE user=" + username + " AND pass=" + hashed)

# 4. Command Injection
def run_command(cmd):
    os.system("ping " + cmd)

# 5. Insecure Deserialization
def load_data(data):
    return pickle.loads(data)

# 6. Weak JWT Implementation
def verify_token(token):
    return jwt.decode(token, verify=False)

# 7. Weak Cryptography
def encrypt_data(data):
    cipher = DES.new(b'8bytekey')
    return cipher.encrypt(data)

# 8. Unvalidated Redirect
@app.route('/redirect')
def follow_redirect():
    target = request.args.get('next')
    return redirect(target)

# 9. Cross-Site Scripting (XSS)
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template_string("Hello {{ name }}")

# 10. Missing CSRF Protection (state-changing route with no CSRF validation)
@app.route('/transfer', methods=['POST'])
def transfer_funds():
    amount = request.form.get('amount')
    # No CSRF check
    return "Transferred " + amount

# 11. Missing Rate Limiting on authentication route
@app.route('/login', methods=['POST'])
def handle_login():
    # Authentication without rate limiting
    return "Logged in"

# 12. Missing Security Headers
@app.route('/headers')
def send_response():
    # Response built without security headers
    return Response("Data")

# 13. Dependency Issues (tested against requirements.txt - we will define a test specifically for requirements.txt)