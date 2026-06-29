import os
import hashlib
from flask import Flask, request

app = Flask(__name__)

API_KEY = "sk-live-abc123secretkey"

def search_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)

def login(username, password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    return db.execute("SELECT * FROM users WHERE user=" + username + " AND pass=" + hashed)

def fetch_external_data(url):
    response = requests.get(url)
    return response.json()

def validate_input(data):
    if isinstance(data, str):
        return True
    return False