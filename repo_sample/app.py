import os

API_KEY = "fake_demo_key_12345"

def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return query

print("Demo app")
