import sqlite3
import subprocess

# Vulnerability 1: Hardcoded password (Bandit: B105)
PASSWORD = "admin123"
DB_PASSWORD = "supersecret"

def get_user(username):
    # Vulnerability 2: SQL Injection — user input directly in query (Bandit: B608, Semgrep)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

def run_command(user_input):
    # Vulnerability 3: Shell injection — user input passed to shell (Bandit: B602)
    subprocess.call(user_input, shell=True)

def safe_add(a, b):
    # This is clean — should NOT be flagged
    return a + b

def calculate(expression):
    # Vulnerability 4: eval() on user input (Bandit: B307)
    return eval(expression)