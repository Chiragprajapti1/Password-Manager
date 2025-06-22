from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import psycopg2
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Load DB URL from environment (Render provides this)
DATABASE_URL = os.environ.get('DATABASE_URL')

# Set up DB connection
def get_db_connection():
    return psycopg2.connect(DATABASE_URL, sslmode='require')

# Generate encryption key
def get_key():
    return os.environ.get("FERNET_KEY").encode()


def encrypt_password(password):
    return Fernet(get_key()).encrypt(password.encode())

def decrypt_password(encrypted):
    return Fernet(get_key()).decrypt(encrypted).decode()

# Create tables
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE,
            password TEXT
        );
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            site TEXT,
            password BYTEA
        );
    ''')
    conn.commit()
    cur.close()
    conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, password))
            conn.commit()
            cur.close()
            conn.close()
            flash("Registration successful. Please login.")
            return redirect('/login')
        except Exception as e:
            flash("Email already registered.")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, password FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            return redirect('/dashboard')
        else:
            flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    user_id = session['user_id']

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        site = request.form['site']
        password = encrypt_password(request.form['password'])
        cur.execute("INSERT INTO passwords (user_id, site, password) VALUES (%s, %s, %s)", (user_id, site, password))
        conn.commit()

    cur.execute("SELECT site, password FROM passwords WHERE user_id = %s", (user_id,))
    data = [(site, decrypt_password(pwd)) for site, pwd in cur.fetchall()]

    cur.close()
    conn.close()
    return render_template('dashboard.html', passwords=data)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# Make sure the database is initialized on import (for Render + Gunicorn)
init_db()

if __name__ == "__main__":
    app.run(debug=False)
