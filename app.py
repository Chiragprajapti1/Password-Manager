from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this in production!

# Generate encryption key if not exists
if not os.path.exists("key.key"):
    with open("key.key", "wb") as key_file:
        key_file.write(Fernet.generate_key())

def get_key():
    return open("key.key", "rb").read()

def encrypt_password(password):
    return Fernet(get_key()).encrypt(password.encode())

def decrypt_password(encrypted):
    return Fernet(get_key()).decrypt(encrypted).decode()

def init_db():
    with sqlite3.connect("users.db") as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE,
                        password TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS passwords (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        site TEXT,
                        password BLOB,
                        FOREIGN KEY(user_id) REFERENCES users(id))''')
        conn.commit()

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
            with sqlite3.connect("users.db") as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
                conn.commit()
                flash("Registration successful. Please login.")
                return redirect('/login')
        except sqlite3.IntegrityError:
            flash("Email already registered.")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect("users.db") as conn:
            c = conn.cursor()
            c.execute("SELECT id, password FROM users WHERE email = ?", (email,))
            user = c.fetchone()
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
    with sqlite3.connect("users.db") as conn:
        c = conn.cursor()
        if request.method == 'POST':
            site = request.form['site']
            password = encrypt_password(request.form['password'])
            c.execute("INSERT INTO passwords (user_id, site, password) VALUES (?, ?, ?)", (user_id, site, password))
            conn.commit()
        c.execute("SELECT site, password FROM passwords WHERE user_id = ?", (user_id,))
        data = [(site, decrypt_password(pwd)) for site, pwd in c.fetchall()]
    return render_template('dashboard.html', passwords=data)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
