
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from database import init_db
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_db():
    conn = sqlite3.connect('instance/database.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('username') != 'admin':
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html', 
                         logged_in='user_id' in session,
                         username=session.get('username'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                      [username, generate_password_hash(password), email])
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists')
        finally:
            db.close()
    
    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', [username]).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
        db.close()
    
    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if session.get('username') == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    quotes = db.execute('SELECT * FROM quotes WHERE user_id = ?', 
                       [session['user_id']]).fetchall()
    projects = db.execute('SELECT * FROM projects WHERE user_id = ?',
                         [session['user_id']]).fetchall()
    notifications = db.execute('SELECT * FROM notifications WHERE user_id = ? AND is_read = 0',
                             [session['user_id']]).fetchall()
    db.close()
    
    return render_template('dashboard/user.html',
                         quotes=quotes,
                         projects=projects,
                         notifications=notifications)

@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    quotes = db.execute('SELECT * FROM quotes').fetchall()
    projects = db.execute('SELECT * FROM projects').fetchall()
    notifications = db.execute('SELECT * FROM notifications WHERE user_id = ? AND is_read = 0',
                             [session['user_id']]).fetchall()
    db.close()
    
    return render_template('dashboard/admin.html',
                         quotes=quotes,
                         projects=projects,
                         notifications=notifications)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
