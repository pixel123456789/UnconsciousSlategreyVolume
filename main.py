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

@app.route('/quote/<int:quote_id>')
@login_required
def quote_details(quote_id):
    db = get_db()
    quote = db.execute('SELECT * FROM quotes WHERE id = ?', [quote_id]).fetchone()
    messages = db.execute('SELECT * FROM messages WHERE quote_id = ?', [quote_id]).fetchall()
    db.close()

    return render_template('dashboard/quote_details.html',
                         quote=quote,
                         messages=messages)

@app.route('/project/<int:project_id>')
@login_required
def project_details(project_id):
    db = get_db()
    project = db.execute('SELECT * FROM projects WHERE id = ?', [project_id]).fetchone()
    messages = db.execute('SELECT * FROM messages WHERE project_id = ?', [project_id]).fetchall()
    db.close()

    return render_template('dashboard/project_details.html',
                         project=project,
                         messages=messages)

@app.route('/create_quote', methods=['POST'])
@login_required
def create_quote():
    title = request.form['title']
    description = request.form['description']

    db = get_db()
    db.execute('INSERT INTO quotes (user_id, title, description) VALUES (?, ?, ?)',
              [session['user_id'], title, description])
    db.commit()
    db.close()

    flash('Quote request submitted successfully')
    return redirect(url_for('dashboard'))

@app.route('/update_quote', methods=['POST'])
@admin_required
def update_quote():
    quote_id = request.form['quote_id']
    status = request.form['status']
    price = request.form.get('price')

    db = get_db()
    if status == 'accepted':
        # Create project from quote
        db.execute('INSERT INTO projects (quote_id, user_id) VALUES (?, ?)',
                  [quote_id, session['user_id']])

    db.execute('UPDATE quotes SET status = ?, price = ? WHERE id = ?',
              [status, price, quote_id])
    db.commit()
    db.close()

    return jsonify({'success': True})

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    content = request.form['content']
    quote_id = request.form.get('quote_id')
    project_id = request.form.get('project_id')
    receiver_id = request.form['receiver_id']

    db = get_db()
    db.execute('''INSERT INTO messages 
                 (sender_id, receiver_id, quote_id, project_id, content)
                 VALUES (?, ?, ?, ?, ?)''',
              [session['user_id'], receiver_id, quote_id, project_id, content])
    db.commit()
    db.close()

    return jsonify({'success': True})

if __name__ == '__main__':
    # Initialize database and create tables
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=5000)