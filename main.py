import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, date
import os
from contextlib import contextmanager
import re

QUOTE_STATUSES = ['pending', 'quoted', 'accepted', 'rejected']
PROJECT_STATUSES = ['planning', 'in_progress', 'review', 'completed']

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

@contextmanager
def get_db():
    if not os.path.exists('instance'):
        os.makedirs('instance')
    db = sqlite3.connect(
        'instance/database.db',
        detect_types=sqlite3.PARSE_DECLTYPES
    )
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()

def init_db():
    if not os.path.exists('instance'):
        os.makedirs('instance')

    with get_db() as conn:
        c = conn.cursor()

        c.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    is_admin BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        c.execute('''CREATE TABLE IF NOT EXISTS quotes
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'quoted', 'accepted', 'rejected')),
                    price REAL,
                    feedback TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id))''')

        c.execute('''CREATE TABLE IF NOT EXISTS projects
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quote_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    status TEXT DEFAULT 'planning' CHECK (status IN ('planning', 'in_progress', 'review', 'completed')),
                    start_date DATE,
                    end_date DATE,
                    progress INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (quote_id) REFERENCES quotes (id),
                    FOREIGN KEY (user_id) REFERENCES users (id))''')

        c.execute('''CREATE TABLE IF NOT EXISTS messages
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    quote_id INTEGER,
                    project_id INTEGER,
                    content TEXT NOT NULL,
                    is_read BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users (id),
                    FOREIGN KEY (receiver_id) REFERENCES users (id),
                    FOREIGN KEY (quote_id) REFERENCES quotes (id),
                    FOREIGN KEY (project_id) REFERENCES projects (id))''')

        c.execute('''CREATE TABLE IF NOT EXISTS notifications
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    type TEXT CHECK (type IN ('info', 'warning', 'success', 'error')),
                    is_read BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id))''')

        # Create indexes for better performance
        c.execute('CREATE INDEX IF NOT EXISTS idx_quotes_user_id ON quotes(user_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_projects_user_id ON projects(user_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_messages_receiver_id ON messages(receiver_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id)')

        # Create admin user if it doesn't exist
        admin = c.execute('SELECT * FROM users WHERE username = ?', ['admin']).fetchone()
        if not admin:
            c.execute('INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)',
                     ['admin', generate_password_hash('ini.dev.liam'), 'liamaaronkinnaird1@outlook.com', True])

        conn.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    return True, None

@app.route('/')
def index():
    return render_template('index.html', 
                         logged_in='user_id' in session,
                         username=session.get('username'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        email = request.form['email'].strip()

        if not username or not password or not email:
            flash('All fields are required', 'error')
            return redirect(url_for('register'))

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email address', 'error')
            return redirect(url_for('register'))

        valid_password, msg = validate_password(password)
        if not valid_password:
            flash(msg, 'error')
            return redirect(url_for('register'))

        try:
            with get_db() as db:
                db.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                          [username, generate_password_hash(password), email])
                db.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')

    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        with get_db() as db:
            user = db.execute('SELECT * FROM users WHERE username = ?', [username]).fetchone()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                flash('Welcome back!', 'success')
                return redirect(url_for('dashboard'))
            
            flash('Invalid username or password', 'error')

    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    with get_db() as db:
        if session.get('is_admin'):
            quotes = db.execute('''
                SELECT q.*, u.username 
                FROM quotes q 
                JOIN users u ON q.user_id = u.id 
                ORDER BY q.created_at DESC
            ''').fetchall()
            
            projects = db.execute('''
                SELECT p.*, q.title, u.username 
                FROM projects p 
                JOIN quotes q ON p.quote_id = q.id 
                JOIN users u ON p.user_id = u.id 
                ORDER BY p.created_at DESC
            ''').fetchall()
        else:
            quotes = db.execute('SELECT * FROM quotes WHERE user_id = ? ORDER BY created_at DESC', 
                              [session['user_id']]).fetchall()
            
            projects = db.execute('''
                SELECT p.*, q.title 
                FROM projects p 
                JOIN quotes q ON p.quote_id = q.id 
                WHERE p.user_id = ? 
                ORDER BY p.created_at DESC
            ''', [session['user_id']]).fetchall()

        notifications = db.execute('''
            SELECT * FROM notifications 
            WHERE user_id = ? AND is_read = 0 
            ORDER BY created_at DESC
        ''', [session['user_id']]).fetchall()

        if session.get('is_admin'):
            return render_template('dashboard/admin.html',
                                quotes=quotes,
                                projects=projects,
                                notifications=notifications,
                                quote_statuses=QUOTE_STATUSES,
                                project_statuses=PROJECT_STATUSES)
        else:
            return render_template('dashboard/user.html',
                                quotes=quotes,
                                projects=projects,
                                notifications=notifications,
                                quote_statuses=QUOTE_STATUSES,
                                project_statuses=PROJECT_STATUSES)

@app.route('/quote/<int:quote_id>')
@login_required
def quote_details(quote_id):
    with get_db() as db:
        quote = db.execute('''
            SELECT q.*, u.username 
            FROM quotes q 
            JOIN users u ON q.user_id = u.id 
            WHERE q.id = ?
        ''', [quote_id]).fetchone()
        
        if not quote:
            flash('Quote not found', 'error')
            return redirect(url_for('dashboard'))

        if not session.get('is_admin') and quote['user_id'] != session['user_id']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))

        messages = db.execute('''
            SELECT m.*, u.username as sender_name 
            FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE m.quote_id = ? 
            ORDER BY m.created_at DESC
        ''', [quote_id]).fetchall()

        return render_template('dashboard/quote_details.html',
                             quote=quote,
                             messages=messages,
                             statuses=QUOTE_STATUSES)

@app.route('/project/<int:project_id>')
@login_required
def project_details(project_id):
    with get_db() as db:
        project = db.execute('''
            SELECT p.*, q.title, q.description, u.username 
            FROM projects p 
            JOIN quotes q ON p.quote_id = q.id 
            JOIN users u ON p.user_id = u.id 
            WHERE p.id = ?
        ''', [project_id]).fetchone()

        if not project:
            flash('Project not found', 'error')
            return redirect(url_for('dashboard'))

        if not session.get('is_admin') and project['user_id'] != session['user_id']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))

        messages = db.execute('''
            SELECT m.*, u.username as sender_name 
            FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE m.project_id = ? 
            ORDER BY m.created_at DESC
        ''', [project_id]).fetchall()

        return render_template('dashboard/project_details.html',
                             project=project,
                             messages=messages,
                             statuses=PROJECT_STATUSES)

@app.route('/create_quote', methods=['POST'])
@login_required
def create_quote():
    title = request.form['title'].strip()
    description = request.form['description'].strip()

    if not title or not description:
        flash('Title and description are required', 'error')
        return redirect(url_for('dashboard'))

    with get_db() as db:
        try:
            db.execute('INSERT INTO quotes (user_id, title, description) VALUES (?, ?, ?)',
                      [session['user_id'], title, description])
            
            admin = db.execute('SELECT id FROM users WHERE is_admin = 1').fetchone()
            if admin:
                db.execute('''
                    INSERT INTO notifications (user_id, content, type) 
                    VALUES (?, ?, ?)
                ''', [admin['id'], f'New quote request: {title}', 'info'])
            
            db.commit()
            flash('Quote request submitted successfully', 'success')
        except sqlite3.Error as e:
            flash('Error creating quote request', 'error')

    return redirect(url_for('dashboard'))

@app.route('/update_quote', methods=['POST'])
@login_required
def update_quote():
    quote_id = request.form['quote_id']
    status = request.form['status']
    price = request.form.get('price')
    feedback = request.form.get('feedback')

    if status not in QUOTE_STATUSES:
        return jsonify({'success': False, 'error': 'Invalid status'})

    with get_db() as db:
        quote = db.execute('SELECT * FROM quotes WHERE id = ?', [quote_id]).fetchone()
        if not quote:
            return jsonify({'success': False, 'error': 'Quote not found'})

        if session.get('is_admin'):
            if status == 'quoted' and not price:
                return jsonify({'success': False, 'error': 'Price is required for quotes'})
            
            try:
                price = float(price) if price else None
                db.execute('''
                    UPDATE quotes 
                    SET status = ?, price = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', [status, price, quote_id])
            
            db.execute('''
                INSERT INTO notifications (user_id, content, type) 
                VALUES (?, ?, ?)
            ''', [quote['user_id'], f'Your quote has been updated: ${price}', 'info'])

        elif session['user_id'] == quote['user_id'] and quote['status'] == 'quoted':
            db.execute('''
                UPDATE quotes 
                SET status = ?, feedback = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', [status, feedback, quote_id])

            if status == 'accepted':
                db.execute('''
                    INSERT INTO projects (quote_id, user_id, start_date) 
                    VALUES (?, ?, ?)
                ''', [quote_id, quote['user_id'], date.today()])
                
                admin = db.execute('SELECT id FROM users WHERE is_admin = 1').fetchone()
                if admin:
                    db.execute('''
                        INSERT INTO notifications (user_id, content, type) 
                        VALUES (?, ?, ?)
                    ''', [admin['id'], f'Quote #{quote_id} has been accepted', 'success'])
            else:
                admin = db.execute('SELECT id FROM users WHERE is_admin = 1').fetchone()
                if admin:
                    db.execute('''
                        INSERT INTO notifications (user_id, content, type) 
                        VALUES (?, ?, ?)
                    ''', [admin['id'], f'Quote #{quote_id} has been rejected', 'warning'])

        db.commit()
        return jsonify({'success': True})

@app.route('/update_project', methods=['POST'])
@login_required
def update_project():
    if not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Admin access required'})

    project_id = request.form['project_id']
    status = request.form['status']
    progress = request.form.get('progress', type=int)

    if status not in PROJECT_STATUSES:
        return jsonify({'success': False, 'error': 'Invalid status'})

    if progress is not None and not (0 <= progress <= 100):
        return jsonify({'success': False, 'error': 'Progress must be between 0 and 100'})

    with get_db() as db:
        project = db.execute('SELECT * FROM projects WHERE id = ?', [project_id]).fetchone()
        if not project:
            return jsonify({'success': False, 'error': 'Project not found'})

        update_fields = ['status = ?']
        params = [status]

        if progress is not None:
            update_fields.append('progress = ?')
            params.append(progress)

        if status == 'completed':
            update_fields.append('end_date = ?')
            params.append(date.today())

        update_fields.append('updated_at = CURRENT_TIMESTAMP')
        params.append(project_id)

        db.execute(f'''
            UPDATE projects 
            SET {', '.join(update_fields)} 
            WHERE id = ?
        ''', params)

        db.execute('''
            INSERT INTO notifications (user_id, content, type) 
            VALUES (?, ?, ?)
        ''', [project['user_id'], f'Your project status has been updated to {status}', 'info'])

        db.commit()
        return jsonify({'success': True})

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    content = request.form['content'].strip()
    quote_id = request.form.get('quote_id')
    project_id = request.form.get('project_id')
    receiver_id = request.form['receiver_id']

    if not content:
        return jsonify({'success': False, 'error': 'Message content is required'})

    with get_db() as db:
        try:
            db.execute('''
                INSERT INTO messages 
                (sender_id, receiver_id, quote_id, project_id, content) 
                VALUES (?, ?, ?, ?, ?)
            ''', [session['user_id'], receiver_id, quote_id, project_id, content])

            db.execute('''
                INSERT INTO notifications (user_id, content, type) 
                VALUES (?, ?, ?)
            ''', [receiver_id, 'You have a new message', 'info'])

            db.commit()
            return jsonify({'success': True})
        except sqlite3.Error:
            return jsonify({'success': False, 'error': 'Error sending message'})

@app.route('/mark_notification_read', methods=['POST'])
@login_required
def mark_notification_read():
    notification_id = request.form['notification_id']

    with get_db() as db:
        db.execute('''
            UPDATE notifications 
            SET is_read = 1 
            WHERE id = ? AND user_id = ?
        ''', [notification_id, session['user_id']])
        db.commit()

    return jsonify({'success': True})

if __name__ == '__main__':
    try:
        # Create instance directory if it doesn't exist
        if not os.path.exists('instance'):
            os.makedirs('instance')
            print("Created instance directory")
        
        # Initialize database directly
        db = sqlite3.connect('instance/database.db')
        with db:
            init_db()
            print("Database initialized at instance/database.db")
            # Test database connection
            db.execute('SELECT 1').fetchone()
            print("Database connection verified")
        db.close()
    except Exception as e:
        print(f"Error during initialization: {e}")
    
    # Run the app
    app.run(host='0.0.0.0', port=5000)