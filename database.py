
import sqlite3
from datetime import datetime
import os
from contextlib import contextmanager

QUOTE_STATUSES = ['pending', 'quoted', 'accepted', 'rejected']
PROJECT_STATUSES = ['planning', 'in_progress', 'review', 'completed']

@contextmanager
def get_db():
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
            from werkzeug.security import generate_password_hash
            c.execute('INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)',
                     ['admin', generate_password_hash('ini.dev.liam'), 'liamaaronkinnaird1@outlook.com', True])
            
        conn.commit()
