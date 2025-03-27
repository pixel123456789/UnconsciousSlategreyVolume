
from flask import jsonify, request, redirect, url_for, flash, render_template
from datetime import datetime

def create_quote():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        db = get_db()
        db.execute('INSERT INTO quotes (user_id, title, description) VALUES (?, ?, ?)',
                  [session['user_id'], title, description])
        
        # Notify admin
        db.execute('INSERT INTO notifications (user_id, content) VALUES (?, ?)',
                  [1, f'New quote request: {title}'])
        db.commit()
        db.close()
        
        flash('Quote request submitted successfully')
        return redirect(url_for('dashboard'))
    
    return redirect(url_for('dashboard'))

def quote_details(quote_id):
    db = get_db()
    quote = db.execute('SELECT * FROM quotes WHERE id = ?', [quote_id]).fetchone()
    messages = db.execute('SELECT * FROM messages WHERE quote_id = ?', [quote_id]).fetchall()
    db.close()
    
    if not quote:
        flash('Quote not found')
        return redirect(url_for('dashboard'))
        
    return render_template('dashboard/quote_details.html',
                         quote=quote,
                         messages=messages)

def project_details(project_id):
    db = get_db()
    project = db.execute('SELECT * FROM projects WHERE id = ?', [project_id]).fetchone()
    messages = db.execute('SELECT * FROM messages WHERE project_id = ?', [project_id]).fetchall()
    db.close()
    
    if not project:
        flash('Project not found')
        return redirect(url_for('dashboard'))
        
    return render_template('dashboard/project_details.html',
                         project=project,
                         messages=messages)

def update_quote_status():
    if request.method == 'POST' and session.get('username') == 'admin':
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
    
    return jsonify({'success': False})

def send_message():
    if request.method == 'POST':
        content = request.form['content']
        quote_id = request.form.get('quote_id')
        project_id = request.form.get('project_id')
        receiver_id = request.form['receiver_id']
        
        db = get_db()
        db.execute('''INSERT INTO messages 
                     (sender_id, receiver_id, quote_id, project_id, content)
                     VALUES (?, ?, ?, ?, ?)''',
                  [session['user_id'], receiver_id, quote_id, project_id, content])
        
        # Create notification
        db.execute('INSERT INTO notifications (user_id, content) VALUES (?, ?)',
                  [receiver_id, 'You have a new message'])
        db.commit()
        db.close()
        
        return jsonify({'success': True})
    
    return jsonify({'success': False})
