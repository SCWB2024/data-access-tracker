from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

app = Flask(__name__)
app.config.from_pyfile('config.py')

db = SQLAlchemy(app)

# Database Model for Access Log
class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    dataset_name = db.Column(db.String(120), nullable=False)
    access_purpose = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<AccessLog {self.username} accessed {self.dataset_name} at {self.timestamp}>'

# --- Routes ---

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Route for logging access
@app.route('/log', methods=['GET', 'POST'])
def log_access():
    if request.method == 'POST':
        username = request.form['username']
        dataset_name = request.form['dataset_name']
        access_purpose = request.form['access_purpose']

        if not username or not dataset_name or not access_purpose:
            flash('All fields are required!', 'danger')
        else:
            new_log = AccessLog(username=username, dataset_name=dataset_name, access_purpose=access_purpose)
            db.session.add(new_log)
            db.session.commit()
            flash('Access logged successfully!', 'success')
            return redirect(url_for('access_history')) # Redirect to history after logging
    return render_template('log_access.html')

# Route for viewing access history
@app.route('/history')
def access_history():
    # Fetch all logs, ordered by timestamp descending
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).all()
    return render_template('access_history.html', logs=logs)

if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)