from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    telegram_id = db.Column(db.String(100), unique=True, nullable=True)
    whatsapp_number = db.Column(db.String(100), unique=True, nullable=True)
    role = db.Column(db.String(20), nullable=False) # 'admin' or 'ranger'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ranger_name = db.Column(db.String(100), nullable=False)
    report_time = db.Column(db.Time, nullable=False)
    report_date = db.Column(db.Date, nullable=False)
    google_maps_link = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    status = db.Column(db.String(20), default='Pending') # Pending, Sent, Failed

    def __repr__(self):
        return f'<Report {self.id} by {self.ranger_name}>'
