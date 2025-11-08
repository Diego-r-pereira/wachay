from flask_sqlalchemy import SQLAlchemy
from enum import Enum

db = SQLAlchemy()

class UserRole(Enum):
    ADMIN = 'admin'
    GUARD = 'guard'
    COMMON = 'common'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.Enum(UserRole), default=UserRole.COMMON, nullable=False)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ranger_name = db.Column(db.String(100), nullable=False)
    report_time = db.Column(db.String(100), nullable=False)
    report_date = db.Column(db.String(100), nullable=False)
    google_maps_link = db.Column(db.String(200), nullable=False)
    image_path = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500), nullable=True)
