from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Database Model
class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    fullname = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(1000), nullable=False)
    is_verify = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.Date)
    updated_at = db.Column(db.Date)
    
# class History(db.Model):
#     __tablename__ = 'history'
#     id = db.Column(db.Integer(), primary_key=True, nullable=False)
#     user_id = db.Column(db.Integer(), nullable=False)
#     date = db.Column(db.Date)
#     movement = db.Column(db.String(64), nullable=False)
class History(db.Model):
    __tablename__ = 'history'
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    user_id = db.Column(db.Integer(), nullable=False)
    date = db.Column(db.Date)
    movement = db.Column(db.Text, nullable=False)  # Use Text for larger strings
