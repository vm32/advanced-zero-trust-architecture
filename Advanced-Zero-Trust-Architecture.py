# File: app.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
limiter = Limiter(app, key_func=get_remote_address)
CORS(app)

from models import User, Device, AccessLog
from routes import auth_bp, device_bp, admin_bp

app.register_blueprint(auth_bp)
app.register_blueprint(device_bp)
app.register_blueprint(admin_bp)

if __name__ == '__main__':
    app.run(debug=True)

# File: config.py

import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///zero_trust_advanced.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-string'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379'

# File: models.py

from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import func

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)
    last_login = db.Column(db.DateTime, default=func.now())
    failed_login_attempts = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    device_type = db.Column(db.String(20), nullable=False)
    os_version = db.Column(db.String(20))
    last_patch_date = db.Column(db.DateTime)
    health_status = db.Column(db.String(20), nullable=False)
    last_check = db.Column(db.DateTime, default=func.now())

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    access_time = db.Column(db.DateTime, default=func.now())
    access_type = db.Column(db.String(20), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    success = db.Column(db.Boolean, nullable=False)

# File: routes/auth.py

from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models import User, AccessLog
from app import db, limiter
from utils import validate_password_strength, is_suspicious_ip

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400
    if not validate_password_strength(data['password']):
        return jsonify({'message': 'Password does not meet security requirements'}), 400
    
    new_user = User(username=data['username'], email=data['email'], role='user')
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not user.check_password(data['password']):
        user.failed_login_attempts += 1
        db.session.commit()
        if user.failed_login_attempts >= 5:
            user.is_active = False
            db.session.commit()
            return jsonify({'message': 'Account locked due to multiple failed attempts'}), 403
        return jsonify({'message': 'Invalid username or password'}), 401
    
    if is_suspicious_ip(request.remote_addr):
        return jsonify({'message': 'Login attempt from suspicious IP'}), 403
    
    access_token = create_access_token(identity=user.id)
    log_entry = AccessLog(user_id=user.id, device_id=None, access_type='login', 
                          ip_address=request.remote_addr, success=True)
    db.session.add(log_entry)
    db.session.commit()
    return jsonify({'access_token': access_token}), 200

# File: routes/device.py

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import Device, AccessLog
from app import db
from datetime import datetime, timedelta

device_bp = Blueprint('device', __name__)

@device_bp.route('/register', methods=['POST'])
@jwt_required()
def register_device():
    data = request.get_json()
    user_id = get_jwt_identity()
    new_device = Device(device_id=data['device_id'], user_id=user_id,
                        device_type=data['device_type'], os_version=data['os_version'],
                        health_status='healthy', last_patch_date=datetime.utcnow())
    db.session.add(new_device)
    db.session.commit()
    return jsonify({'message': 'Device registered successfully'}), 201

@device_bp.route('/health_check', methods=['POST'])
@jwt_required()
def health_check():
    data = request.get_json()
    device = Device.query.filter_by(device_id=data['device_id']).first()
    if not device:
        return jsonify({'message': 'Device not found'}), 404
    
    # Perform health check logic here
    if datetime.utcnow() - device.last_patch_date > timedelta(days=30):
        device.health_status = 'needs_update'
    else:
        device.health_status = 'healthy'
    
    device.last_check = datetime.utcnow()
    db.session.commit()
    return jsonify({'health_status': device.health_status}), 200

# File: routes/admin.py

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User, AccessLog
from app import db

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/user_activity', methods=['GET'])
@jwt_required()
def user_activity():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.role != 'admin':
        return jsonify({'message': 'Unauthorized access'}), 403
    
    logs = AccessLog.query.order_by(AccessLog.access_time.desc()).limit(100).all()
    activity = [{
        'user_id': log.user_id,
        'device_id': log.device_id,
        'access_time': log.access_time,
        'access_type': log.access_type,
        'ip_address': log.ip_address,
        'success': log.success
    } for log in logs]
    return jsonify({'activity': activity}), 200

# File: utils.py

import re
import requests

def validate_password_strength(password):
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def is_suspicious_ip(ip_address):
    response = requests.get(f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}', 
                            headers={'Key': 'YOUR_ABUSEIPDB_API_KEY'})
    if response.status_code == 200:
        data = response.json()
        return data['data']['abuseConfidenceScore'] > 80
    return False

# File: requirements.txt

Flask==2.0.1
Flask-SQLAlchemy==2.5.1
Flask-Migrate==3.0.1
Flask-JWT-Extended==4.2.3
Flask-Limiter==1.4
Flask-CORS==3.0.10
requests==2.26.0
redis==3.5.3
gunicorn==20.1.0
