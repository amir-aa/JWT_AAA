from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from peewee import *
from playhouse.pool import PooledSqliteDatabase
from datetime import datetime, timedelta
from bcrypt import hashpw, gensalt, checkpw
import os
import logging
from functools import wraps
from marshmallow import Schema, fields, ValidationError

# Flask app setup
app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')  # Use env variable in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

DATABASE_NAME = os.getenv('DATABASE_NAME', 'aaa.db')  # Use in-memory for testing
DATABASE = SqliteDatabase(DATABASE_NAME)  # Use PooledSqliteDatabase if needed

# Models
class BaseModel(Model):
    class Meta:
        database = DATABASE
# JWT setup
jwt = JWTManager(app)

# Models (WHAT)

class User(BaseModel):
    id = AutoField()
    username = CharField(unique=True, max_length=80)
    password = CharField(max_length=120)
    role = CharField(max_length=20)
    last_login = DateTimeField(null=True)

class AuditLog(BaseModel):
    id = AutoField()
    user = ForeignKeyField(User, backref='logs')
    action = CharField(max_length=100)
    timestamp = DateTimeField(default=datetime.utcnow)
    details = TextField(null=True)

# Schemas for validation
class UserSchema(Schema):
    username = fields.String(required=True)
    password = fields.String(required=True)
    role = fields.String(required=True)

class LoginSchema(Schema):
    username = fields.String(required=True)
    password = fields.String(required=True)



def log_action(user_id, action, details=None):
    AuditLog.create(user=user_id, action=action, details=details)
# Authentication Decorator (WHO)
def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.get_or_none(User.id == current_user_id)
            if not user or user.role != role:
                return jsonify({"msg": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Audit logging function (HOW)
def log_action(user_id, action, details=None):
    AuditLog.create(user=user_id, action=action, details=details)

# Routes (WHERE)
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    try:
        validated_data = UserSchema().load(data)
    except ValidationError as e:
        return jsonify({"msg": "Validation failed", "errors": e.messages}), 400

    hashed_password = hashpw(validated_data['password'].encode(), gensalt()).decode()
    try:
        new_user = User.create(
            username=validated_data['username'],
            password=hashed_password,
            role=validated_data['role']
        )
        log_action(new_user.id, "USER_REGISTERED")
        return jsonify({"msg": "User registered successfully"}), 201
    except IntegrityError:
        return jsonify({"msg": "Username already exists"}), 400

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    try:
        validated_data = LoginSchema().load(data)
    except ValidationError as e:
        return jsonify({"msg": "Validation failed", "errors": e.messages}), 400

    user = User.get_or_none(User.username == validated_data['username'])
    if user and checkpw(validated_data['password'].encode(), user.password.encode()):
        user.last_login = datetime.utcnow()
        user.save()
        access_token = create_access_token(identity=str(user.id))  # Convert user.id to string
        log_action(user.id, "USER_LOGIN")
        return jsonify({"token": access_token}), 200
    
    return jsonify({"msg": "Invalid credentials"}), 401
@app.route('/protected', methods=['GET'])
@jwt_required()
@require_role('admin')
def protected():
    current_user_id = get_jwt_identity()
    log_action(current_user_id, "ACCESSED_PROTECTED_RESOURCE")
    return jsonify({"msg": "Access granted to protected resource"})

@app.route('/audit/logs', methods=['GET'])
@jwt_required()
@require_role('admin')
def get_audit_logs():
    logs = (AuditLog
            .select(AuditLog, User)
            .join(User)
            .order_by(AuditLog.timestamp.desc())
            .limit(100))
    return jsonify([{
        "user_id": log.user.id,
        "username": log.user.username,
        "action": log.action,
        "timestamp": log.timestamp.isoformat(),
        "details": log.details
    } for log in logs])

# Database initialization (WHEN)
@app.before_request
def initialize_database():
    DATABASE.connect(reuse_if_open=True)
    #DATABASE.create_tables([User, AuditLog],safe=True)
    #DATABASE.close()

"""@app.teardown_appcontext
def close_database(exception=None):
    if not DATABASE.is_closed():
        DATABASE.close()"""

# Error handling (HOW MUCH - cost in terms of errors)
@app.errorhandler(Exception)
def handle_error(error):
    logging.error(f"An error occurred: {str(error)}")
    return jsonify({"msg": "An internal error occurred"}), 500

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True)
