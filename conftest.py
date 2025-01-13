import pytest
from app import app as flask_app, DATABASE,AuditLog,User
from bcrypt import hashpw, gensalt
@pytest.fixture
def app():
    # Configure the app for testing
    flask_app.config['TESTING'] = True
    flask_app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    
    # Use an in-memory SQLite database for testing
    flask_app.config['DATABASE_NAME'] = ':memory:'
    
    # Initialize the database
    with flask_app.app_context():
        DATABASE.init(':memory:')
        DATABASE.connect(reuse_if_open=True)
        DATABASE.create_tables([User, AuditLog])
    
    yield flask_app
    
    # Clean up after tests
    DATABASE.drop_tables([User, AuditLog])
    DATABASE.close()

@pytest.fixture
def client(app):
    return app.test_client()
@pytest.fixture
def non_admin_token(client):
    # Create a non-admin user
    non_admin_user = {
        "username": "nonadmin",
        "password": "nonadminpassword",
        "role": "user"
    }
    hashed_password = hashpw(non_admin_user['password'].encode(), gensalt()).decode()
    User.create(username=non_admin_user['username'], password=hashed_password, role=non_admin_user['role'])
    
    # Log in as the non-admin user and get the token
    response = client.post('/auth/login', json={"username": non_admin_user['username'], "password": non_admin_user['password']})
    return response.json['token']