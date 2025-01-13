import pytest
from app import User, AuditLog, DATABASE,log_action
from bcrypt import hashpw, gensalt

# Test data
TEST_USER = {
    "username": "testuser",
    "password": "testpassword",
    "role": "user"
}

ADMIN_USER = {
    "username": "adminuser",
    "password": "adminpassword",
    "role": "admin"
}

# Helper functions
def create_test_user(username, password, role):
    hashed_password = hashpw(password.encode(), gensalt()).decode()
    user = User.create(username=username, password=hashed_password, role=role)
    return user

def get_auth_token(client, username, password):
    response = client.post('/auth/login', json={"username": username, "password": password})
    return response.json['token']

# Tests
def test_register_success(client):
    response = client.post('/auth/register', json=TEST_USER)
    assert response.status_code == 201
    assert response.json['msg'] == "User registered successfully"

def test_register_fail_duplicate_username(client):
    create_test_user(TEST_USER['username'], TEST_USER['password'], TEST_USER['role'])
    response = client.post('/auth/register', json=TEST_USER)
    assert response.status_code == 400
    assert response.json['msg'] == "Username already exists"

def test_login_success(client):
    create_test_user(TEST_USER['username'], TEST_USER['password'], TEST_USER['role'])
    response = client.post('/auth/login', json={"username": TEST_USER['username'], "password": TEST_USER['password']})
    assert response.status_code == 200
    assert 'token' in response.json

def test_protected_success(client):
    # Create an admin user
    create_test_user(ADMIN_USER['username'], ADMIN_USER['password'], ADMIN_USER['role'])
    
    # Get the authentication token
    token = get_auth_token(client, ADMIN_USER['username'], ADMIN_USER['password'])
    print(f"Generated Token: {token}")  # Debug print
    
    # Access the protected route
    headers = {'Authorization': f'Bearer {token}'}
    response = client.get('/protected', headers=headers)
    print(f"Response JSON: {response.json}")  # Debug print
    
    # Assert the response
    assert response.status_code == 200
    assert response.json['msg'] == "Access granted to protected resource"
# Cleanup is handled by the app fixture in conftest.py


def test_get_audit_logs_success(client):
    # Create an admin user
    admin_user = create_test_user(ADMIN_USER['username'], ADMIN_USER['password'], ADMIN_USER['role'])
    
    # Create some audit logs
    log_action(admin_user.id, "TEST_ACTION", details="Test details")
    log_action(admin_user.id, "ANOTHER_ACTION", details="More details")
    
    # Get the authentication token
    token = get_auth_token(client, ADMIN_USER['username'], ADMIN_USER['password'])
    
    # Access the audit logs route
    headers = {'Authorization': f'Bearer {token}'}
    response = client.get('/audit/logs', headers=headers)
    
    # Assert the response
    assert response.status_code == 200
    assert isinstance(response.json, list)
    assert len(response.json) == 3  # Two logs + one USER_LOGIN log
    assert response.json[0]['action'] == "USER_LOGIN"  # Most recent log first
    assert response.json[2]['action'] == "ANOTHER_ACTION"
    assert response.json[1]['action'] == "TEST_ACTION"
def test_get_audit_logs_fail_insufficient_permissions(client):
    # Create a non-admin user
    create_test_user(TEST_USER['username'], TEST_USER['password'], TEST_USER['role'])
    
    # Get the authentication token
    token = get_auth_token(client, TEST_USER['username'], TEST_USER['password'])
    
    # Access the audit logs route
    headers = {'Authorization': f'Bearer {token}'}
    response = client.get('/audit/logs', headers=headers)
    
    # Assert the response
    assert response.status_code == 403
    assert response.json['msg'] == "Insufficient permissions"

def test_get_audit_logs_fail_no_token(client):
    # Access the audit logs route without a token
    response = client.get('/audit/logs')
    
    # Assert the response
    assert response.status_code == 401

#edgecase
class TestProtectedAccess:
	def test_access_denied_for_non_admin(self, client, non_admin_token):
		response = client.get('/protected', headers={'Authorization': f'Bearer {non_admin_token}'})
		assert response.status_code == 403
		assert response.json == {'msg': 'Insufficient permissions'}