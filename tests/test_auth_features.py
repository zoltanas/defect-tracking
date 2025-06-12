import pytest
from app import app as flask_app

@pytest.fixture
def app():
    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False, # Disable CSRF for testing forms
    })
    yield flask_app

@pytest.fixture
def client(app):
    return app.test_client()

def test_register_page_renders_confirm_password(client):
    """Test that the register page renders with two password fields."""
    response = client.get('/register')
    assert response.status_code == 200
    assert b'Password' in response.data
    assert b'Confirm Password' in response.data
    assert response.data.count(b'<input type="password"') == 2

def test_register_fails_if_passwords_do_not_match(client):
    """Test that registration fails if the passwords do not match."""
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'password123',
        'confirm_password': 'password456'
    }, follow_redirects=True)
    assert response.status_code == 200 # Should re-render the register page
    assert b'Passwords do not match' in response.data
    # Check that user was not created (assuming User model and db access if possible,
    # for now, we check for the error message)

def test_register_succeeds_if_passwords_match(client):
    """Test that registration succeeds if the passwords match (and username is unique)."""
    # This test assumes that a user 'newuser' doesn't exist.
    # For a real app, you'd want to ensure the user is cleaned up from DB after test.
    response = client.post('/register', data={
        'username': 'newuser',
        'password': 'password123',
        'confirm_password': 'password123'
    }, follow_redirects=True)
    # Successful registration should redirect to login page
    assert response.status_code == 200 # Or the status code for redirection if not 200 after follow_redirects
    assert b'Login' in response.data # Assuming redirection to login page shows 'Login'
    assert b'Create your account' not in response.data # Should not be on register page
    assert b'Passwords do not match' not in response.data
    # Further checks could involve trying to log in as 'newuser' or checking the database.
