from flask import Flask, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_session import Session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import json
import logging

# Initialize Flask app and other components
app = Flask(__name__)
CORS(app, supports_credentials=True)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

# Load configuration from a config file
with open('config.json') as config_file:
    config = json.load(config_file)

app.config.update(
    SECRET_KEY=config['FLASK_SECRET_KEY'],
    SESSION_TYPE='sqlalchemy',
    SESSION_SQLALCHEMY_TABLE='sessions',
    SQLALCHEMY_DATABASE_URI=(
        f"postgresql://{config['PGUSER']}:{config['PGPASSWORD']}"
        f"@{config['PGHOST']}:{config['PGPORT']}/{config['PGDATABASE']}"
    ),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # Ensure secure cookie is used
    SESSION_COOKIE_SAMESITE='None',  # Allow cross-site cookies
    SESSION_COOKIE_DOMAIN=config['DOMAIN']  # Use the correct domain
)

db = SQLAlchemy(app)
app.config['SESSION_SQLALCHEMY'] = db
Session(app)

class SessionData(db.Model):
    __tablename__ = 'sessions'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), unique=True)
    data = db.Column(db.LargeBinary)
    expiry = db.Column(db.DateTime)
    __table_args__ = {'extend_existing': True}

with app.app_context():
    db.create_all()

users = [
    {"email": "your-user@microsoft-login-domain", "provider": "AzureAD"},
    {"email": "your-user@password-login-domain", "provider": "Form", "password": "password123"},
    {"email": "your-user@google-login-domain", "provider": "Google"}
]

def determine_provider(email):
    for user in users:
        if user['email'] == email:
            return user['provider']
    return None

def init_saml_auth(req, provider):
    with open(f'saml_{provider}.json') as settings_file:
        saml_settings = json.load(settings_file)
    logger.debug(f"SAML Settings for {provider}: {saml_settings}")
    auth = OneLogin_Saml2_Auth(req, saml_settings)
    return auth

def prepare_flask_request(request):
    return {
        'https': 'on',
        'http_host': config['DOMAIN'],
        'server_port': '443',
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

@app.route('/api/login', methods=['POST'])
def login():
    email = request.json.get('email')
    provider = determine_provider(email)
    if not provider:
        return jsonify({"error": "You are not authorized. If you believe you should be authorized, then contact support"}), 401
    
    if provider == "Form":
        user = next(user for user in users if user['email'] == email)
        password = request.json.get('password')
        if 'password' not in user or not user['password']:
            return jsonify({"error": "Password is required for form-based authentication"}), 401
        if user['password'] == password:
            session['user'] = {"email": email, "provider": provider}
            return jsonify({"message": "Login successful"}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401

    elif provider in ["AzureAD", "Google"]:
        if 'password' in request.json:
            return jsonify({"error": "Password login not allowed for SSO users"}), 401
        req = prepare_flask_request(request)
        auth = init_saml_auth(req, provider)
        session['saml_provider'] = provider
        session.modified = True  # Ensure the session is marked as modified
        sso_url = auth.login()
        return jsonify({"ssoUrl": sso_url}), 200

    return jsonify({"error": "Unsupported provider"}), 401

@app.route('/api/acs', methods=['POST'])
def acs():
    req = prepare_flask_request(request)
    provider = session.get('saml_provider')
    if not provider:
        return jsonify({"error": "Provider not set in session"}), 400
    
    auth = init_saml_auth(req, provider)
    auth.process_response()
    errors = auth.get_errors()
    if not errors:
        session['samlUserdata'] = auth.get_attributes()
        session['user'] = {
            'email': auth.get_nameid(),
            'provider': provider,
            'session_index': auth.get_session_index()
        }
        return redirect('/')
    return jsonify({"error": "Login failed", "errors": errors}), 401

@app.route('/api/profile', methods=['GET'])
def profile():
    if 'user' not in session:
        return jsonify({"error": "Not logged in, please log in again."}), 401
    user_info = {"fullname": "John Doe", "email": session['user']['email']}
    return jsonify(user_info)

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)

