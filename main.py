from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import random
import string
import json
import time
import os
import secrets
from datetime import datetime, timedelta
import hashlib
import threading

app = Flask(__name__)

# Generate a consistent secret key
app.secret_key = hashlib.sha256('mooverify-key-system'.encode()).hexdigest()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# Thread-safe persistent storage
class PersistentStorage:
    def __init__(self):
        self.data = {
            'users': {},
            'admin_credentials': {
                'username': 'admin',
                'password_hash': hashlib.sha256('admin123'.encode()).hexdigest()
            },
            'user_accounts': {'users': {}}
        }
        self.lock = threading.Lock()
        self._load_from_file()
    
    def _load_from_file(self):
        """Try to load data from file for persistence"""
        try:
            # This won't work on Vercel, but provides local persistence
            if os.path.exists('data_backup.json'):
                with open('data_backup.json', 'r') as f:
                    loaded_data = json.load(f)
                    self.data.update(loaded_data)
        except:
            pass
    
    def _save_to_file(self):
        """Try to save data to file for persistence"""
        try:
            # This won't work on Vercel, but provides local persistence
            with open('data_backup.json', 'w') as f:
                json.dump(self.data, f)
        except:
            pass
    
    def load_data(self):
        with self.lock:
            return self.data.get('users', {})
    
    def save_data(self, data):
        with self.lock:
            self.data['users'] = data
            self._save_to_file()
            return True
    
    def load_user_accounts(self):
        with self.lock:
            return self.data.get('user_accounts', {'users': {}})
    
    def save_user_accounts(self, accounts):
        with self.lock:
            self.data['user_accounts'] = accounts
            self._save_to_file()
            return True
    
    def load_admin_credentials(self):
        with self.lock:
            return self.data.get('admin_credentials', {
                'username': 'admin',
                'password_hash': hashlib.sha256('admin123'.encode()).hexdigest()
            })
    
    def save_admin_credentials(self, credentials):
        with self.lock:
            self.data['admin_credentials'] = credentials
            self._save_to_file()
            return True

# Global storage instance
storage = PersistentStorage()

# Storage functions
def load_data():
    return storage.load_data()

def save_data(data):
    return storage.save_data(data)

def load_user_accounts():
    return storage.load_user_accounts()

def save_user_accounts(accounts):
    return storage.save_user_accounts(accounts)

def load_admin_credentials():
    return storage.load_admin_credentials()

def save_admin_credentials(credentials):
    return storage.save_admin_credentials(credentials)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_admin(username, password):
    credentials = load_admin_credentials()
    return (username == credentials['username'] and 
            hash_password(password) == credentials['password_hash'])

def verify_user(username, password):
    accounts = load_user_accounts()
    if username in accounts['users']:
        stored_hash = accounts['users'][username]['password_hash']
        return hash_password(password) == stored_hash
    return False

def verify_api_key(api_key):
    accounts = load_user_accounts()
    for username, user_data in accounts['users'].items():
        if 'api_keys' in user_data:
            for key_data in user_data['api_keys']:
                if key_data['key'] == api_key:
                    return username
    return None

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def user_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_logged_in'):
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_unique_moo_key():
    charset = string.ascii_uppercase + string.digits
    data = load_data()
    attempts = 0
    while attempts < 100:
        key_parts = [
            ''.join(random.choices(charset, k=3)),
            ''.join(random.choices(charset, k=3)),
            ''.join(random.choices(charset, k=3)),
            ''.join(random.choices(charset, k=3))
        ]
        key = f"MOO-{key_parts[0]}-{key_parts[1]}-{key_parts[2]}-{key_parts[3]}"
        key_exists = False
        for user_data in data.values():
            if user_data.get('key') == key:
                key_exists = True
                break
        if not key_exists:
            return key
        attempts += 1
    raise Exception("Could not generate unique key after 100 attempts")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/generate')
def index():
    token = request.args.get('token')
    if not token:
        return render_template('error.html', message="No token provided"), 400
    data_store = load_data()
    current_time = time.time()
    if token not in data_store:
        data_store[token] = {
            'created_timestamp': current_time,
            'ip_address': request.remote_addr,
            'key': None
        }
        save_data(data_store)
    user_data = data_store[token]
    if current_time - user_data['created_timestamp'] > 21600:
        user_data['created_timestamp'] = current_time
        user_data['key'] = None
        save_data(data_store)
    if user_data.get('key'):
        return render_template('key_already_generated.html', 
                             token=token, 
                             key=user_data['key'])
    session['verification_token'] = token
    session['verification_start'] = time.time()
    session.permanent = True
    return render_template('index.html', token=token)

@app.route('/verify_token', methods=['POST'])
def verify_token():
    try:
        token = request.json.get('token', '').strip()
        if not token:
            return jsonify({'success': False, 'message': 'No token provided'})
        data_store = load_data()
        current_time = time.time()
        if token not in data_store:
            data_store[token] = {
                'created_timestamp': current_time,
                'ip_address': request.remote_addr,
                'key': None
            }
            save_data(data_store)
        user_data = data_store[token]
        if current_time - user_data['created_timestamp'] > 21600:
            user_data['created_timestamp'] = current_time
            user_data['key'] = None
            save_data(data_store)
        if user_data.get('key'):
            return jsonify({'success': False, 'message': 'Key already generated for this user'})
        session['verification_token'] = token
        session['verification_start'] = time.time()
        session.permanent = True
        return jsonify({'success': True, 'message': 'Token verified successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'})

@app.route('/generate_key', methods=['POST'])
def generate_key():
    try:
        token = session.get('verification_token')
        start_time = session.get('verification_start')
        if not token or not start_time:
            return jsonify({'success': False, 'message': 'No active verification session. Please start over.'})
        elapsed = time.time() - start_time
        if elapsed < 30:
            remaining = 30 - int(elapsed)
            return jsonify({'success': False, 'message': f'Please wait {remaining} more seconds before generating your key.'})
        data_store = load_data()
        if token not in data_store:
            return jsonify({'success': False, 'message': 'User not found'})
        user_data = data_store[token]
        if user_data.get('key'):
            return jsonify({'success': False, 'message': 'Key already generated for this user'})
        try:
            key = generate_unique_moo_key()
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})
        current_time = time.time()
        user_data['key'] = key
        user_data['key_generated_at'] = datetime.now().isoformat()
        user_data['key_generated_timestamp'] = current_time
        save_data(data_store)
        session.pop('verification_token', None)
        session.pop('verification_start', None)
        return jsonify({
            'success': True, 
            'key': key,
            'message': 'MOO Key generated successfully!'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'})

@app.route('/validate_key', methods=['POST'])
def validate_key():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'message': 'No data provided'})
        
        key = data.get('key', '').upper().strip()
        username = data.get('username', 'unknown')
        
        if not validate_moo_key_format(key):
            return jsonify({'valid': False, 'message': 'Invalid key format. Use: MOO-XXX-XXX-XXX-XXX'})
        
        data_store = load_data()
        current_time = time.time()
        
        key_found = False
        key_user = None
        key_data = None
        
        for user, user_data in data_store.items():
            if user_data.get('key') == key:
                key_found = True
                key_user = user
                key_data = user_data
                break
        
        if not key_found:
            return jsonify({'valid': False, 'message': 'Key not found in database'})
        
        if current_time - key_data['key_generated_timestamp'] > 21600:
            return jsonify({'valid': False, 'message': 'Key has expired (6 hours)'})
        
        if key_user != username:
            return jsonify({'valid': False, 'message': 'Key does not belong to this user'})
        
        return jsonify({
            'valid': True, 
            'message': 'Key validated successfully',
            'generated_at': key_data['key_generated_at']
        })
    
    except Exception as e:
        return jsonify({'valid': False, 'message': f'Validation error: {str(e)}'})

def validate_moo_key_format(key):
    import re
    pattern = r'^MOO-[A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{3}$'
    return re.match(pattern, key.upper()) is not None

@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password:
            return render_template('user_signup.html', error='Username and password are required')
        
        if password != confirm_password:
            return render_template('user_signup.html', error='Passwords do not match')
        
        if len(password) < 6:
            return render_template('user_signup.html', error='Password must be at least 6 characters long')
        
        accounts = load_user_accounts()
        
        if username in accounts['users']:
            return render_template('user_signup.html', error='Username already exists')
        
        accounts['users'][username] = {
            'password_hash': hash_password(password),
            'created_at': datetime.now().isoformat(),
            'api_keys': []
        }
        
        save_user_accounts(accounts)
        
        session['user_logged_in'] = True
        session['user_username'] = username
        return redirect(url_for('user_dashboard'))
    
    return render_template('user_signup.html')

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if verify_user(username, password):
            session['user_logged_in'] = True
            session['user_username'] = username
            return redirect(url_for('user_dashboard'))
        else:
            return render_template('user_login.html', error='Invalid username or password')
    
    return render_template('user_login.html')

@app.route('/user/logout')
def user_logout():
    session.pop('user_logged_in', None)
    session.pop('user_username', None)
    return redirect(url_for('home'))

@app.route('/user/dashboard')
@user_required
def user_dashboard():
    accounts = load_user_accounts()
    user_data = accounts['users'].get(session['user_username'], {})
    return render_template('user_dashboard.html', user_data=user_data)

@app.route('/user/generate_api_key', methods=['POST'])
@user_required
def generate_api_key():
    try:
        accounts = load_user_accounts()
        username = session['user_username']
        
        api_key = secrets.token_hex(32)
        
        if 'api_keys' not in accounts['users'][username]:
            accounts['users'][username]['api_keys'] = []
        
        accounts['users'][username]['api_keys'].append({
            'key': api_key,
            'created_at': datetime.now().isoformat(),
            'last_used': None
        })
        
        save_user_accounts(accounts)
        
        return jsonify({'success': True, 'api_key': api_key})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/user/revoke_api_key', methods=['POST'])
@user_required
def revoke_api_key():
    try:
        data = request.get_json()
        api_key = data.get('api_key')
        
        accounts = load_user_accounts()
        username = session['user_username']
        
        if 'api_keys' in accounts['users'][username]:
            accounts['users'][username]['api_keys'] = [
                key for key in accounts['users'][username]['api_keys'] 
                if key['key'] != api_key
            ]
            
            save_user_accounts(accounts)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if verify_admin(username, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error='Invalid credentials')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return redirect(url_for('home'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    data = load_data()
    accounts = load_user_accounts()
    
    total_keys = 0
    total_tokens = len(data)
    used_tokens = 0
    active_keys = 0
    current_time = time.time()
    total_users = len(accounts['users'])
    
    for user_data in data.values():
        if user_data.get('key'):
            total_keys += 1
            used_tokens += 1
            if current_time - user_data.get('key_generated_timestamp', 0) < 21600:
                active_keys += 1
    
    stats = {
        'total_keys': total_keys,
        'total_tokens': total_tokens,
        'used_tokens': used_tokens,
        'active_keys': active_keys,
        'total_users': total_users
    }
    
    return render_template('admin_dashboard.html', stats=stats, keys=data, users=accounts['users'])

@app.route('/admin/delete_key', methods=['POST'])
@admin_required
def admin_delete_key():
    try:
        data = request.get_json()
        token = data.get('token')
        data_store = load_data()
        if token in data_store:
            data_store[token]['key'] = None
            save_data(data_store)
            return jsonify({'success': True, 'message': 'Key deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Token not found'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/clear_expired', methods=['POST'])
@admin_required
def admin_clear_expired():
    try:
        data_store = load_data()
        current_time = time.time()
        expired_count = 0
        expired_users = []
        for username, user_data in data_store.items():
            if current_time - user_data.get('created_timestamp', 0) > 21600:
                expired_users.append(username)
        for username in expired_users:
            if username in data_store:
                del data_store[username]
                expired_count += 1
        save_data(data_store)
        return jsonify({'success': True, 'message': f'Cleared {expired_count} expired tokens'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/change_password', methods=['POST'])
@admin_required
def admin_change_password():
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        credentials = load_admin_credentials()
        if hash_password(current_password) != credentials['password_hash']:
            return jsonify({'success': False, 'message': 'Current password is incorrect'})
        credentials['password_hash'] = hash_password(new_password)
        save_admin_credentials(credentials)
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-API-Key')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

def create_app():
    return app

if __name__ == '__main__':
    print("MooVerify Key System Starting...")
    print("Server running on http://0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
