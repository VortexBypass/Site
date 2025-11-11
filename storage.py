import os
import json
from vercel_kv import kv

# Initialize KV store
def get_kv_data(key, default):
    try:
        data = kv.get(key)
        return data if data is not None else default
    except:
        return default

def set_kv_data(key, data):
    try:
        kv.set(key, data)
        return True
    except:
        return False

# Use KV storage functions
def load_data():
    return get_kv_data('mooverify_data', {'users': {}})

def save_data(data):
    return set_kv_data('mooverify_data', data)

def load_user_accounts():
    return get_kv_data('mooverify_users', {'users': {}})

def save_user_accounts(accounts):
    return set_kv_data('mooverify_users', accounts)

def load_admin_credentials():
    return get_kv_data('mooverify_admin', {
        'username': 'admin',
        'password_hash': 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'  # '123'
    })
