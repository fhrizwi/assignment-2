from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
import uuid
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

users_db = {}
accounts = {}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            bearer = request.headers['Authorization']
            if bearer and bearer.startswith("Bearer "):
                token = bearer[7:]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_db.get(data['sub'])
            if current_user is None:
                return jsonify({'message': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired!'}), 401
        except Exception:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    if username in users_db:
        return jsonify({'message': 'Username already exists'}), 400
    user_id = str(uuid.uuid4())
    hashed_password = generate_password_hash(password)
    users_db[username] = {'username': username, 'hashed_password': hashed_password, 'id': user_id}
    accounts[user_id] = 0.0
    return jsonify({'message': 'User created', 'user_id': user_id})

@app.route('/login', methods=['POST'])
def login():
    data = request.form
    username = data.get('username')
    password = data.get('password')
    user = users_db.get(username)
    if not user or not check_password_hash(user['hashed_password'], password):
        return jsonify({'message': 'Invalid username or password'}), 401
    token = jwt.encode({
        'sub': username,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'access_token': token, 'token_type': 'bearer'})

@app.route('/deposit', methods=['POST'])
@token_required
def deposit(current_user):
    data = request.get_json()
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({'message': 'Amount must be positive'}), 400
    accounts[current_user['id']] += amount
    return jsonify({'message': 'Deposited', 'balance': accounts[current_user['id']]})

@app.route('/withdraw', methods=['POST'])
@token_required
def withdraw(current_user):
    data = request.get_json()
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({'message': 'Amount must be positive'}), 400
    if amount > accounts[current_user['id']]:
        return jsonify({'message': 'Insufficient balance'}), 400
    accounts[current_user['id']] -= amount
    return jsonify({'message': 'Withdrawn', 'balance': accounts[current_user['id']]})

@app.route('/balance', methods=['GET'])
@token_required
def balance(current_user):
    return jsonify({'user_id': current_user['id'], 'balance': accounts[current_user['id']]})

if __name__ == '__main__':
    app.run(debug=True)
