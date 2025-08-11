from sanic import Sanic
from sanic.response import json
from sanic_ext import Extend
import jwt
from datetime import datetime, timedelta
import uuid
from passlib.hash import bcrypt

app = Sanic("BankAPI")
Extend(app)

SECRET_KEY = 'your-secret-key'
users_db = {}
accounts = {}

def get_token_from_header(request):
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        return auth[7:]
    return None

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = payload.get('sub')
        if not username or username not in users_db:
            return None, 'Invalid token or user'
        return users_db[username], None
    except jwt.ExpiredSignatureError:
        return None, 'Token expired'
    except Exception:
        return None, 'Invalid token'

@app.post("/signup")
async def signup(request):
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return json({'message': 'Username and password required'}, status=400)
    if username in users_db:
        return json({'message': 'Username already exists'}, status=400)
    user_id = str(uuid.uuid4())
    hashed_password = bcrypt.hash(password)
    users_db[username] = {'username': username, 'hashed_password': hashed_password, 'id': user_id}
    accounts[user_id] = 0.0
    return json({'message': 'User created', 'user_id': user_id})

@app.post("/login")
async def login(request):
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = users_db.get(username)
    if not user or not bcrypt.verify(password, user['hashed_password']):
        return json({'message': 'Invalid username or password'}, status=401)
    token = jwt.encode({'sub': username, 'exp': datetime.utcnow() + timedelta(minutes=30)}, SECRET_KEY, algorithm='HS256')
    return json({'access_token': token, 'token_type': 'bearer'})

@app.post("/deposit")
async def deposit(request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        return json({'message': err}, status=401)
    data = request.json
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return json({'message': 'Amount must be positive'}, status=400)
    accounts[user['id']] += amount
    return json({'message': 'Deposited', 'balance': accounts[user['id']]})

@app.post("/withdraw")
async def withdraw(request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        return json({'message': err}, status=401)
    data = request.json
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return json({'message': 'Amount must be positive'}, status=400)
    if amount > accounts[user['id']]:
        return json({'message': 'Insufficient balance'}, status=400)
    accounts[user['id']] -= amount
    return json({'message': 'Withdrawn', 'balance': accounts[user['id']]})

@app.get("/balance")
async def balance(request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        return json({'message': err}, status=401)
    return json({'user_id': user['id'], 'balance': accounts[user['id']]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
