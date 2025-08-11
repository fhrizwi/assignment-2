import morepath
import jwt
from datetime import datetime, timedelta
import uuid
from passlib.hash import bcrypt
from morepath import Response

SECRET_KEY = 'your-secret-key'
users_db = {}
accounts = {}

class App(morepath.App):
    pass

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

def get_token_from_request(request):
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        return auth[7:]
    return None

@App.path(path='/signup', model=None)
class Signup:
    pass

@App.json(model=Signup, request_method='POST')
def signup(self, request):
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return Response(json={'message': 'Username and password required'}, status=400)
    if username in users_db:
        return Response(json={'message': 'Username already exists'}, status=400)
    user_id = str(uuid.uuid4())
    hashed_password = bcrypt.hash(password)
    users_db[username] = {'username': username, 'hashed_password': hashed_password, 'id': user_id}
    accounts[user_id] = 0.0
    return {'message': 'User created', 'user_id': user_id}

@App.path(path='/login', model=None)
class Login:
    pass

@App.json(model=Login, request_method='POST')
def login(self, request):
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = users_db.get(username)
    if not user or not bcrypt.verify(password, user['hashed_password']):
        return Response(json={'message': 'Invalid username or password'}, status=401)
    token = jwt.encode({'sub': username, 'exp': datetime.utcnow() + timedelta(minutes=30)}, SECRET_KEY, algorithm='HS256')
    return {'access_token': token, 'token_type': 'bearer'}

@App.path(path='/deposit', model=None)
class Deposit:
    pass

@App.json(model=Deposit, request_method='POST')
def deposit(self, request):
    token = get_token_from_request(request)
    user, err = verify_token(token)
    if err:
        return Response(json={'message': err}, status=401)
    data = request.json
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return Response(json={'message': 'Amount must be positive'}, status=400)
    accounts[user['id']] += amount
    return {'message': 'Deposited', 'balance': accounts[user['id']]}

@App.path(path='/withdraw', model=None)
class Withdraw:
    pass

@App.json(model=Withdraw, request_method='POST')
def withdraw(self, request):
    token = get_token_from_request(request)
    user, err = verify_token(token)
    if err:
        return Response(json={'message': err}, status=401)
    data = request.json
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return Response(json={'message': 'Amount must be positive'}, status=400)
    if amount > accounts[user['id']]:
        return Response(json={'message': 'Insufficient balance'}, status=400)
    accounts[user['id']] -= amount
    return {'message': 'Withdrawn', 'balance': accounts[user['id']]}

@App.path(path='/balance', model=None)
class Balance:
    pass

@App.json(model=Balance, request_method='GET')
def balance(self, request):
    token = get_token_from_request(request)
    user, err = verify_token(token)
    if err:
        return Response(json={'message': err}, status=401)
    return {'user_id': user['id'], 'balance': accounts[user['id']]}

if __name__ == '__main__':
    morepath.run(App())
