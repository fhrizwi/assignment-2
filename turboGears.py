from tg import expose, TGController, request, response, AppConfig, minimal_wsgi
import jwt
from datetime import datetime, timedelta
import uuid
from passlib.hash import bcrypt

SECRET_KEY = 'your-secret-key'
users_db = {}
accounts = {}

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

def get_token():
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        return auth[7:]
    return None

class RootController(TGController):
    @expose('json')
    def signup(self, **kw):
        username = kw.get('username')
        password = kw.get('password')
        if not username or not password:
            response.status = 400
            return {'message': 'Username and password required'}
        if username in users_db:
            response.status = 400
            return {'message': 'Username already exists'}
        user_id = str(uuid.uuid4())
        hashed_password = bcrypt.hash(password)
        users_db[username] = {'username': username, 'hashed_password': hashed_password, 'id': user_id}
        accounts[user_id] = 0.0
        return {'message': 'User created', 'user_id': user_id}

    @expose('json')
    def login(self, **kw):
        username = kw.get('username')
        password = kw.get('password')
        user = users_db.get(username)
        if not user or not bcrypt.verify(password, user['hashed_password']):
            response.status = 401
            return {'message': 'Invalid username or password'}
        token = jwt.encode({'sub': username, 'exp': datetime.utcnow() + timedelta(minutes=30)}, SECRET_KEY, algorithm='HS256')
        return {'access_token': token, 'token_type': 'bearer'}

    @expose('json')
    def deposit(self, **kw):
        token = get_token()
        user, err = verify_token(token)
        if err:
            response.status = 401
            return {'message': err}
        try:
            amount = float(kw.get('amount', 0))
        except:
            amount = 0
        if amount <= 0:
            response.status = 400
            return {'message': 'Amount must be positive'}
        accounts[user['id']] += amount
        return {'message': 'Deposited', 'balance': accounts[user['id']]}

    @expose('json')
    def withdraw(self, **kw):
        token = get_token()
        user, err = verify_token(token)
        if err:
            response.status = 401
            return {'message': err}
        try:
            amount = float(kw.get('amount', 0))
        except:
            amount = 0
        if amount <= 0:
            response.status = 400
            return {'message': 'Amount must be positive'}
        if amount > accounts[user['id']]:
            response.status = 400
            return {'message': 'Insufficient balance'}
        accounts[user['id']] -= amount
        return {'message': 'Withdrawn', 'balance': accounts[user['id']]}

    @expose('json')
    def balance(self):
        token = get_token()
        user, err = verify_token(token)
        if err:
            response.status = 401
            return {'message': err}
        return {'user_id': user['id'], 'balance': accounts[user['id']]}

if __name__ == '__main__':
    config = AppConfig(minimal=True, root_controller=RootController())
    app = config.make_wsgi_app()
    from wsgiref.simple_server import make_server
    server = make_server('0.0.0.0', 8080, app)
    print("Serving on http://0.0.0.0:8080")
    server.serve_forever()
