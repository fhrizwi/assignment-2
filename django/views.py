import json
import jwt
from datetime import datetime, timedelta
import uuid
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from passlib.hash import bcrypt

SECRET_KEY = 'your-secret-key'
users_db = {}
accounts = {}

def get_token_from_request(request):
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

@csrf_exempt
def signup(request):
    if request.method != 'POST':
        return JsonResponse({'message': 'Method not allowed'}, status=405)
    data = json.loads(request.body)
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return JsonResponse({'message': 'Username and password required'}, status=400)
    if username in users_db:
        return JsonResponse({'message': 'Username already exists'}, status=400)
    user_id = str(uuid.uuid4())
    hashed_password = bcrypt.hash(password)
    users_db[username] = {'username': username, 'hashed_password': hashed_password, 'id': user_id}
    accounts[user_id] = 0.0
    return JsonResponse({'message': 'User created', 'user_id': user_id})

@csrf_exempt
def login(request):
    if request.method != 'POST':
        return JsonResponse({'message': 'Method not allowed'}, status=405)
    data = json.loads(request.body)
    username = data.get('username')
    password = data.get('password')
    user = users_db.get(username)
    if not user or not bcrypt.verify(password, user['hashed_password']):
        return JsonResponse({'message': 'Invalid username or password'}, status=401)
    token = jwt.encode({'sub': username, 'exp': datetime.utcnow() + timedelta(minutes=30)}, SECRET_KEY, algorithm='HS256')
    return JsonResponse({'access_token': token, 'token_type': 'bearer'})

@csrf_exempt
def deposit(request):
    if request.method != 'POST':
        return JsonResponse({'message': 'Method not allowed'}, status=405)
    token = get_token_from_request(request)
    user, err = verify_token(token)
    if err:
        return JsonResponse({'message': err}, status=401)
    data = json.loads(request.body)
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return JsonResponse({'message': 'Amount must be positive'}, status=400)
    accounts[user['id']] += amount
    return JsonResponse({'message': 'Deposited', 'balance': accounts[user['id']]})

@csrf_exempt
def withdraw(request):
    if request.method != 'POST':
        return JsonResponse({'message': 'Method not allowed'}, status=405)
    token = get_token_from_request(request)
    user, err = verify_token(token)
    if err:
        return JsonResponse({'message': err}, status=401)
    data = json.loads(request.body)
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return JsonResponse({'message': 'Amount must be positive'}, status=400)
    if amount > accounts[user['id']]:
        return JsonResponse({'message': 'Insufficient balance'}, status=400)
    accounts[user['id']] -= amount
    return JsonResponse({'message': 'Withdrawn', 'balance': accounts[user['id']]})

def balance(request):
    if request.method != 'GET':
        return JsonResponse({'message': 'Method not allowed'}, status=405)
    token = get_token_from_request(request)
    user, err = verify_token(token)
    if err:
        return JsonResponse({'message': err}, status=401)
    return JsonResponse({'user_id': user['id'], 'balance': accounts[user['id']]})
