from flask import Flask, request, jsonify,abort, make_response
import firebase_admin
from firebase_admin import credentials, firestore
import requests
import uuid
import datetime
from dotenv import load_dotenv
import os
import re
import asyncio
from validate_services import validate_clickup_token,validate_github_admin,validate_github_repo,validate_github_token
from flask_cors import CORS, cross_origin

 
app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'

CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization", "Session-ID"]}})



load_dotenv(".env")
valRegEx = r'^[a-zA-Z0-9_-]+$'

if False:
    service_account_key = {
        "type": os.getenv("FIREBASE_TYPE"),
        "project_id": os.getenv("FIREBASE_PROJECT_ID"),
        "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
        "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
        "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
        "client_id": os.getenv("FIREBASE_CLIENT_ID"),
        "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
        "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
        "auth_provider_x509_cert_url": os.environ.get("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
        "client_x509_cert_url": os.environ.get("FIREBASE_CLIENT_X509_CERT_URL"),
        "universe_domain": "googleapis.com"
    }
else:
    service_account_key = "C:\\Users\\Aram Jnad\Desktop\\internship\Bu1ldbot\\produ-5d1cb-firebase-adminsdk-8hzdo-f44bea1278.json"

if not firebase_admin._apps: ## EDITED
    cred = credentials.Certificate(service_account_key) ## EDITED
    firebase_admin.initialize_app(cred) ## EDITED

db = firestore.client()

SLACK_CLIENT_ID = os.getenv("SLACK_CLIENTID")
SLACK_CLIENT_SECRET = os.getenv("SLACK_CLIENT_SECRET")
SLACK_REDIRECT_URI = 'https://extraordinary-nasturtium-9fc3f1.netlify.app/dashboard/'

COLLECTION_NAME = 'users'

@app.route('/auth', methods=['POST'])
@cross_origin()
def auth():
    data = request.json
    auth_code = data.get('AUTH_CODE')
    session_id = request.headers.get('Session-ID')

    if auth_code:
        response = requests.post('https://slack.com/api/oauth.v2.access', data={
            'code': auth_code,
            'client_id': SLACK_CLIENT_ID,
            'client_secret': SLACK_CLIENT_SECRET,
            'redirect_uri': SLACK_REDIRECT_URI
        })

        if response.status_code != 200:
            abort(500)

        tokens = response.json()
        access_token = tokens.get('access_token')
        user_id = tokens.get('authed_user', {}).get('id')
        team_id = tokens.get('team', {}).get('id')

        if not access_token or not user_id or not team_id:
            abort(500)
        users_ref = db.collection(COLLECTION_NAME).document(user_id)
        user_doc = users_ref.get()

        session_id = str(uuid.uuid4())
        creation_date = datetime.datetime.now(datetime.timezone.utc)

        if not user_doc.exists():
            users_ref.set({
                'clickup_token': None,
                'github_token': None,
                'session_id': session_id,
                'team_id': team_id
            })
        else:
            users_ref.update({'session_id': session_id, 'team_id': team_id, 'name': name})

        db.collection('sessions').document(session_id).set({
            'access_token': access_token,
            'user_id': user_id,
            'team_id': team_id,
            'created_at': creation_date
        })
        res=""
        res.headers['Session-ID'] = session_id
        res.headers.add("Access-Control-Allow-Origin", "*") # CORS
        res.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        return res,200


    if session_id:
        doc_ref = db.collection('sessions').document(session_id)
        doc = doc_ref.get()
        if doc.exists():
            session_data = doc.to_dict()

            user_id = session_data.get('user_id')
            user_ref = db.collection(COLLECTION_NAME).document(user_id)
            user_doc = user_ref.get()
            user_info_response = requests.get('https://slack.com/api/users.info', headers={
            'Authorization': f'Bearer {access_token}'
        }, params={'user': user_id})

        if user_info_response.status_code != 200:
            abort(500)

        user_info = user_info_response.json()

        if not user_info.get('ok'):
            abort(500)
        user = user_info['user']
        name = user.get('profile', {}).get('display_name')
        name = name.split()[0]

        if user_doc.exists:
                user_data = user_doc.to_dict()
                session_data.update(user_data)
                return jsonify({
                "AUTH_CODE": auth_code,
                "USER_NAME":name,
                "GITHUB_STATUS": 1 if user_data.get("github_token") != None else 0, 
                "CLICKUP_STATUS": 1 if user_data.get("clickup_token") != None else 0, 
                })
        else:
            abort(401)

    abort(401)



@app.route('/is_authenticated', methods=['POST'])
@cross_origin()
def is_authenticated():
    session_id = request.headers.get('Session-ID')
    if session_id:

        session_ref = db.collection('sessions').document(session_id).get()        
        if session_ref.exists:
            response = make_response("Authenticated", 200)
            response.headers['Access-Control-Allow-Origin'] = '*'

            return response
        else:
            abort(401)
    else:
        abort(401)




def store_clickup_access_token(user_id, access_token):
    doc_ref = db.collection('users').document(user_id)
    doc_ref.set({
        'clickup_token': access_token
    }, merge=True) 

def store_github_access_token(user_id, access_token):
    doc_ref = db.collection('users').document(user_id)
    doc_ref.set({
        'github_token': access_token
    }, merge=True)

def get_clickup_access_token(authorization_code):
    client_id = os.getenv('_CLICKUP_CLIENT_ID')
    client_secret = os.getenv('_CLICKUP_CLIENT_SECRET')
    redirect_uri = os.getenv('CLICKUP_REDIRECT_URI')
    token_url = 'https://app.clickup.com/api/v2/oauth/token'

    token_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': authorization_code,
        'redirect_uri': redirect_uri
    }
    response = requests.post(token_url, data=token_data)
    if response.status_code == 200:
        return response.json().get('access_token')
    else:
        raise Exception(f"Failed to fetch access token: {response.text}")

def get_github_access_token(authorization_code):
    client_id = os.getenv('_GITHUB_CLIENT_ID')
    client_secret = os.getenv('_GITHUB_CLIENT_SECRET')
    redirect_uri = os.getenv('GITHUB_REDIRECT_URI')
    token_url = 'https://github.com/login/oauth/access_token'

    token_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': authorization_code,
        'redirect_uri': redirect_uri
    }
    headers = {'Accept': 'application/json'}
    response = requests.post(token_url, data=token_data, headers=headers)
    if response.status_code == 200:
        return response.json().get('access_token')
    else:
        raise Exception(f"Failed to fetch access token: {response.text}")

@app.route('/update', methods=['POST'])
@cross_origin()
def update_user_data():
    data = request.get_json()
    session_id = request.headers.get('Session-ID')
    session_ref = db.collection('sessions').document(session_id)
    session_doc = session_ref.get()

    if not session_doc.exists():
        abort(401)
    
    session_data = session_doc.to_dict()

    user_id = session_data.get('user_id')
    if not user_id:
       abort(401)

    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists():
        abort(401)

    token_source = data.get("SOURCE")
    authorization_code = data.get("AUTH_CODE")

    if token_source == "Github":
        try:
            access_token = get_github_access_token(authorization_code)
            store_github_access_token(user_id, access_token)
            return 200
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    if token_source == "Clickup":
        try:
            access_token = get_clickup_access_token(authorization_code)
            store_clickup_access_token(user_id, access_token)
            return 200
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    return 400
if __name__ == '__main__':
    app.run()
