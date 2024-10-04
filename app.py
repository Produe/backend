from flask import Flask, request, jsonify,abort
import firebase_admin
from firebase_admin import credentials, firestore
import requests
import uuid
import datetime
from dotenv import load_dotenv
import os
import re
import asyncio
import validate_services
from flask_cors import CORS, cross_origin

 
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://extraordinary-nasturtium-9fc3f1.netlify.app/, 127.0.0.1"}})

load_dotenv("TOKENS.env")
valRegEx = r'^[a-zA-Z0-9_-]+$'

if True:
    service_account_key = {
        "type": os.getenv("FIREBASE_TYPE"),
        "project_id": os.getenv("FIREBASE_PROJECT_ID"),
        "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
        "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
        "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
        "client_id": os.getenv("FIREBASE_CLIENT_ID"),
        "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
        "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
        "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
        "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL"),
        "universe_domain": "googleapis.com"
    }
else:
    service_account_key = "produ-5d1cb-firebase-adminsdk-8hzdo-12c1025bab.json"

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
            return jsonify({'request_state': 500})
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
        users_ref = db.collection(COLLECTION_NAME).document(user_id)
        user_doc = users_ref.get()

        session_id = str(uuid.uuid4())
        creation_date = datetime.datetime.now(datetime.timezone.utc)

        if not user_doc.exists():
            users_ref.set({
                'clickup_token': None,
                'github_token': None,
                'github_admin': None,
                'github_repo': None,
                'name': name, 
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
        return res,200


    if session_id:
        doc_ref = db.collection('sessions').document(session_id)
        doc = doc_ref.get()
        if doc.exists():
            session_data = doc.to_dict()

            user_id = session_data.get('user_id')
            user_ref = db.collection(COLLECTION_NAME).document(user_id)
            user_doc = user_ref.get()

            if user_doc.exists:
                user_data = user_doc.to_dict()
                session_data.update(user_data)
                return jsonify({
                "AUTH_CODE": auth_code,
                "USER_NAME":user_data.get("name"),
                "GITHUB_STATUS": 1 if user_data.get("github_token") != None else 0, 
                "CLICKUP_STATUS": 1 if user_data.get("github_token") != None else 0, 
                "GITLAB_STATUS":1 if user_data.get("gitlab")!= None else 0, 
                "JIRA_STATUS": 1 if user_data.get("jira") != None else 0
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
            return 200
        else:
            abort(401)
    else:
        abort(401)


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
        return jsonify({"request_state": 401}), 401

    user_ref = db.collection(COLLECTION_NAME).document(user_id)
    user_doc = user_ref.get()


    if not user_doc.exists():
        return jsonify({"request_state": 401}), 401

    updated_fields = {
        "clickup_token":None,
        "github_token":None,
        "github_admin":None,
        "github_repo":None
    }
    no_regex = []
    no_connection = []

    user_data = user_doc.to_dict()
    token_source = data.get("token_source")
    token = data.get("token")

    github_token_valid = True
    if token_source == "Github":
        github_token = token
        if re.match(valRegEx, github_token):
            if validate_github_token(github_token):
                updated_fields['github_token'] = github_token
            else:
                no_connection.append(1)
                github_token_valid = False
        else:
            no_regex.append(1)
            github_token_valid = False

    github_admin = data.get('github_admin')
    github_admin_valid = True
    if github_admin:
        if re.match(valRegEx, github_admin):
            if github_token_valid and validate_github_admin(github_admin, token):
                updated_fields['github_admin'] = github_admin
            else:
                no_connection.append(2)
                github_admin_valid = False
        else:
            no_regex.append(2)
            github_admin_valid = False

    github_repo = data.get('github_repo')
    if github_repo:
        if re.match(valRegEx, github_repo):
            if github_token_valid and github_admin_valid and validate_github_repo(github_admin, github_repo, token):
                updated_fields['github_repo'] = github_repo
            else:
                no_connection.append(3)
        else:
            no_regex.append(3)

    if token_source == "Clickup":
        clickup_token = token
        if re.match(valRegEx, clickup_token):
            if validate_clickup_token(clickup_token):
                updated_fields['clickup_token'] = clickup_token
            else:
                no_connection.append(1)
        else:
            no_regex.append(1)

    if updated_fields:
        if github_token_valid:
            user_ref.update(updated_fields)

    if no_regex or no_connection:
        return jsonify({
                        "FAILED_REGEX": no_regex,
                        "FAILED_CONNECTION": no_connection,
                        "GITHUB_STATUS": 1 if user_data.get("github_token") != None else 0, 
                        "CLICKUP_STATUS": 1 if user_data.get("github_token") != None else 0, 
                        "GITLAB_STATUS":1 if user_data.get("gitlab")!= None else 0, 
                        "JIRA_STATUS": 1 if user_data.get("jira") != None else 0}), 403
    else:
        return jsonify({
                        "FAILED_REGEX": no_regex,
                        "FAILED_CONNECTION": no_connection,
                        "GITHUB_STATUS": 1 if user_data.get("github_token") != None else 0, 
                        "CLICKUP_STATUS": 1 if user_data.get("github_token") != None else 0, 
                        "GITLAB_STATUS":1 if user_data.get("gitlab")!= None else 0, 
                        "JIRA_STATUS": 1 if user_data.get("jira") != None else 0}), 200


if __name__ == '__main__':
    app.run(debug=True)
