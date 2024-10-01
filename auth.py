import firebase_admin
from firebase_admin import credentials, firestore
from flask import Flask, request, jsonify, abort
import re
import requests

valRegEx = r'^[a-zA-Z0-9_-]+$'
app = Flask(__name__)

cred = credentials.Certificate('Bu1ldbot/produ-5d1cb-firebase-adminsdk-8hzdo-f44bea1278.json')
firebase_admin.initialize_app(cred)

db = firestore.client()

COLLECTION_NAME = 'users'


def validate_github_token(github_token):
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    response = requests.get('https://api.github.com/user', headers=headers)
    return response.status_code == 200


def validate_github_admin(github_admin, github_token):
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    response = requests.get(f'https://api.github.com/users/{github_admin}', headers=headers)
    return response.status_code == 200


def validate_github_repo(github_admin, github_repo, github_token):
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    response = requests.get(f'https://api.github.com/repos/{github_admin}/{github_repo}', headers=headers)
    return response.status_code == 200


def validate_clickup_token(clickup_token):
    headers = {
        'Authorization': clickup_token
    }
    response = requests.get('https://api.clickup.com/api/v2/user', headers=headers)
    return response.status_code == 200


@app.route('/update', methods=['POST'])
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



