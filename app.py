from flask import Flask, request, jsonify, abort, make_response, redirect
import requests
import os
import datetime
from dotenv import load_dotenv
from flask_cors import CORS, cross_origin

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization", "Session-ID"]}})

load_dotenv(".env")

SLACK_CLIENT_ID = os.getenv("SLACK_CLIENTID")
SLACK_CLIENT_SECRET = os.getenv("SLACK_CLIENT_SECRET")
SLACK_REDIRECT_URI = 'https://extraordinary-nasturtium-9fc3f1.netlify.app/dashboard/'


@app.route('/auth', methods=['POST'])
@cross_origin()
def auth():
    access_token = request.cookies.get("access_token")
    github_token = request.cookies.get("github_token")
    clickup_token = request.cookies.get("clickup_token")
    data = request.json
    auth_code = data.get('AUTH_CODE')

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

        if not access_token or not user_id:
            abort(500)

        res = make_response(200)
        expiration = datetime.datetime.now() + datetime.timedelta(days=7)  

        res.set_cookie("access_token", access_token, httponly=True, secure=True, samesite='Lax', expires=expiration)

        return res

    abort(401)

    if access_token:
        user_info_response = requests.get('https://slack.com/api/users.info', headers={
            'Authorization': f'Bearer {access_token}'
        })

        if user_info_response.status_code != 200:
            abort(500)

        user_info = user_info_response.json()

        if not user_info.get('ok'):
            abort(500)

        user = user_info['user']
        first_name = user.get('profile', {}).get('real_name', 'User').split()[0]

        return jsonify({
            "USER_NAME": first_name,
            "GITHUB_STATUS": 1 if github_token else 0,
            "CLICKUP_STATUS": 1 if clickup_token else 0,
        })



@app.route('/is_authenticated', methods=['POST'])
@cross_origin()
def is_authenticated():
    access_token = request.cookies.get("access_token")

    if access_token:
        response = make_response(200)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response

    abort(401)


@app.route('/update', methods=['POST'])
@cross_origin()
def update_user_data():
    data = request.get_json()
    access_token = request.cookies.get("access_token")

    if not access_token:
        abort(401)

    user_id = request.cookies.get("user_id")
    if not user_id:
        abort(401)

    token_source = data.get("SOURCE")
    authorization_code = data.get("AUTH_CODE")

    try:
        if token_source == "Github":
            access_token = get_github_access_token(authorization_code)
            res = make_response(200)
            res.set_cookie("github_token", access_token, httponly=True, secure=True, samesite='Lax')
            return res

        elif token_source == "Clickup":
            access_token = get_clickup_access_token(authorization_code)
            res = make_response(200)
            res.set_cookie("clickup_token", access_token, httponly=True, secure=True, samesite='Lax')
            return res

    except Exception as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({"error": "Invalid source"}), 400


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

@app.route('/aa')
def aa():
    return 200

if __name__ == '__main__':
    app.run()
