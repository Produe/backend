from flask import Flask, request, jsonify,make_response,redirect
from flask_cors import CORS
from datetime import datetime, timedelta
import jwt
import firebase_admin
from firebase_admin import credentials, firestore
import requests
import os
import openai

cred = credentials.Certificate("produ-5d1cb-firebase-adminsdk-8hzdo-96d06b029a.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

app = Flask(__name__)
CORS(app,
     supports_credentials=True,
     resources={r"/*": {"origins": ["https://produe.netlify.app", "http://localhost:5173"]}},
     methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"]
)
def api_request(url, headers, method="GET", data=None):
    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data)

        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": "Request failed", "details": str(e)}

from dotenv import load_dotenv
import os

load_dotenv('TOKENS.env')
TOGETHER_API_KEY = os.getenv("TOGETHER_API_KEY")
TOGETHER_API_URL = "https://api.together.xyz/v1/completions"
openai.api_key = os.getenv("OPENAI_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = os.getenv("GOOGLE_DISCOVERY_URL")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

CLICKUP_CLIENT_ID = os.getenv("CLICKUP_CLIENT_ID")
CLICKUP_CLIENT_SECRET = os.getenv("CLICKUP_CLIENT_SECRET")
CLICKUP_REDIRECT_URI = os.getenv("CLICKUP_REDIRECT_URI")

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"

CLICKUP_AUTH_URL = "https://app.clickup.com/api"
CLICKUP_TOKEN_URL = f"{CLICKUP_AUTH_URL}/v2/oauth/token"
CLICKUP_API_URL = f"{CLICKUP_AUTH_URL}/v2"

google_config = requests.get(GOOGLE_DISCOVERY_URL).json()
GOOGLE_TOKEN_URL = google_config["token_endpoint"]
GOOGLE_USERINFO_URL = google_config["userinfo_endpoint"]

# Decorator for JWT Authentication
def login_required(func):
    def wrapper(*args, **kwargs):
        token = request.cookies.get("access_token")
        if not token:
            return jsonify({"error": "Token missing"}), 401

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            google_id = payload["google_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401


        try:
            user_doc = db.collection("users").document(google_id).get()

            if not user_doc.exists:
                return jsonify({"error": "User not found"}), 401

        except Exception as e:
            return jsonify({"error": "Internal server error"}), 500

        return func(google_id, *args, **kwargs)

    wrapper.__name__ = func.__name__
    return wrapper

# /login Endpoint
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        auth_code = data.get("CODE")
        if not auth_code:
            return jsonify({"error": "Authorization code is required"}), 400

        # Exchange auth_code for tokens
        token_response = requests.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": auth_code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        ).json()

        if "error" in token_response:
            return jsonify({"error": "Failed to exchange authorization code"}), 400

        access_token = token_response.get("access_token")

        # Fetch user info from Google
        user_info_response = requests.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        ).json()

        google_id = user_info_response.get("sub")
        name = user_info_response.get("name")
        email = user_info_response.get("email")

        if not google_id or not name or not email:
            return jsonify({"error": "Failed to retrieve user information"}), 400

        # Add user to Firestore if not exists
        user_ref = db.collection("users").document(google_id)
        if not user_ref.get().exists:
            user_ref.set({
                "name": name,
                "email": email,
                "cohorts": []
            })

        token = jwt.encode(
            {"google_id": google_id, "exp": datetime.utcnow() + timedelta(days=30)},
            SECRET_KEY,
            algorithm="HS256",
        )

        # Send JWT in a secure, HTTP-only cookie
        response = make_response(jsonify({"message": "Login successful"}), 200)
        response.set_cookie("access_token", token, httponly=True, secure=True, max_age=30*24*60*60, samesite='None')

        return response

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Internal server error"}), 500
# /cohort/create Endpoint
@app.route("/cohort/create", methods=["POST"])
@login_required
def create_cohort(google_id):
    try:
        data = request.json
        name = data.get("NAME")

        if not name:
            return jsonify({"error": "Cohort name is required"}), 400

        # Create cohort
        cohort_ref = db.collection("cohorts").document()
        cohort_ref.set({
            "name": name,
            "creator": google_id,
            "teams": [],
            "github_token": None,
            "clickup_tokens": []
        })

        # Link cohort to user
        user_ref = db.collection("users").document(google_id)
        user = user_ref.get()
        if user.exists:
            user_data = user.to_dict()
            cohorts = user_data.get("cohorts", [])
            cohorts.append(cohort_ref.id)
            user_ref.update({"cohorts": cohorts})

        return retrieve_struct(google_id)

    except Exception as e:
        print(f"Cohort creation error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# /team/create Endpoint
@app.route("/team/create", methods=["POST"])
@login_required
def create_team(google_id):
    try:
        data = request.json
        cohort_id = data.get("COHORT-ID")
        name = data.get("NAME")

        if not cohort_id or not name:
            return jsonify({"error": "Cohort ID and team name are required"}), 400

        cohort_ref = db.collection("cohorts").document(cohort_id)
        cohort = cohort_ref.get()

        if not cohort.exists:
            return jsonify({"error": "Cohort not found"}), 404

        cohort_data = cohort.to_dict()
        if cohort_data["creator"] != google_id:
            return jsonify({"error": "Unauthorized to modify this cohort"}), 403

        team_id = f"team_{len(cohort_data['teams']) + 1}"
        new_team = {"id": team_id, "name": name, "contributors": []}
        cohort_data["teams"].append(new_team)

        cohort_ref.update({"teams": cohort_data["teams"]})

        return retrieve_struct(google_id)

    except Exception as e:
        print(f"Team creation error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# /general Endpoint
@app.route("/general", methods=["POST"])
@login_required
def general(google_id):
    return retrieve_struct(google_id)

def retrieve_struct(google_id):
    try:
        user_ref = db.collection("users").document(google_id)
        user = user_ref.get()

        if not user.exists:
            return jsonify({"error": "User not found"}), 404

        user_data = user.to_dict()
        cohorts = []

        for cohort_id in user_data.get("cohorts", []):
            cohort_ref = db.collection("cohorts").document(cohort_id)
            cohort = cohort_ref.get()

            if cohort.exists:
                cohort_data = cohort.to_dict()

                # Iterate over teams inside the cohort
                if "teams" in cohort_data:
                    for team in cohort_data["teams"]:
                        # Check if 'members' exists in each team
                        if "members" in team:
                            # Loop through the members and change "DISPLAYNAME" to "name"
                            for member in team["members"]:
                                if "DISPLAYNAME" in member:
                                    member["name"] = member.pop("DISPLAYNAME")  # Replace DISPLAYNAME with "name"

                # Add the cohort_id to the cohort data
                cohort_data["id"] = cohort_id
                cohorts.append(cohort_data)

        if not cohorts:
            return jsonify({"error": "No cohorts found"}), 404

        return jsonify({"cohorts": cohorts}), 200

    except Exception as e:
        print(f"General retrieval error: {e}")
        return jsonify({"error": "Internal server error"}), 500



# /auth Endpoint
@app.route("/auth", methods=["POST"])
@login_required
def auth_service(google_id):
    try:
        data = request.json
        auth_code = data.get("CODE")
        service_type = data.get("TYPE")

        if not auth_code or not service_type:
            return jsonify({"error": "Authorization code and service type are required"}), 400

        cohort_id = data.get("COHORT-ID")
        if not cohort_id:
            return jsonify({"error": "Cohort ID is required"}), 400

        cohort_ref = db.collection("cohorts").document(cohort_id)
        cohort = cohort_ref.get()

        if not cohort.exists:
            return jsonify({"error": "Cohort not found"}), 404

        cohort_data = cohort.to_dict()
        if cohort_data["creator"] != google_id:
            return jsonify({"error": "Unauthorized to modify this cohort"}), 403

        if service_type.upper() == "GITHUB":
            token_response = api_request(
                GITHUB_TOKEN_URL,
                headers={"Accept": "application/json"},
                method="POST",
                data={
                    "client_id": GITHUB_CLIENT_ID,
                    "client_secret": GITHUB_CLIENT_SECRET,
                    "code": auth_code,
                },
            )

            token = token_response.get("access_token")
            if not token:
                return jsonify({"error": "Failed to retrieve GitHub access token", "details": token_response}), 400
            cohort_ref.update({"github_token": token})
        elif service_type.upper() == "CLICKUP":
            token_response = api_request(
                CLICKUP_TOKEN_URL,
                headers={"Content-Type": "application/json"},
                method="POST",
                data={
                    "client_id": CLICKUP_CLIENT_ID,
                    "client_secret": CLICKUP_CLIENT_SECRET,
                    "code": auth_code,
                },
            )

            token = token_response.get("access_token")
            if not token:
                return jsonify({"error": "Failed to retrieve ClickUp access token", "details": token_response}), 400
            clickup_tokens = cohort_data.get("clickup_tokens", [])
            clickup_tokens.append(token)
            cohort_ref.update({"clickup_tokens": clickup_tokens})
        else:
            return jsonify({"error": "Unsupported service type"}), 400

        return jsonify({}), 200

    except Exception as e:
        print(f"Service auth error: {e}")
        return jsonify({"error": f"Internal server error: {e}"}), 500

# /is_authenticated Endpoint
@app.route("/is_authenticated", methods=["POST"])
@login_required
def is_authenticated(google_id):
    try:
        return jsonify({}), 200
    except Exception as e:
        print(f"Authentication check error: {e}")
        return jsonify({"error": "Internal server error"}), 500


# /team/settings Endpoint
@app.route("/team/settings", methods=["POST"])
def team_settings():
    google_id="100890050626620355723"
    try:
        data = request.json
        cohort_id = data.get("COHORT-ID")
        team_id = data.get("TEAM-ID")
        service = data.get("SERVICE").upper()
        creds = data.get("CREDS")

        if not cohort_id or not team_id or not service:
            return jsonify({"error": "Cohort ID, Team ID, and Service are required"}), 400

        cohort_ref = db.collection("cohorts").document(cohort_id)
        cohort = cohort_ref.get()

        if not cohort.exists:
            return jsonify({"error": "Cohort not found"}), 404

        cohort_data = cohort.to_dict()
        if cohort_data["creator"] != google_id:
            return jsonify({"error": "Unauthorized to modify this cohort"}), 403

        # Locate the team
        teams = cohort_data.get("teams", [])
        team = next((t for t in teams if t["id"] == team_id), None)
        if not team:
            return jsonify({"error": "Team not found"}), 404

        # Handle fetching settings
        if not creds:
            if service == "GITHUB":
                github_token = cohort_data.get("github_token")
                if not github_token:
                    return jsonify({"ORGS": []}), 200

                headers = {"Authorization": f"Bearer {github_token}"}

                    # Fetch the authenticated user's info (to get the GitHub username)
                user_response = requests.get("https://api.github.com/user", headers=headers)
                if user_response.status_code != 200:
                    return jsonify({"error": "Failed to fetch GitHub user information"}), 500

                user_data = user_response.json()
                github_username = user_data.get("login")  # This is the GitHub username of the user who authorized the OAuth app

                    # Fetch organizations for the user
                orgs_response = requests.get("https://api.github.com/user/orgs", headers=headers)
                if orgs_response.status_code != 200:
                    return jsonify({"error": "Failed to fetch GitHub organizations"}), 500

                orgs_data = orgs_response.json()
                orgs = []

                    # Fetch user-owned repositories (no specific organization)
                user_repos_response = requests.get("https://api.github.com/user/repos", headers=headers)
                if user_repos_response.status_code != 200:
                    return jsonify({"error": "Failed to fetch user repositories"}), 500
                user_repos = [
                    {"NAME": repo["name"]}
                    for repo in user_repos_response.json()
                    if repo["owner"]["type"] == "User"
                ]
                    # Add 'N/A' organization for user-owned repositories
                orgs.append({
                    "NAME": "N/A",
                    "USER": github_username,
                    "REPOS": user_repos
                })

                for org in orgs_data:
                    org_name = org["login"]
                    repos_response = requests.get(f"https://api.github.com/orgs/{org_name}/repos", headers=headers)

                    if repos_response.status_code != 200:
                        continue

                    repos = [{"NAME": repo["name"]} for repo in repos_response.json()]
                    orgs.append({
                        "NAME": org_name,
                        "USER": github_username,  # The GitHub username of the user who authorized access
                        "REPOS": repos
                    })

                return jsonify({"ORGS": orgs}), 200

            elif service == "CLICKUP":
                clickup_tokens = cohort_data.get("clickup_tokens", [])
                if not clickup_tokens:
                    return jsonify({"WORKSPACES": []}), 200

                workspaces = []

                for token in clickup_tokens:
                    headers = {"Authorization": token}

                    # Fetch the authenticated user's info (to get the ClickUp user info)
                    user_response = requests.get("https://api.clickup.com/api/v2/user", headers=headers)
                    if user_response.status_code != 200:
                        return jsonify({"error": "Failed to fetch ClickUp user information"}), 500

                    user_data = user_response.json()
                    clickup_user = user_data.get("user", {}).get("username")  # ClickUp username of the user who authorized the app

                    # Fetch teams (workspaces) for the ClickUp user
                    workspaces_response = requests.get("https://api.clickup.com/api/v2/team", headers=headers)
                    if workspaces_response.status_code != 200:
                        continue

                    for workspace in workspaces_response.json().get("teams", []):
                        workspaces.append({
                            "NAME": workspace["name"],
                            "USER": clickup_user,  # The ClickUp username of the user who gave you access
                        })

                return jsonify({"WORKSPACES": workspaces}), 200

        # Handle updating settings
        if service == "GITHUB":
            account = creds.get("ACCOUNT")
            org = creds.get("ORG")
            repo = creds.get("REPO")

            if not account or not repo:
                return jsonify({"error": "GitHub credentials are incomplete"}), 400

            team["github"] = {"account": account, "org": org, "repo": repo}
        elif service == "CLICKUP":
            workspace = creds.get("WORKSPACE")
            if not workspace:
                return jsonify({"error": "ClickUp credentials are incomplete"}), 400

            team["clickup"] = {"workspace": workspace}
        else:
            return jsonify({"error": "Unsupported service type"}), 400

        # Update the team in Firestore
        updated_teams = [t if t["id"] != team_id else team for t in teams]
        cohort_ref.update({"teams": updated_teams})

        return jsonify({}), 200

    except Exception as e:
        print(f"Team settings error: {e}")
        return jsonify({"error": f"Internal server error: {e}"}), 500




# /team/members Endpoint
@app.route("/team/members", methods=["POST"])
def team_members():
    google_id="100890050626620355723"
    try:
        data = request.json
        cohort_id = data.get("COHORT-ID")
        team_id = data.get("TEAM-ID")
        table = data.get("TABLE", [])

        if not cohort_id or not team_id:
            return jsonify({"error": "Cohort ID and Team ID are required"}), 400

        cohort_ref = db.collection("cohorts").document(cohort_id)
        cohort = cohort_ref.get()

        if not cohort.exists:
            return jsonify({"error": "Cohort not found"}), 404

        cohort_data = cohort.to_dict()
        if cohort_data["creator"] != google_id:
            return jsonify({"error": "Unauthorized to modify this cohort"}), 403

        # Locate the team
        teams = cohort_data.get("teams", [])
        team = next((t for t in teams if t["id"] == team_id), None)
        if not team:
            return jsonify({"error": "Team not found"}), 404

        if isinstance(table,dict) and not table:  # If table is empty, fetch usernames
            github_token = cohort_data.get("github_token")
            clickup_tokens = cohort_data.get("clickup_tokens", [])

            github_usernames = []
            clickup_usernames = []

            # Fetch GitHub contributors
            github_config = team.get("github", {})
            repo = github_config.get("repo")
            account = github_config.get("account")
            org=github_config.get("org")
            github_usernames=[]
            if github_token and org:
                    headers = {"Authorization": f"Bearer {github_token}"}
                    org_members_url = f"https://api.github.com/orgs/{org}/members"
                    members_response = requests.get(org_members_url, headers=headers)
                    
                    if members_response.status_code == 200:
                        github_usernames = [user['login'] for user in members_response.json()]

            clickup_usernames = set()
            workspace_name = team.get("clickup", {}).get("workspace")

            for token in clickup_tokens:
                headers = {"Authorization": token}
                # Fetch all workspaces
                workspaces_response = requests.get("https://api.clickup.com/api/v2/team", headers=headers)
                if workspaces_response.status_code != 200:
                    continue

                workspaces_data = workspaces_response.json().get("teams", [])
                workspace_id = next((ws["id"] for ws in workspaces_data if ws["name"] == workspace_name), None)
                if not workspace_id:
                    continue


                # Fetch all spaces in the workspace
                spaces_response = requests.get(f"https://api.clickup.com/api/v2/team/{workspace_id}/space", headers=headers)
                if spaces_response.status_code != 200:
                    continue

                spaces = spaces_response.json().get("spaces", [])
                for space in spaces:
                    space_id = space["id"]

                    # Fetch all folders in the space
                    folders_response = requests.get(f"https://api.clickup.com/api/v2/space/{space_id}/folder", headers=headers)
                    if folders_response.status_code != 200:
                        continue

                    folders = folders_response.json().get("folders", [])
                    for folder in folders:
                        folder_id = folder["id"]

                        # Fetch all lists in the folder
                        lists_response = requests.get(f"https://api.clickup.com/api/v2/folder/{folder_id}/list", headers=headers)
                        if lists_response.status_code != 200:
                            print(f"Error fetching lists for folder ID '{folder_id}':")
                            print(f"Response: {lists_response.text}")
                            continue

                        lists = lists_response.json().get("lists", [])
                        for task_list in lists:
                            list_id = task_list["id"]

                            # Fetch all tasks in the list
                            tasks_response = requests.get(f"https://api.clickup.com/api/v2/list/{list_id}/task", headers=headers)
                            if tasks_response.status_code != 200:
                                continue

                            tasks = tasks_response.json().get("tasks", [])
                            for task in tasks:
                                # Add all assignees to the set of usernames
                                for assignee in task.get("assignees", []):
                                    username = assignee.get("username")
                                    if username:
                                        clickup_usernames.add(username)



            return jsonify({
                "TABLE":team.get("members",[]),
                "USERNAMES": {
                    "CLICKUP": list(clickup_usernames),
                    "GITHUB": github_usernames
                }
            }), 200
        import uuid
        for member in table:
            if "id" not in member or not member["id"]:
                member["id"] = str(uuid.uuid4())
        team["members"] = table
        updated_teams = [t if t["id"] != team_id else team for t in teams]
        cohort_ref.update({"teams": updated_teams})

        return retrieve_struct(google_id)

    except Exception as e:
        print(f"Team members error: {e}")
        return jsonify({"error": f"Internal server error: {e}"}), 500




@app.route("/team/dashboard", methods=["POST"])
def team_dashboard():
    try:
        data = request.get_json()

        cohort_id = data.get("COHORT-ID")
        team_id = data.get("TEAM-ID")

        if not cohort_id or not team_id:
            return jsonify({"error": "COHORT-ID and TEAM-ID are required"}), 400

        cohort_ref = db.collection("cohorts").document(cohort_id)
        cohort = cohort_ref.get()
        if not cohort.exists:
            return jsonify({"error": "Cohort not found"}), 404

        cohort_data = cohort.to_dict()

        team = next((t for t in cohort_data.get("teams", []) if t["id"] == team_id), None)
        if not team:
            return jsonify({"error": "Team not found"}), 404

        # Initialize response components
        services = []
        tasks = []
        members = team.get('members', [])

        # Ensure `members` is an iterable (empty list if not present)
        if not isinstance(members, list):
            members = []
        tasks=[]
        github_commits=[]
        # Process ClickUp tasks
        clickup_tokens = cohort_data.get("clickup_tokens", [])
        if clickup_tokens:
            clickup_tasks = fetch_clickup_tasks(clickup_tokens, team)
            if clickup_tasks:
                tasks.extend(clickup_tasks)
                services.append({"NAME": "ClickUp", "STATUS": 1})
            else:
                services.append({"NAME": "ClickUp", "STATUS": 0})
        else:
            services.append({"NAME": "ClickUp", "STATUS": 0})

        # Process GitHub commits
        github_token = cohort_data.get("github_token")
        if github_token:
            github_commits = fetch_github_commits(github_token, team)
            if github_commits:
                services.append({"NAME": "GitHub", "STATUS": 1})
            else:
                services.append({"NAME": "GitHub", "STATUS": 0})
        else:
            services.append({"NAME": "GitHub", "STATUS": 0})

        # Construct the response
        response = {
            "SERVICES": services,
            "TASKS": filter_tasks_by_contributors(tasks, members),
            "MEMBERS": merge_user_data(github_commits, members),
        }
        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


def filter_tasks_by_contributors(projects_list, users_list):
    # Ensure `projects_list` and `users_list` are iterable (empty lists if not present)
    if not isinstance(projects_list, list):
        projects_list = []
    if not isinstance(users_list, list):
        users_list = []
    # Create a mapping from ClickUp usernames to user details (display name and ID)
    user_mapping = {
        user['CLICKUP']: {"DISPLAYNAME": user['DISPLAYNAME'], "ID": user['id']}
        for user in users_list
    }
    # Initialize a list to hold the filtered projects
    filtered_projects = []

    # Loop through the projects list
    for project in projects_list:
        # Get the list of contributors for this project
        contributors = set(project.get('CONTRIBUTERS', []))

        # Check if any contributor matches a ClickUp username
        if not contributors.isdisjoint(user_mapping.keys()):
            # Replace ClickUp usernames with display names and IDs
            new_contributors = []
            for contributor in project.get("CONTRIBUTERS", []):
                if contributor in user_mapping:
                    new_contributors.append({
                        "DISPLAYNAME": user_mapping[contributor]["DISPLAYNAME"],
                        "ID": user_mapping[contributor]["ID"]
                    })

            # Create a new project dictionary with updated contributors
            updated_project = project.copy()
            updated_project["CONTRIBUTERS"] = new_contributors
            filtered_projects.append(updated_project)

    return filtered_projects

def merge_user_data(github_data, user_mapping):
    """
    Merges GitHub user data with a user mapping to create a list of display names, IDs, and total commits.

    :param github_data: List of dictionaries, each containing "NAME" (GitHub username) and "COMMITS" (number of commits).
    :param user_mapping: List of dictionaries, each containing "CLICKUP", "GITHUB", "DISPLAYNAME", and "ID".
    :return: A list of dictionaries in the format [{"NAME": displayname, "ID": user_id, "COMMITS": total_commits}].
    """
    # Ensure `github_data` and `user_mapping` are iterable (empty lists if not present)
    if not isinstance(github_data, list):
        github_data = []
    if not isinstance(user_mapping, list):
        user_mapping = []

    # Create a mapping from GitHub usernames to display names and IDs
    github_to_user_details = {
        user.get("GITHUB"): {
            "DISPLAYNAME": user.get("DISPLAYNAME"),
            "ID": user.get("id","")  # Include the ID from user_mapping
        }
        for user in user_mapping
    }

    # Build the result list
    result = []
    for github_user in github_data:
        github_username = github_user.get("NAME")
        total_commits = github_user.get("COMMITS", 0)

        # Check if the GitHub username exists in the mapping
        if github_username in github_to_user_details:
            user_details = github_to_user_details[github_username]
            result.append({
                "NAME": user_details["DISPLAYNAME"],
                "ID": user_details["ID"],  # Include the ID in the result
                "COMMITS": total_commits,
            })

    return result

def fetch_clickup_tasks(tokens, team):
    """
    Fetch tasks from ClickUp using multiple tokens.
    Maps workspace name to workspace ID before fetching tasks.
    """
    tasks = []
    clickup_data = team.get("clickup", {})
    workspace_name = clickup_data.get("workspace") if clickup_data else None

    if not workspace_name:
        return []  # Return empty list if no workspace name is provided

    for token in tokens:
        try:
            # Fetch the list of workspaces to find the matching ID
            url = "https://api.clickup.com/api/v2/team"
            headers = {"Authorization": token}
            workspaces_response = requests.get(url, headers=headers)

            if workspaces_response.status_code != 200:
                continue  # If this token fails, try the next one

            workspaces_data = workspaces_response.json().get("teams", [])
            workspace_id = None

            # Map the workspace name to the corresponding ID
            for workspace in workspaces_data:
                if workspace.get("name") == workspace_name:
                    workspace_id = workspace.get("id")
                    break

            if not workspace_id:
                continue  # If no matching workspace ID is found, try the next token

            # Fetch tasks from the resolved workspace ID
            task_url = f"https://api.clickup.com/api/v2/team/{workspace_id}/task"
            task_response = requests.get(task_url, headers=headers)

            if task_response.status_code != 200:
                continue  # If task fetching fails, try the next token

            task_data = task_response.json().get("tasks", [])
            for task in task_data:
                tasks.append({
                    "NAME": task.get("name"),
                    "CONTRIBUTERS": [assignee.get("username") for assignee in task.get("assignees", [])],
                    "STATUS": task.get("status", {}).get("status"),
                    "DUE": task.get("due_date"),
                    "INITIATED": task.get("date_created"),
                    "ID":task.get("id")
                })

            # If tasks are successfully fetched, stop iterating over tokens
            break

        except Exception as e:
            continue  # If an error occurs with a token, try the next one

    return tasks if tasks else []  # Return empty list if no tasks found


def fetch_github_commits(token, team):
    try:
        github_data = team.get("github", {})
        repo = github_data.get("repo")
        if not repo:
            return []  # Return empty list if no repo

        headers = {"Authorization": f"Bearer {token}"}
        commits_count = {}
        member_data = []
        owner=team.get("github").get("account")
        if owner:
            url = f"https://api.github.com/repos/{owner}/{repo}/contributors"
            response1 = requests.get(url, headers=headers)
            if response1.status_code == 200:
                response=response1
            else:
                owner=team.get("github").get("org")
                if owner:
                    url = f"https://api.github.com/repos/{owner}/{repo}/contributors"
                    response2 = requests.get(url, headers=headers)
                    if response2.status_code == 200:
                        response=response2
                    else:
                        return []

        contributors = response.json()
        for contributor in contributors:
            name = contributor.get("login")
            commits = contributor.get("contributions", 0)
            commits_count[name] = commits_count.get(name, 0) + commits

        for name, commits in commits_count.items():
            member_data.append({
                "NAME": name,
                "COMMITS": commits,
            })

        return member_data
    except Exception:
        return []  # Return empty list in case of error


@app.route("/member/dashboard", methods=["POST"])
def member_dashboard():
    try:
        data = request.get_json()
        cohort_id = data.get("COHORT-ID")
        team_id = data.get("TEAM-ID")
        member_id = data.get("MEMBER-ID")

        if not cohort_id or not team_id or not member_id:
            return jsonify({"error": "COHORT-ID, TEAM-ID, and MEMBER-ID are required"}), 400

        cohort_ref = db.collection("cohorts").document(cohort_id)
        cohort=cohort_ref.get()
        if not cohort.exists:
            return jsonify({"error": "Cohort not found"}), 404
        cohort_data = cohort.to_dict()
        team = next((t for t in cohort_data.get("teams", []) if t["id"] == team_id), None)
        if not team:
            return jsonify({"error": "Team not found"}), 404

        member = next((m for m in team.get("members", []) if m["id"] == member_id), None)
        if not member:
            return jsonify({"error": "Member not found"}), 404
        # Initialize response components
        tasks = []
        skills = []

        # Fetch ClickUp tasks
        clickup_tokens = cohort_data.get("clickup_tokens")
        if clickup_tokens:
            clickup_data=team.get("clickup")
            if clickup_data:
                tasks = fetch_member_tasks(clickup_tokens, clickup_data.get("workspace",""), member)

        # Calculate skills from GitHub commits
        github_token = cohort_data.get("github_token")
        if github_token:
            skills = calculate_member_skills(github_token, team, member)

        # Construct the response
        response = {
            "TASKS": tasks,
            "SKILLS": skills,
        }
        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



from datetime import datetime, timezone

def fetch_member_tasks(tokens, workspace_name, member):
    """
    Fetches tasks assigned to a member in a ClickUp workspace.

    Args:
        tokens (list): List of ClickUp API tokens.
        workspace_name (str): Name of the ClickUp workspace.
        member (dict): Member dictionary containing their 'id'.

    Returns:
        list: List of tasks assigned to the member with expected and taken times in days.
    """
    try:
        # Find the correct workspace ID and token
        workspace_id = None
        valid_token = None

        for token in tokens:
            url = "https://api.clickup.com/api/v2/team"
            headers = {"Authorization": token}
            response = requests.get(url, headers=headers)

            if response.status_code != 200:
                continue  # Try the next token if this one fails

            teams = response.json().get("teams", [])
            for team in teams:
                if team["name"] == workspace_name:
                    workspace_id = team["id"]
                    valid_token = token
                    break
            if workspace_id:
                break  # Stop searching once the workspace is found

        if not workspace_id or not valid_token:
            # If no matching workspace or valid token is found
            return []

        # Fetch tasks from the workspace
        task_url = f"https://api.clickup.com/api/v2/team/{workspace_id}/task"
        headers = {"Authorization": valid_token}
        response = requests.get(task_url, headers=headers)

        if response.status_code != 200:
            return []

        task_data = response.json().get("tasks", [])
        member_tasks = []

        for task in task_data:
            assignees = [assignee["username"] for assignee in task.get("assignees", [])]
            if member["CLICKUP"] in assignees:
                due_date = task.get("due_date")
                date_created = task.get("date_created")
                date_closed = task.get("date_closed")

                # Skip the task if it is closed (i.e., it has a date_closed)
                if date_closed:
                    continue

                # Convert timestamps to datetime objects with timezone awareness (UTC)
                due_date_dt = datetime.fromtimestamp(int(due_date) / 1000, tz=timezone.utc) if due_date else None
                date_created_dt = datetime.fromtimestamp(int(date_created) / 1000, tz=timezone.utc) if date_created else None
                # Use the current date if date_closed is missing
                current_date = datetime.now(tz=timezone.utc)

                # Calculate expected time in days (inclusive of both start and due dates)
                if due_date_dt and date_created_dt:
                    expected_days = (due_date_dt - date_created_dt).days + 1  # +1 to include both start and due date
                else:
                    expected_days = None

                # Calculate taken time in days (inclusive of both start and closure dates, use current date for open tasks)
                if date_created_dt:
                    taken_days = (current_date - date_created_dt).days + 1  # +1 to include both start and current date
                else:
                    taken_days = None

                # Append task details with expected and taken times
                member_tasks.append({
                    "NAME": task["name"],
                    "EXPECTED": expected_days,
                    "TAKEN": taken_days,
                    "ID":task.get("id")
                })

        return member_tasks

    except Exception as e:
        print(f"Error fetching member tasks: {e}")
        return []


def calculate_member_skills(token, team, member):
    try:
        github_data = team.get("github")
        if not github_data:
            return {}

        repo = github_data.get("repo")
        if not repo:
            return {}

        headers = {"Authorization": f"Bearer {token}"}
        sub_skills = {
            "code cohesion": [],
            "data structures": [],
            "coupling": [],
            "dependencies": [],
        }

        # Determine the GitHub owner (account or org)
        owner = github_data.get("account") or github_data.get("org")
        if not owner:
            return {}

        # List of potential owners to try
        potential_owners = [github_data.get("account"), github_data.get("org")]

        # Try each owner until one succeeds
        response = None
        for owner in potential_owners:
            if not owner:
                continue  # Skip if owner is None

            # Construct the URL and make the request
            url = f"https://api.github.com/repos/{owner}/{repo}/commits?author={member['GITHUB']}"
            response = requests.get(url, headers=headers)

            # Check if the response is successful
            if response.status_code == 200:
                break  # Exit the loop if we get a valid response

        # If no valid response, return empty
        if not response or response.status_code != 200:
            print(f"Failed to fetch commits. Last attempted owner: {owner}, Status code: {response.status_code if response else 'No Response'}")
            return {}


        commits = response.json()
        if not commits:
            return {}

        # Process commits to evaluate skills
        for commit in commits:
            commit_message = commit.get("commit", {}).get("message", "")
            commit_code = fetch_commit_code(commit["url"], headers)
            if commit_code:
                quality_scores = rate_commit_quality(commit_message, commit_code)
                for skill, score in quality_scores.items():
                    sub_skills[skill].append(score)

        # Calculate average scores for each skill
        skills = {
            skill: sum(scores) / len(scores) if scores else 0
            for skill, scores in sub_skills.items()
        }

        return {"SUB-SKILLS": skills}
    except Exception as e:
        print(f"Error calculating member skills: {e}")
        return {}


def fetch_commit_code(commit_url, headers):
    try:
        response = requests.get(commit_url, headers=headers)
        if response.status_code != 200:
            return None
        return response.json().get("files", [])
    except Exception:
        return None


import re

def rate_commit_quality(commit_message, commit_code):
    """Rates commit quality based on multiple metrics using Together.ai."""

    # Adjusted prompt to focus on numeric scores
    prompt = f"""
    Evaluate the following Git commit message and associated code based on these metrics:
    1. Code cohesion (0-100): Logical grouping, minimal repetition, clear purpose.
    2. Data structures (0-100): Appropriate and efficient use of data structures.
    3. Coupling (0-100): Level of interdependence; lower coupling is better.
    4. Dependencies (0-100): Appropriate and minimal use of external dependencies.

    Return the scores for each metric in the following format:
    Code Cohesion: [score]
    Data Structures: [score]
    Coupling: [score]
    Dependencies: [score]

    Commit Message: {commit_message}

    Commit Code: {commit_code}
    """

    try:
        # Make a request to Together.ai API
        headers = {
            "Authorization": f"Bearer {TOGETHER_API_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "model": "codellama/CodeLlama-7b-hf",  # Use a code-focused model
            "prompt": prompt,
            "max_tokens": 200,
            "temperature": 0
        }
        response = requests.post(TOGETHER_API_URL, headers=headers, json=data)
        response.raise_for_status()  # Raise an error for bad status codes

        # Parse the response
        review = response.json().get("choices", [{}])[0].get("text", "").strip()

        # Define expected metrics
        expected_metrics = ["code cohesion", "data structures", "coupling", "dependencies"]
        quality_scores = {metric: 0 for metric in expected_metrics}  # Initialize scores

        # Parse the response for numeric scores
        lines = review.split("\n")
        for line in lines:
            for metric in expected_metrics:
                if metric in line.lower():
                    # Use regex to find a numeric score
                    match = re.search(r'(\d+)', line)
                    if match:
                        score = int(match.group(1))
                        if 0 <= score <= 100:  # Validate score range
                            quality_scores[metric] = score
                        else:
                            print(f"Error parsing score for {metric}: Score out of range (0-100).")
                    else:
                        print(f"Error parsing score for {metric}: No valid numeric score found in '{line}'.")

        return quality_scores
    except Exception as e:
        print(f"Error during analysis: {e}")
        return {}


def fetch_commits_from_github(repo, owner, author, github_token):
    """Fetch commits from GitHub for a specific repo and author."""
    headers = {"Authorization": f"Bearer {github_token}"}
    url = f"https://api.github.com/repos/{owner}/{repo}/commits?author={author}"

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return []

    commits = []
    for commit in response.json():
        commits.append({
            "TEXT": commit["commit"]["message"],
            "DATE": commit["commit"]["committer"]["date"],
            "LINK": commit["html_url"],
            "SHA": commit["sha"],
            "REPO": repo
        })
    return commits

def analyze_commit_with_gpt(commit_message, task_title, task_description, code):
    """Use GPT to strictly analyze if a commit is directly and fully related to the task."""

    prompt = (
        f"You are an expert code reviewer with a strict mandate to ensure commits are only related to their tasks.\n"
        f"The task title is: \"{task_title}\"\n"
        f"The task description is: \"{task_description}\"\n"
        f"Evaluate the following commit and its associated code to determine if it is directly and fully fulfilling the requirements of this task.\n"
        f"Commit message: \"{commit_message}\"\n"
        f"Code: \"{code}\"\n\n"
        f"Criteria:\n"
        f"1. The commit must be explicitly tied to the task's requirements as described.\n"
        f"2. No partial or tangential relation is acceptable.\n"
        f"3. Any unrelated or ambiguous elements in the commit will result in a \"no\".\n\n"
        f"Respond with 'yes' if the commit is fully aligned and directly fulfills the task, otherwise respond with 'no'.\n"
        f"Provide a concise justification for your decision."
    )

    try:
        # Use GPT to analyze the commit
        response = openai.ChatCompletion.create(
            model="gpt-3",  # Use the most advanced model for strict evaluation
            messages=[
                {"role": "system", "content": "You are a strict and highly logical code reviewer."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=150,  # Allocate more tokens for detailed responses
            temperature=0  # Ensure deterministic and strict responses
        )

        result = response['choices'][0]['message']['content'].strip().lower()

        # Parse response
        is_related = result.startswith("yes")  # "yes" must explicitly appear at the start
        justification = result

        return is_related, justification
    except Exception as e:
        print(f"Error during analysis: {e}")
        return False, str(e)


def fetch_full_code_of_commit(repo_name, commit_sha, github_token, owner):
    """Fetch the full code of the commit (not just the changes) from GitHub."""
    headers = {"Authorization": f"Bearer {github_token}"}
    url = f"https://api.github.com/repos/{owner}/{repo_name}/commits/{commit_sha}"

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return ""

    try:
        commit_data = response.json()
        files = commit_data.get("files", [])
        full_code = ""

        # Iterate through the files and fetch the full content of each file.
        for file in files:
            filename = file.get("filename")
            raw_url = file.get("raw_url")

            if raw_url:
                file_response = requests.get(raw_url, headers=headers)
                if file_response.status_code == 200:
                    file_content = file_response.text
                    full_code += f"File: {filename}\n{file_content}\n\n"
                else:
                    full_code += f"File: {filename} (Error fetching file content)\n\n"
        return full_code.strip()  # Return full code of all files in the commit

    except Exception as e:
        return f"Error fetching full code: {str(e)}"


def fetch_task_from_clickup(clickup_tokens, task_id, members_data):
    """Fetch task details from ClickUp and replace ClickUp usernames with DISPLAYNAME and ID from members_data."""
    # Ensure `members_data` is iterable (empty list if not present)
    if not isinstance(members_data, list):
        members_data = []

    # Create a mapping from ClickUp usernames to user details (DISPLAYNAME and ID)
    clickup_to_user_details = {
        member.get("CLICKUP"): {
            "DISPLAYNAME": member.get("DISPLAYNAME"),
            "ID": member.get("id")
        }
        for member in members_data
    }

    # Iterate over all tokens and try each one
    for token in clickup_tokens:
        try:
            url = f"https://api.clickup.com/api/v2/task/{task_id}"
            headers = {
                "Authorization": token
            }
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                task_data = response.json()

                # Basic task information
                task_title = task_data.get("name", "No Title")
                task_description = task_data.get("description", "No Description")

                # Replace ClickUp usernames with DISPLAYNAME and ID from members_data
                assignees = []
                for assignee in task_data.get("assignees", []):
                    clickup_username = assignee.get("username")
                    if clickup_username in clickup_to_user_details:
                        user_details = clickup_to_user_details[clickup_username]
                        assignees.append({
                            "DISPLAYNAME": user_details["DISPLAYNAME"],
                            "ID": user_details["id"]
                        })

                # Timestamp fields
                due_date = task_data.get("due_date")
                date_created = task_data.get("date_created")

                # Convert timestamps to datetime objects with timezone awareness (UTC)
                due_date_dt = datetime.fromtimestamp(int(due_date) / 1000, tz=timezone.utc) if due_date else None
                date_created_dt = datetime.fromtimestamp(int(date_created) / 1000, tz=timezone.utc) if date_created else None

                # Use the current date if `date_closed` is missing
                current_date = datetime.now(tz=timezone.utc)

                # Calculate expected time in days (inclusive of both start and due dates)
                if due_date_dt and date_created_dt:
                    expected_days = (due_date_dt - date_created_dt).days + 1  # +1 to include both start and due date
                else:
                    expected_days = None

                # Calculate taken time in days (inclusive of both start and current dates)
                if date_created_dt:
                    taken_days = (current_date - date_created_dt).days + 1  # +1 to include both start and current date
                else:
                    taken_days = None

                # Enrich the details dictionary
                details = {
                    "NAME": task_title,
                    "STATUS": task_data.get("status", {}).get("status", "No Status"),
                    "CONTRIBUTERS": assignees,
                    "DUE": due_date_dt.isoformat() if due_date_dt else None,
                    "INITIATED": date_created_dt.isoformat() if date_created_dt else None,
                    "EXPECTED": expected_days,
                    "TAKEN": taken_days,
                }

                return task_title, task_description, assignees, details
        except Exception as e:
            continue  # Try the next token if this one fails

    return None, None, None, None  # Return None if none of the tokens work

@app.route("/task/dashboard", methods=["POST"])
def task_dashboard():
    data = request.json
    cohort_id = data.get("COHORT-ID")
    team_id = data.get("TEAM-ID")
    member_id = data.get("MEMBER-ID")
    task_id = data.get("TASK-ID")

    if not cohort_id or not team_id or not task_id:
        return jsonify({"error": "COHORT-ID, TEAM-ID, and TASK-ID are required."}), 400

    cohort_ref = db.collection("cohorts").document(cohort_id)
    cohort = cohort_ref.get()
    if not cohort.exists:
        return jsonify({"error": "Cohort not found."}), 404

    cohort_data = cohort.to_dict()
    clickup_tokens = cohort_data.get("clickup_tokens")
    github_token = cohort_data.get("github_token")

    team = next((t for t in cohort_data.get("teams", []) if t["id"] == team_id), None)
    if not team:
        return jsonify({"error": "Team not found."}), 404

    clickup_data = team.get("clickup")
    github_data = team.get("github",{})

    repo = github_data.get("repo","")
    owner = github_data.get("org","") or github_data.get("account","")
    members = team.get("members", [])

    task_title, task_description,task_assignees,details= fetch_task_from_clickup(clickup_tokens, task_id,members)
    if not task_title:
        return jsonify({"error": "Unable to fetch task details from ClickUp."}), 404




    all_commits = []

    if member_id:
        member = next((m for m in members if m["id"] == member_id), None)
        if task_assignees:
            if not member["CLICKUP"] in task_assignees:
                return jsonify({"error":"member not an assignee"}),404
        github_username = member.get("GITHUB")

        commits = fetch_commits_from_github(repo, owner, github_username, github_token)
        for commit in commits:
            code = fetch_full_code_of_commit(commit["REPO"], commit["SHA"], github_token, owner)
            is_related, justification = analyze_commit_with_gpt(commit["TEXT"], task_title, task_description, code)
            if is_related:
                commit["JUSTIFICATION"] = justification
                all_commits.append(commit)

        return jsonify({"COMMITS": all_commits,
                        "TASK":details
                        }), 200

    else:
        for member in members:
            github_username = member.get("GITHUB")
            if not github_username:
                continue
            if not member in task_assignees and task_assignees != [] and task_assignees != None:
                continue

            commits = fetch_commits_from_github(repo, owner, github_username, github_token)
            for commit in commits:
                code = fetch_full_code_of_commit(commit["REPO"], commit["SHA"], github_token, owner)
                is_related, justification = analyze_commit_with_gpt(commit["TEXT"], task_title, task_description, code)
                if is_related:
                    commit["JUSTIFICATION"] = justification
                    commit["USER"] ={
                        "NAME": member.get("DISPLAYNAME", "Unknown"),
                        "ID":member.get("id","")
                    }
                    all_commits.append(commit)

        return jsonify({"COMMITS": all_commits,
                        "TASK":details
                        }), 200


if __name__ == "__main__":
    app.run(debug=True)
