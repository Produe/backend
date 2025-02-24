from flask import Flask, request, jsonify, make_response, redirect
from flask_cors import CORS
from datetime import datetime, timedelta,timezone
import jwt
import firebase_admin
from firebase_admin import credentials, firestore
import requests
import os
import json

from openai import AzureOpenAI

from firebase_config import db, retrieve_struct
from github_functions import fetch_github_commits_from_branches,fetch_formatted_commit_code,fetch_member_commits_from_github,fetch_full_code_of_commit
from clickup_functions import fetch_clickup_members,fetch_clickup_tasks,fetch_member_tasks,fetch_task_from_clickup
from other_helper_functions import calculate_member_skills,filter_tasks_by_contributors,merge_user_data
from llm_calls import analyze_commit_with_gpt,analyze_subskill,rate_commit_quality
# Load environment variables
from dotenv import load_dotenv
load_dotenv('TOKENS.env')


# Initialize Flask app
app = Flask(__name__)
CORS(app,
     supports_credentials=True,
     resources={r"/*": {"origins": [
         "https://produe.netlify.app",
         "http://localhost:5173",
         "https://tryprodu.com",
         "https://www.tryprodu.com",
         "https://app.tryprodu.com",
         "https://auth.tryprodu.com"
         ]}},
     methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"]
)

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

# Constants
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"
CLICKUP_AUTH_URL = "https://app.clickup.com/api"
CLICKUP_TOKEN_URL = f"{CLICKUP_AUTH_URL}/v2/oauth/token"
CLICKUP_API_URL = f"{CLICKUP_AUTH_URL}/v2"

# Fetch Google OAuth configuration
google_config = requests.get(GOOGLE_DISCOVERY_URL).json()
GOOGLE_TOKEN_URL = google_config["token_endpoint"]
GOOGLE_USERINFO_URL = google_config["userinfo_endpoint"]




def api_request(url, headers, method="GET", data=None):
    """Generic API request function."""
    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": "Request failed", "details": str(e)}

def login_required(func):
    """Decorator for JWT authentication."""
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

# Endpoints
@app.route("/login", methods=["POST"])
def login():
    """Login endpoint."""
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
        response.set_cookie("access_token", token, httponly=True, secure=True, max_age=30*24*60*60, samesite='None',domain=".tryprodu.com")

        return response

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/cohort/create", methods=["POST"])
@login_required
def create_cohort(google_id):
    """Create a new cohort."""
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



@app.route("/team/create", methods=["POST"])
@login_required
def create_team(google_id):
    """Create a new team within a cohort."""
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







@app.route("/general", methods=["POST"])
@login_required
def general(google_id):
    """Fetch general cohort and team data."""
    return retrieve_struct(google_id)





@app.route("/auth", methods=["POST"])
@login_required
def auth_service(google_id):
    """Authenticate a service (GitHub or ClickUp) for a cohort."""
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




@app.route("/is_authenticated", methods=["POST"])
@login_required
def is_authenticated(google_id):
    """Check if the user is authenticated."""
    try:
        return jsonify({}), 200
    except Exception as e:
        print(f"Authentication check error: {e}")
        return jsonify({"error": "Internal server error"}), 500



@app.route("/team/settings", methods=["POST"])
@login_required
def team_settings(google_id):
    """Fetch or update team settings for a specific service (GitHub or ClickUp)."""
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





@app.route("/team/members", methods=["POST"])
@login_required
def team_members(google_id):
    """Fetch or update team members."""
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

        if isinstance(table, dict) and not table:  # If table is empty, fetch usernames
            github_token = cohort_data.get("github_token")
            clickup_tokens = cohort_data.get("clickup_tokens", [])

            github_usernames = set()
            clickup_usernames = set()

            # Fetch GitHub organization members
            github_config = team.get("github", {})
            repo = github_config.get("repo")
            owner = github_config.get("org") or github_config.get("account")

            if github_token and owner:
                headers = {"Authorization": f"Bearer {github_token}"}

                # Fetch organization members
                org_members_url = f"https://api.github.com/orgs/{owner}/members"
                members_response = requests.get(org_members_url, headers=headers)

                if members_response.status_code == 200:
                    github_usernames.update(user['login'] for user in members_response.json())

                # Fetch contributors from all branches
                if repo:
                    branches_url = f"https://api.github.com/repos/{owner}/{repo}/branches"
                    branches_response = requests.get(branches_url, headers=headers)

                    if branches_response.status_code == 200:
                        branches = branches_response.json()
                        for branch in branches:
                            branch_name = branch.get("name")
                            contributors_url = f"https://api.github.com/repos/{owner}/{repo}/contributors?sha={branch_name}"
                            contributors_response = requests.get(contributors_url, headers=headers)

                            if contributors_response.status_code == 200:
                                github_usernames.update(contributor['login'] for contributor in contributors_response.json())

            # Fetch ClickUp usernames
            workspace_name = team.get("clickup", {}).get("workspace")
            if workspace_name:
                clickup_usernames = set(fetch_clickup_members(clickup_tokens, workspace_name))

            return jsonify({
                "TABLE": team.get("members", []),
                "USERNAMES": {
                    "CLICKUP": list(clickup_usernames),
                    "GITHUB": list(github_usernames)
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
@login_required
def team_dashboard(google_id):
    """Fetch team dashboard data with enhanced service checks."""
    try:
        data = request.get_json()
        cohort_id = data.get("COHORT-ID")
        team_id = data.get("TEAM-ID")

        if not cohort_id or not team_id:
            return jsonify({"error": "COHORT-ID and TEAM-ID are required"}), 400

        # Fetch cohort data
        cohort_ref = db.collection("cohorts").document(cohort_id)
        cohort = cohort_ref.get()
        if not cohort.exists:
            return jsonify({"error": "Cohort not found"}), 404
        cohort_data = cohort.to_dict()

        # Find team data
        team = next((t for t in cohort_data.get("teams", []) if t["id"] == team_id), None)
        if not team:
            return jsonify({"error": "Team not found"}), 404

        # Service validation helpers
        def validate_clickup():
            """Validate ClickUp connection status using workspace name."""
            tokens = cohort_data.get("clickup_tokens", [])
            workspace_name = team.get("clickup", {}).get("workspace")

            if not tokens or not workspace_name:
                return False

            for token in tokens:
                try:
                    # First validate the token and get workspaces
                    teams_res = requests.get(
                        "https://api.clickup.com/api/v2/team",
                        headers={"Authorization": token},
                        timeout=5
                    )

                    if not teams_res.ok:
                        continue  # Invalid token, try next one

                    # Find workspace by name in the user's teams
                    workspaces = teams_res.json().get('teams', [])
                    workspace = next(
                        (ws for ws in workspaces if ws['name'] == workspace_name),
                        None
                    )

                    if not workspace:
                        continue  # Workspace not found with this token

                    # If we found the workspace, validate full access
                    workspace_id = workspace['id']
                    workspace_res = requests.get(
                        f"https://api.clickup.com/api/v2/team/{workspace_id}",
                        headers={"Authorization": token},
                        timeout=5
                    )

                    if workspace_res.ok:
                        return True

                except (requests.RequestException, KeyError):
                    continue

            return False

        def validate_github():
            """Validate GitHub connection status using organization from team data."""
            token = cohort_data.get("github_token")
            github_info = team.get("github", {})
            repo_name = github_info.get("repo")
            owner = github_info.get("org")

            if not token or not repo_name or not owner:
                return False

            try:
                # Validate token validity
                user_res = requests.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"token {token}",
                        "Accept": "application/vnd.github.v3+json"
                    },
                    timeout=5
                )

                # Validate repository access
                repo_res = requests.get(
                    f"https://api.github.com/repos/{owner}/{repo_name}",
                    headers={
                        "Authorization": f"token {token}",
                        "Accept": "application/vnd.github.v3+json"
                    },
                    timeout=5
                )

                # Check both token validity and repo access
                return user_res.ok and repo_res.ok

            except requests.RequestException:
                return False


        # Build service status list
        services = [
            {"NAME": "ClickUp", "STATUS": 1 if validate_clickup() else 0},
            {"NAME": "GitHub", "STATUS": 1 if validate_github() else 0}
        ]

        # Fetch data only for connected services
        tasks = []
        github_commits = []
        members = team.get('members', []) or []

        # Get ClickUp tasks if service is connected
        if any(s["NAME"] == "ClickUp" and s["STATUS"] == 1 for s in services):
            clickup_tokens = cohort_data.get("clickup_tokens", [])
            if clickup_tokens:
                tasks = fetch_clickup_tasks(clickup_tokens, team)

        # Get GitHub commits if service is connected
        if any(s["NAME"] == "GitHub" and s["STATUS"] == 1 for s in services):
            github_token = cohort_data.get("github_token")
            if github_token:
                github_commits = fetch_github_commits_from_branches(github_token, team)

        return jsonify({
            "SERVICES": services,
            "TASKS": filter_tasks_by_contributors(tasks, members),
            "MEMBERS": merge_user_data(github_commits, members)
        }), 200

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500



@app.route("/member/dashboard", methods=["POST"])
@login_required
def member_dashboard(google_id):
    """Fetch member dashboard data."""
    try:
        data = request.get_json()
        cohort_id = data.get("COHORT-ID")
        team_id = data.get("TEAM-ID")
        member_id = data.get("MEMBER-ID")

        if not cohort_id or not team_id or not member_id:
            return jsonify({"error": "COHORT-ID, TEAM-ID, and MEMBER-ID are required"}), 400

        cohort_ref = db.collection("cohorts").document(cohort_id)
        cohort = cohort_ref.get()
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
            clickup_data = team.get("clickup")
            if clickup_data:
                tasks = fetch_member_tasks(clickup_tokens, clickup_data.get("workspace", ""), member)

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





@app.route("/task/dashboard", methods=["POST"])
@login_required
def task_dashboard(google_id):
    """Fetch task dashboard data."""
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
    github_data = team.get("github", {})

    repo = github_data.get("repo", "")
    owner = github_data.get("org", "") or github_data.get("account", "")
    members = team.get("members", [])

    # Fetch task details from ClickUp
    task_title, task_description, task_assignees, details = fetch_task_from_clickup(clickup_tokens, task_id, members)

    print("hello, checking out clickup:")

    print (task_title)
    print (task_description)
    print (task_assignees)
    print (details)

    if not task_title:
        return jsonify({"error": "Unable to fetch task details from ClickUp."}), 404

    # Prepare the task details
    task_details = {
        "CONTRIBUTERS": [{"DISPLAYNAME": member.get("DISPLAYNAME", ""), "ID": member.get("id", "")} for member in members if member["CLICKUP"] in task_assignees],
        "DUE": details.get("DUE"),
        "INITIATED": details.get("INITIATED"),
        "NAME": task_title,
        "STATUS": details.get("STATUS", "Unknown"),
        "EXPECTED": details.get("EXPECTED"),
        "TAKEN": details.get("TAKEN")
    }

    # Prepare the commits details
    all_commits = []

    if member_id:
        # Fetch commits for a specific member
        member = next((m for m in members if m["id"] == member_id), None)
        if task_assignees:
            print(task_assignees)
            a=[]
            for assingee in task_assignees:
                a.append(assingee.get("username",""))
            if not member["CLICKUP"] in a:
                return jsonify({"error": "member not an assignee"}), 404
        github_username = member.get("GITHUB")

        commits = fetch_member_commits_from_github(repo, owner, github_username, github_token)
        for commit in commits:
            code = fetch_full_code_of_commit(commit["repo"], commit["sha"], github_token, owner)
            is_related, justification = analyze_commit_with_gpt(commit["commit"]["message"], task_title, task_description, code)
            if is_related:
                all_commits.append({
                    "TEXT": commit["commit"]["message"],
                    "DATE": commit["commit"]["author"]["date"],
                    "LINK": commit["html_url"],
                    "USER": member.get("DISPLAYNAME", "Unknown")
                })

    else:
        # Fetch commits for all members
        for member in members:
            github_username = member.get("GITHUB")
            if not github_username:
                continue
            if task_assignees:
                print(task_assignees)
                a=[]
                for assingee in task_assignees:
                    a.append(assingee.get("username",""))
                if not member["CLICKUP"] in a:
                    return jsonify({"error": "member not an assignee"}), 404
            commits = fetch_member_commits_from_github(repo, owner, github_username, github_token)
            for commit in commits:
                code = fetch_full_code_of_commit(commit["repo"], commit["sha"], github_token, owner)
                is_related, justification = analyze_commit_with_gpt(commit["commit"]["message"], task_title, task_description, code)
                if is_related:
                    all_commits.append({
                        "TEXT": commit["commit"]["message"],
                        "DATE": commit["commit"]["author"]["date"],
                        "LINK": commit["html_url"],
                        "USER": member.get("DISPLAYNAME", "Unknown")
                    })

    return jsonify({
        "TASK": task_details,
        "COMMITS": all_commits
    }), 200


@app.route("/subskills/chart", methods=["POST", "OPTIONS"])
def subskills_chart():
    """Endpoint to fetch subskill data for a member."""
    if request.method == "OPTIONS":
        # Handle preflight request
        return jsonify({"message": "CORS preflight successful"}), 200

    def handle_post_request():
        try:
            data = request.json
            cohort_id = data.get("COHORT-ID")
            team_id = data.get("TEAM-ID")
            member_id = data.get("MEMBER-ID")
            subskill = data.get("SUB-SKILL")

            if not cohort_id or not team_id or not member_id or not subskill:
                return jsonify({"error": "Missing required fields"}), 400

            # Fetch cohort and team data
            cohort_ref = db.collection("cohorts").document(cohort_id)
            cohort = cohort_ref.get()
            if not cohort.exists:
                return jsonify({"error": "Cohort not found"}), 404

            cohort_data = cohort.to_dict()
            team = next((t for t in cohort_data.get("teams", []) if t["id"] == team_id), None)
            if not team:
                return jsonify({"error": "Team not found"}), 404

            member = next((m for m in team.get("members", []) if m["id"] == member_id), None)
            if not member:
                return jsonify({"error": "Member not found"}), 404

            github_token = cohort_data.get("github_token")
            github_data = team.get("github", {})
            repo = github_data.get("repo")
            owner = github_data.get("org") or github_data.get("account")
            github_username = member.get("GITHUB")

            if not github_token or not repo or not owner or not github_username:
                return jsonify({"error": "GitHub data not found"}), 404

            commits = fetch_member_commits_from_github(repo, owner, github_username,github_token)
            if not commits:
                return jsonify({"error": "No commits found"}), 404

            # Process commits for the specified subskill
            result = []

            for commit in commits:

                commit_url = commit.get("url")
                # Convert headers to a hashable type (tuple of tuples)
                headers = {"Authorization": f"Bearer {github_token}"}
                commit_code = fetch_formatted_commit_code(commit_url, headers)
                if not commit_code:
                    continue

                # Analyze commit quality using Claude API (cached)
                quality_scores = rate_commit_quality(commit.get("sha",""),commit.get("commit", {}).get("message"), commit_code)
                if subskill.lower() in quality_scores:
                    # Fetch detailed analysis for the subskill (cached)
                    analysis = analyze_subskill(commit.get("sha",""),commit.get("commit", {}).get("message"), commit_code, subskill)
                    if analysis:
                        result.append({
                            "VALUE": str(quality_scores[subskill.lower()]),
                            "COMMENT": analysis.get("comment", "No comment"),
                            "DATE": commit.get("commit", {}).get("author", {}).get("date"),
                            "LINK": commit.get("html_url"),
                            "LOCATION": analysis.get("location", "Unknown"),
                            "SNIPPET": analysis.get("snippet", ""),
                            "BEGIN": analysis.get("begin", "1"),
                            "HIGHLIGHT": analysis.get("highlight", ["1", "5"])
                        })

            if not result:
                return jsonify({"error": "No data found for subskill"}), 404

            return jsonify({
                "SUBSKILL": subskill,
                "DATA": result
            }), 200

        except Exception as e:
            print(f"Subskills chart error: {e}")
            return jsonify({"error": "Internal server error"}), 500

    return handle_post_request()


####
if __name__ == "__main__":
    app.run()
