from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from flask import Flask, request, jsonify, abort
import firebase_admin
from firebase_admin import credentials, firestore
import requests
import uuid
import datetime
from dotenv import load_dotenv
import os
import re
import asyncio


load_dotenv("TOKENS.env")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
SLACK_APP_TOKEN = os.getenv("SLACK_APP_TOKEN")
TEAM_ENDPOINT = 'https://api.clickup.com/api/v2/team'

if not firebase_admin._apps: ## EDITED
    cred = credentials.Certificate("produ-5d1cb-firebase-adminsdk-8hzdo-f44bea1278.json") ## EDITED
    firebase_admin.initialize_app(cred) ## EDITED

db = firestore.client()

def get_user_by_team_id(team_id):
    users_ref = db.collection('users')
    query = users_ref.where('team_id', '==', team_id).get()

    if not query:
        raise ValueError(f"No user found with team ID: {team_id}")
    return query[0].to_dict()

def get_team_id_from_command(command):
    return command.get('team_id')

def fetch_clickup_token(user_data):
    clickup_token = user_data.get('clickup_token')
    if clickup_token:
        return clickup_token
    else:
        raise ValueError("ClickUp token not found for this user.")

def get_teams(clickup_token):
    headers = {
        'Authorization': clickup_token
    }
    response = requests.get(TEAM_ENDPOINT, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to retrieve teams. Status code: {response.status_code}")

def get_tasks_for_team(clickup_token, team_id):
    tasks_endpoint = f'https://api.clickup.com/api/v2/team/{team_id}/task'
    headers = {
        'Authorization': clickup_token
    }
    response = requests.get(tasks_endpoint, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to retrieve tasks for team {team_id}. Status code: {response.status_code}")

def fetch_all_tasks(user_data):
    clickup_token = fetch_clickup_token(user_data)
    all_tasks = []
    teams = get_teams(clickup_token)
    if teams:
        for team in teams['teams']:
            team_id = team['id']
            tasks = get_tasks_for_team(clickup_token, team_id)
            if tasks:
                for task in tasks['tasks']:
                    task_info = {
                        'team_id': team_id,
                        'team_name': team['name'],
                        'task_id': task['id'],
                        'task_name': task['name'],
                        'task_status': task.get('status', {}).get('name', 'Unknown'),
                        'assignees': [assignee.get('username', 'Unknown') for assignee in task.get('assignees', [])]
                    }
                    all_tasks.append(task_info)
    return all_tasks

def fetch_github_commits(user_data):
    github_token = user_data.get('github_token')
    github_repo = user_data.get('github_repo')
    github_admin = user_data.get('github_admin')

    if not github_token or not github_repo:
        raise ValueError("GitHub token or repository is not set for this user.")

    github_api_url = f'https://api.github.com/repos/{github_admin}/{github_repo}/commits'
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    response = requests.get(github_api_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch commits from GitHub. Status code: {response.status_code}")

def is_workspace_authenticated(team_id):
    """Check if the team (workspace) is authenticated in Firestore."""
    users_ref = db.collection('users')
    query = users_ref.where('team_id', '==', team_id).get()
    return len(query) > 0

app = App(token=SLACK_BOT_TOKEN)

@app.command("/clickup_tasks")
def filter_tasks_by_assignee(ack, command, say):
    ack()

    team_id = get_team_id_from_command(command)
    if not is_workspace_authenticated(team_id):
        say(f"Workspace for team {team_id} is not authenticated. Please contact your administrator.")
        return

    try:
        user_data = get_user_by_team_id(team_id) 
        tasks_list = fetch_all_tasks(user_data)
        username = command['text']
        filtered_tasks = [task for task in tasks_list if username in task['assignees']]

        if filtered_tasks:
            response_text = f"Here are the tasks assigned to *{username}*:\n"
            for task in filtered_tasks:
                response_text += (f"• *Task ID:* {task['task_id']} | "
                                  f"*Name:* {task['task_name']} | "
                                  f"*Team:* {task['team_name']} | "
                                  f"*Status:* {task['task_status']}\n")
            say(response_text)
        else:
            say(f"No tasks found for user {username}.")
    except requests.exceptions.RequestException as e:
        say(f"Error fetching data: {str(e)}")

@app.command("/github_commits")
def fetch_github_commits_command(ack, command, say):
    ack()

    team_id = get_team_id_from_command(command)
    if not is_workspace_authenticated(team_id):
        say(f"Workspace for team {team_id} is not authenticated. Please contact your administrator.")
        return

    try:
        user_data = get_user_by_team_id(team_id)  
        commits_list = fetch_github_commits(user_data)

        if commits_list:
            response_text = "Here are the latest commits:\n"
            for commit in commits_list[:5]: 
                response_text += (f"• *SHA:* {commit['sha']} | "
                                  f"*Message:* {commit['commit']['message']} | "
                                  f"*Author:* {commit['commit']['author']['name']} | "
                                  f"*Date:* {commit['commit']['author']['date']}\n")
            say(response_text)
        else:
            say(f"No commits found for user {team_id}.")
    except requests.exceptions.RequestException as e:
        say(f"Error fetching GitHub commits: {str(e)}")

if __name__ == "__main__":
    
    handler = SocketModeHandler(app, SLACK_APP_TOKEN)
    handler.start()