import requests


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
