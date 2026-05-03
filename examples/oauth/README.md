# examples/oauth

A minimal authoritah server demonstrating GitHub OAuth login.

## Setup

### 1. Create a GitHub OAuth App

1. Go to **GitHub → Settings → Developer Settings → OAuth Apps → New OAuth App**
2. Fill in the fields:
    - **Application name**: anything you like
    - **Homepage URL**: `http://localhost:8080`
    - **Authorization callback URL**: `http://localhost:8080/auth/oauth/github/callback`
3. Click **Register application**
4. Copy the **Client ID**
5. Click **Generate a new client secret** and copy it

### 2. Run the server

```bash
GITHUB_CLIENT_ID=your_client_id \
GITHUB_CLIENT_SECRET=your_client_secret \
go run ./examples/oauth
```

## Try it

### Sign in with GitHub

Open your browser and navigate to:
http://localhost:8080/auth/oauth/github

You'll be redirected to GitHub to authorize the app. After approving, GitHub sends you back, and you'll get a JSON response with your session token and user info.

### Call a protected route

```bash
curl -s http://localhost:8080/me \
  -H "Authorization: Bearer <token>" | jq .
```

## Reset

```bash
rm authoritah-oauth.db
```