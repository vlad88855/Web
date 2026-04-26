import ssl
import uvicorn
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from jose import jwt

app = FastAPI()

CASDOOR_URL = "https://localhost:444"  # URL Casdoor (HTTP для внутрішніх запитів)
CLIENT_ID = "e05d3d2637bc42897b76"
CLIENT_SECRET = ""
REDIRECT_URI = "https://localhost/callback"
ORG_NAME = "ordinary-users"
APP_NAME = "app-lab3"


@app.get("/", response_class=HTMLResponse)
async def index():
    return """
    <html>
        <head>
            <title>Lab 3 - Home</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f4f7f6; margin: 0; }
                .container { background: white; padding: 50px; border-radius: 15px; box-shadow: 0 15px 35px rgba(0,0,0,0.1); text-align: center; width: 400px; }
                h1 { color: #333; margin-bottom: 30px; font-size: 24px; }
                .btn-group { display: flex; flex-direction: column; gap: 15px; }
                .btn { padding: 15px 25px; border-radius: 8px; text-decoration: none; font-weight: bold; transition: 0.3s; display: block; }
                .btn-login { background-color: #4CAF50; color: white; }
                .btn-login:hover { background-color: #45a049; }
                .btn-info { background-color: #2196F3; color: white; }
                .btn-info:hover { background-color: #1e88e5; }
                .footer { margin-top: 40px; font-size: 0.8rem; color: #888; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>IAM Laboratory System</h1>
                <p style="color: #666; margin-bottom: 30px;">OIDC Authorization Code Flow Implementation</p>

                <div class="btn-group">
                    <a href="/login" class="btn btn-login">Login with Casdoor</a>
                    <a href="/user-info" class="btn btn-info">Check User Info (Protected)</a>
                </div>

                <div class="footer">
                    Status: Development Mode | TLS 1.2
                </div>
            </div>
        </body>
    </html>
    """


@app.get("/hello", response_class=HTMLResponse)
async def hello():
    return """
    <html>
        <head>
            <title>Login Successful</title>
            <style>
                body { font-family: 'Segoe UI', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #eef2f7; margin: 0; }
                .container { background: white; padding: 3rem; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.1); text-align: center; max-width: 450px; }
                h1 { color: #28a745; margin-bottom: 1rem; }
                p { color: #555; line-height: 1.6; }
                .actions { margin-top: 2rem; display: flex; flex-direction: column; gap: 1rem; }
                .btn { padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600; transition: all 0.2s; }
                .btn-primary { background-color: #17a2b8; color: white; }
                .btn-primary:hover { background-color: #138496; transform: translateY(-2px); }
                .btn-outline { border: 1px solid #ccc; color: #777; font-size: 0.9rem; }
                .btn-outline:hover { background: #f8f9fa; }
            </style>
        </head>
        <body>
            <div class="container">
                <div style="font-size: 50px;">🎉</div>
                <h1>Login Successful!</h1>
                <p>OIDC handshake completed. Your session is now active and protected by a Secure HttpOnly cookie.</p>

                <div class="actions">
                    <a href="/user-info" class="btn btn-primary">Check My Profile (User Info)</a>
                    <a href="/" class="btn btn-outline">Return to Main Page</a>
                </div>
            </div>
        </body>
    </html>
    """
@app.get("/login")
async def login():
    login_url = (
        f"{CASDOOR_URL}/login/oauth/authorize"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=openid%20profile%20email"
        f"&state=vlad_shynkaruk"
    )
    return RedirectResponse(url=login_url)


@app.get("/callback")
async def callback(code: str):
    token_url = f"{CASDOOR_URL}/api/login/oauth/access_token"

    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
    }

    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(token_url, data=data)
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to get token from Casdoor")

        token_data = response.json()
        access_token = token_data.get("access_token")

        response = RedirectResponse(url="/hello")
        response.set_cookie(key="auth_token", value=access_token, httponly=True, secure=True)
        return response


@app.get("/user-info")
async def user_info(request: Request):
    token = request.cookies.get("auth_token")

    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized: No token provided")

    userinfo_url = f"{CASDOOR_URL}/api/userinfo?accessToken={token}"

    async with httpx.AsyncClient(verify=False) as client:
        response = await client.get(userinfo_url)
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail="Unauthorized: Invalid token")

        return response.json()

@app.get("/hello")
async def hello():
    return "Hello from Vlad Shynkaruk КP-33. Login successful!"

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=443,
        ssl_certfile="localhost+1.pem",
        ssl_keyfile="localhost+1-key.pem",
        ssl_version=ssl.PROTOCOL_TLSv1_2,
        ssl_ciphers="AES128-SHA:AES256-SHA"
    )
