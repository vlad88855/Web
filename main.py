import ssl
import uvicorn
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from jose import jwt, JWTError
import json
#lab 4 additional
import asyncio
import websockets
from fastapi import WebSocket, WebSocketDisconnect
import message_pb2
app = FastAPI()

CASDOOR_URL = "https://localhost:444"
CLIENT_ID = "e05d3d2637bc42897b76"
CLIENT_SECRET = "97184187984581f9142c4ab98ff6033f1249ad43"
REDIRECT_URI = "https://localhost/callback"
JWKS_URL = f"{CASDOOR_URL}/.well-known/jwks"

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
                <h1>Login Successful!</h1>
                <p>OIDC handshake completed. Your session is now active and protected by a Secure HttpOnly cookie.</p>

                <div class="actions">
                    <a href="/user-info" class="btn btn-primary">Check My Profile (User Info)</a>
                    <a href="/" class="btn btn-outline">Return to Main Page</a>
                    <a href="/realtime" class="btn" style="background-color: #ff9800; color: white;">Real-time Crypto Monitor</a>
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
        "redirect_uri": REDIRECT_URI,
    }

    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(token_url, data=data)
        if response.status_code != 200:
            print(f"Casdoor error: {response.text}")
            raise HTTPException(status_code=400, detail="Failed to get token from Casdoor")

        token_data = response.json()
        access_token = token_data.get("access_token")

        response = RedirectResponse(url="/hello")
        response.set_cookie(key="auth_token", value=access_token, httponly=True, secure=True, samesite='lax')
        return response


@app.get("/user-info", response_class=HTMLResponse)
async def user_info(request: Request):
    token = request.cookies.get("auth_token")
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized: No token provided")

    async with httpx.AsyncClient(verify=False) as client:
        jwks_response = await client.get(JWKS_URL)
        if jwks_response.status_code != 200:
            raise HTTPException(status_code=500, detail="Could not fetch JWKS")
        jwks = jwks_response.json()

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        rsa_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = key
                break

        if not rsa_key:
            raise HTTPException(status_code=401, detail=f"Key {kid} not found.")

        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=['RS256'],
            audience=CLIENT_ID,
            options={"verify_at_hash": False}
        )

        pretty_payload = json.dumps(payload, indent=4, ensure_ascii=False)

        html_content = f"""
        <html>
            <head>
                <title>User Profile</title>
                <style>
                    body {{ font-family: 'Segoe UI', Tahoma, sans-serif; display: flex; justify-content: center; background-color: #f4f7f6; padding: 40px; margin: 0; }}
                    .container {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.1); width: 100%; max-width: 600px; }}
                    h1 {{ color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
                    pre {{ background: #282c34; color: #abb2bf; padding: 15px; border-radius: 8px; overflow-x: auto; font-family: Consolas, monospace; font-size: 14px; }}
                    .btn {{ display: inline-block; padding: 10px 20px; background-color: #6c757d; color: white; text-decoration: none; border-radius: 6px; margin-top: 15px; transition: 0.2s; }}
                    .btn:hover {{ background-color: #5a6268; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>User Profile</h1>
                    <p>Hello, <strong>{payload.get('displayName', 'User')}</strong>!</p>
                    <p><strong>Email:</strong> {payload.get('email', 'N/A')}</p>

                    <h3>Decoded JWT Token:</h3>
                    <pre>{pretty_payload}</pre>

                    <a href="/hello" class="btn">Back</a>
                </div>
            </body>
        </html>
        """
        return html_content

    except Exception as e:
        print(f"JWT Validation Error: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


# LAB 4


@app.get("/realtime", response_class=HTMLResponse)
async def realtime():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Real-time Crypto</title>
        <script src="https://cdn.jsdelivr.net/npm/protobufjs@7.2.5/dist/protobuf.min.js"></script>
    </head>
    <body>
        <h2>Live Crypto Prices</h2>
        <input type="text" id="symbolInput" placeholder="BTCUSDT">
        <button onclick="subscribe()">Subscribe</button>
        <ul id="messages"></ul>
    
        <script>
            let ws;
            let CoinUpdate;
    
            const protoStr = `
            syntax = "proto3";
            message CoinUpdate {
                string symbol = 1;
                string price = 2;
            }`;
    
            protobuf.parse.filename = "message.proto";
            const parsed = protobuf.parse(protoStr);
            const root = parsed.root;
            CoinUpdate = root.lookupType("CoinUpdate");
    
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(protocol + '//' + window.location.host + '/ws');
            ws.binaryType = "arraybuffer"; // Обов'язково для Protobuf
    
            ws.onmessage = function(event) {
                const buffer = new Uint8Array(event.data);
                const message = CoinUpdate.decode(buffer);
                
                const li = document.createElement('li');
                li.textContent = message.symbol + ": " + message.price;
                document.getElementById('messages').appendChild(li);
            };
    
            function subscribe() {
                const symbol = document.getElementById("symbolInput").value;
                ws.send(symbol); // Відправляємо інфу про види ресурсів
            }
        </script>
    </body>
    </html>"""


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[dict] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append({"ws": websocket, "subs": set()})

    def disconnect(self, websocket: WebSocket):
        self.active_connections = [c for c in self.active_connections if c["ws"] != websocket]

    def subscribe(self, websocket: WebSocket, symbol: str):
        for c in self.active_connections:
            if c["ws"] == websocket:
                c["subs"].add(symbol.upper())

    async def broadcast(self, symbol: str, price: str):
        update = message_pb2.CoinUpdate(symbol=symbol, price=price)
        serialized_data = update.SerializeToString()

        for connection in self.active_connections:
            if symbol in connection["subs"]:
                try:
                    await connection["ws"].send_bytes(serialized_data)
                except:
                    pass


manager = ConnectionManager()

subscription_queue = asyncio.Queue()

async def binance_listener():
    uri = "wss://stream.binance.com:9443/ws"
    async with websockets.connect(uri) as binance_ws:

        async def handle_subscriptions():
            while True:
                symbol = await subscription_queue.get()
                subscribe_msg = {
                    "method": "SUBSCRIBE",
                    "params": [f"{symbol.lower()}@trade"],
                    "id": 1
                }
                await binance_ws.send(json.dumps(subscribe_msg))

        asyncio.create_task(handle_subscriptions())

        while True:
            message = await binance_ws.recv()
            data = json.loads(message)
            if "result" not in data:
                symbol = data.get("s")
                price = data.get("p")
                if symbol and price:
                    await manager.broadcast(symbol, price)


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(binance_listener())

async def validate_token(token: str):
    async with httpx.AsyncClient(verify=False) as client:
        jwks_response = await client.get(JWKS_URL)
        jwks = jwks_response.json()

    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    rsa_key = next((key for key in jwks.get("keys", []) if key.get("kid") == kid), None)

    if not rsa_key:
        raise ValueError("Key not found")

    return jwt.decode(token, rsa_key, algorithms=['RS256'], audience=CLIENT_ID, options={"verify_at_hash": False})


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.cookies.get("auth_token")
    if not token:
        await websocket.close(code=1008)
        return

    try:
        await validate_token(token)
    except Exception:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    try:
        while True:
            symbol = await websocket.receive_text()
            manager.subscribe(websocket, symbol)
            await subscription_queue.put(symbol)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8080
    )
