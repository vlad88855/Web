import ssl
import uvicorn
from fastapi import FastAPI

app = FastAPI()

@app.get("/hello")
async def hello():
    return "Hello from Vlad Shynkaruk КP-33"

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