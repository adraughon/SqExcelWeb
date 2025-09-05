from fastapi import FastAPI
from mangum import Mangum

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI on Vercel!"}

@app.get("/test")
def test():
    return {"message": "Test endpoint working!"}

@app.post("/api/seeq/test-connection")
def test_connection(request: dict):
    return {
        "success": True,
        "message": "Test connection endpoint working",
        "received_data": request
    }

# Wrap FastAPI app with Mangum for serverless deployment
handler = Mangum(app)