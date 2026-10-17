from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {
        "status": "success",
        "message": "Security Alert System API is running"
    }