import os
import uuid
from fastapi import FastAPI, Request, Form, HTTPException, Depends, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, JSONResponse
import bleach
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI(title="XSS Demo + RBAC", version="1.0")

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' https://fastapi.tiangolo.com; "
            "connect-src 'self' https://cdn.jsdelivr.net;"
        )
        return response

app.add_middleware(CSPMiddleware)

users_db = {
    "alice": {"username": "alice", "role": "user", "password": "alice123"},
    "bob": {"username": "bob", "role": "user", "password": "bob456"},
    "admin": {"username": "admin", "role": "admin", "password": "admin123"},
}

files_db = [
    {"id": 1, "filename": "report_alice.pdf", "owner": "alice", "size": 1024},
    {"id": 2, "filename": "photo_bob.jpg", "owner": "bob", "size": 2048},
    {"id": 3, "filename": "admin_keys.txt", "owner": "admin", "size": 512},
]

sessions = {}

def get_current_user(session_id: str = Query(...)):
    username = sessions.get(session_id)
    if not username:
        raise HTTPException(401, "Unauthorized")
    return users_db.get(username)

def get_file_secure(file_id: int, current_user: dict = Depends(get_current_user)):
    file = next((f for f in files_db if f["id"] == file_id), None)
    if not file:
        raise HTTPException(404, "File not found")
    
    is_owner = file["owner"] == current_user["username"]
    is_admin = current_user["role"] == "admin"
    
    if not (is_owner or is_admin):
        raise HTTPException(404, "File not found")
    
    return file

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = users_db.get(username)
    if not user or user["password"] != password:
        raise HTTPException(401, "Invalid credentials")
    
    session_id = str(uuid.uuid4())
    sessions[session_id] = username
    return {"session_id": session_id}

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
comments = []

@app.get("/")
async def root():
    return {"msg": "Сервис работает. Перейдите на /comments или /files"}

@app.get("/comments")
async def show_comments(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "comments": comments
    })

@app.post("/comment")
async def add_comment(comment: str = Form(...)):
    cleaned_comment = bleach.clean(
        comment,
        tags=['b', 'i', 'u', 'a', 'p', 'br', 'strong', 'em'],
        attributes={'a': ['href', 'target']},
        protocols=['http', 'https'],
        strip=True
    )
    comments.append(cleaned_comment)
    return RedirectResponse("/comments", status_code=303)

@app.get("/files/my")
def get_my_files(current_user: dict = Depends(get_current_user)):
    user_files = [f for f in files_db if f["owner"] == current_user["username"]]
    return {"files": user_files}

@app.get("/files/all")
def get_all_files(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(403, "Only admin can view all files")
    return {"files": files_db}

@app.get("/files/{file_id}")
def get_file(file: dict = Depends(get_file_secure)):
    return file

@app.delete("/files/{file_id}")
def delete_file(file_id: int, session_id: str = Query(...)):
    current_user = get_current_user(session_id)
    file = get_file_secure(file_id, current_user)
    files_db.remove(file)
    return {"msg": f"File {file['id']} deleted"}