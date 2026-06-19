import os
import uuid
import shutil
import filetype
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException, Depends, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, Response, JSONResponse, FileResponse
import bleach
from starlette.middleware.base import BaseHTTPMiddleware
from cryptography.fernet import Fernet
from dotenv import load_dotenv


app = FastAPI(title="XSS Demo + RBAC", version="1.0")

load_dotenv()

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY is not set in .env")

cipher = Fernet(ENCRYPTION_KEY.encode())

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
    {"id": 1, "filename": "report_alice.pdf", "owner": "alice", "size": 1024, "path": "storage/report_alice.pdf", "is_encrypted": False},
    {"id": 2, "filename": "photo_bob.jpg", "owner": "bob", "size": 2048, "path": "storage/photo_bob.jpg", "is_encrypted": False},
    {"id": 3, "filename": "admin_keys.txt", "owner": "admin", "size": 512, "path": "storage/admin_keys.txt", "is_encrypted": False},
]

sessions = {}

MAX_FILE_SIZE = 2 * 1024 * 1024

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

@app.post("/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    encrypt: bool = False,
    current_user: dict = Depends(get_current_user)
):
    total_size = 0
    await file.seek(0)
    chunk = await file.read(1024 * 1024)
    while chunk:
        total_size += len(chunk)
        if total_size > MAX_FILE_SIZE:
            raise HTTPException(413, "File too large (max 2 MB)")
        chunk = await file.read(1024 * 1024)

    await file.seek(0)
    head = await file.read(2048)
    kind = filetype.guess(head)
    if kind is None:
        allowed = True
        mime = "text/plain"
    elif kind.mime in ["image/jpeg", "image/png"]:
        allowed = True
        mime = kind.mime
    else:
        allowed = False

    if not allowed:
        raise HTTPException(400, "Only JPEG, PNG and TXT files are allowed")        
    
    await file.seek(0)
    file_data = await file.read()

    if encrypt:
        encrypted_data = cipher.encrypt(file_data)
        is_encrypted = True
    else:
        encrypted_data = file_data
        is_encrypted = False

    if kind is not None:
        extension = kind.extension
    else:
        extension = "txt"

    physical_name = f"{uuid.uuid4()}.{extension}"
    physical_path = os.path.join("storage", physical_name)

    with open(physical_path, "wb") as f:
        f.write(encrypted_data)

    new_file = {
        "id": len(files_db) + 1,
        "filename": file.filename,
        "owner": current_user["username"],
        "size": total_size,
        "path": physical_path,
        "is_encrypted": is_encrypted
    }
    files_db.append(new_file)
    
    return {"msg": "File uploaded", "file_id": new_file["id"], "encrypted": is_encrypted}

@app.get("/files/{file_id}/download")
def download_file(file_id: int, current_user: dict = Depends(get_current_user)):
    file = get_file_secure(file_id, current_user)

    if not os.path.exists(file["path"]):
        raise HTTPException(404, "File not found on server")

    with open(file["path"], "rb") as f:
        file_data = f.read()

    if file["is_encrypted"]:
        try:
            file_data = cipher.decrypt(file_data)
        except Exception as e:
            raise HTTPException(500, f"Decryption failed: {str(e)}")
    
    return Response(
        content=file_data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename={file['filename']}"
        }
    )