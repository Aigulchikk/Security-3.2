import os
from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
import bleach
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI(title="XSS Demo", version="1.0")

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'"
        return response

app.add_middleware(CSPMiddleware)

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

comments = []

@app.get("/")
async def root():
    return {"msg": "Сервис работает. Перейдите на /comments"}

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