from fastapi import FastAPI, HTTPException
from src.schemas import UserCreate

app = FastAPI(title="Регистрация пользователей", version="1.0")

@app.post("/registration")
async def register_user(user: UserCreate):
    return {"msg": "Пользователь создан", "user": user.username}

@app.get("/")
async def root():
    return {"msg": "Сервис регистрации работает"}