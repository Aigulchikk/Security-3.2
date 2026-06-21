# Secure File Manager MVP

MVP защищенного веб-сервиса на FastAPI для безопасного хранения файлов.

## Стек технологий

- **FastAPI**
- **Pydantic v2**
- **Cryptography (Fernet)**
- **Docker & Docker Compose**
- **Bandit** (SAST)
- **Тесты:** `python test_security.py`

## Тесты
python test_security.py

## Инструкция по развертыванию

- Клонирование репозитория: bash git clone 
- Создание виртуального окружения venv python3 -m venv venv
- Активация venv source venv/bin/activate
- Установка всех зависимостей pip install --upgrade pip, pip install -r requirements.txt
- Настройка env cp .env.example .env 
- Запуск сервера uvicorn main:app --reload --host 127.0.0.1 --port 8000

## Как перейти на сайт 
[link](http://127.0.0.1:8000/docs)