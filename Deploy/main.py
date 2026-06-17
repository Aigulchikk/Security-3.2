import os
from dotenv import load_dotenv

load_dotenv()

secret = os.getenv("APP_SECRET")

if secret is None:
    print("Ошибка: переменная APP_SECRET не установлена в окружении")
    exit(1)
else:
    first_chars = secret[:3]
    print(f"Система запущена. Хеш секрета: {first_chars}***")
