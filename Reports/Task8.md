## 1. Скриншот терминала с успешным запуском тестов (все тесты passed).
![alt text](./Images/8(1).jpg "tests")

## 2. Файл test_security.py
```
import requests

BASE_URL = "http://127.0.0.1:8000"

resp = requests.post(f"{BASE_URL}/login", data={"username": "alice", "password": "alice123"})
session_alice = resp.json()["session_id"]

resp = requests.post(f"{BASE_URL}/login", data={"username": "bob", "password": "bob456"})
session_bob = resp.json()["session_id"]

resp = requests.post(f"{BASE_URL}/login", data={"username": "admin", "password": "admin123"})
session_admin = resp.json()["session_id"]

def test_idor():
    print("Test 1: Bob tries to get Alice's file (id=1)...")
    resp = requests.get(f"{BASE_URL}/files/1", params={"session_id": session_bob})
    assert resp.status_code == 404, "IDOR protection failed!"
    print("✅ Passed")

def test_own_file():
    print("Test 2: Bob gets his own file (id=2)...")
    resp = requests.get(f"{BASE_URL}/files/2", params={"session_id": session_bob})
    assert resp.status_code == 200, "Can't access own file!"
    print("✅ Passed")

def test_admin_delete():
    print("Test 3: Admin deletes Alice's file (id=1)...")
    resp = requests.delete(f"{BASE_URL}/files/1", params={"session_id": session_admin})
    assert resp.status_code == 200, "Admin can't delete file!"
    print("✅ Passed")

def test_my_files():
    print("Test 4: Bob gets his files...")
    resp = requests.get(f"{BASE_URL}/files/my", params={"session_id": session_bob})
    assert resp.status_code == 200
    files = resp.json()["files"]
    assert all(f["owner"] == "bob" for f in files), "Wrong files in /files/my!"
    print("✅ Passed")

def test_admin_all_files():
    print("Test 5: Admin gets all files...")
    resp = requests.get(f"{BASE_URL}/files/all", params={"session_id": session_admin})
    assert resp.status_code == 200
    files = resp.json()["files"]
    assert len(files) >= 1, "Admin can't see all files!"
    print("✅ Passed")

if __name__ == "__main__":
    print("Running security tests...")
    test_idor()
    test_own_file()
    test_admin_delete()
    test_my_files()
    test_admin_all_files()
    print("\n All tests passed!")
```