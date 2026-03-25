# -*- coding: utf-8 -*-
"""
Created on Thu Mar 19 14:32:09 2026

@author: mauri

測試用漏洞實驗環境(擴充版)
"""

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

app = FastAPI()

# ---------------------------------------------------------
# 1. 首頁：包含所有漏洞測試的入口
# ---------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index():
    return """
    <html>
        <head>
            <title>Vulnerable Lab - 擴充版</title>
            <style>
                body { font-family: sans-serif; line-height: 1.6; padding: 20px; background-color: #f0f2f5; }
                .card { background: white; padding: 15px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                h2 { color: #1a73e8; }
                code { background: #eee; padding: 2px 5px; }
            </style>
        </head>
        <body>
            <h1>弱點測試實驗室 (V2.0 擴充版)</h1>
            
            <!-- SQL 注入測試 -->
            <div class="card">
                <h2>測試 1: SQL Injection (POST)</h2>
                <p>嘗試在帳號輸入 <code>' OR '1'='1</code></p>
                <form action="/login" method="post">
                    帳號: <input type="text" name="username">
                    密碼: <input type="password" name="password">
                    <input type="submit" value="登入">
                </form>
            </div>

            <!-- XSS 測試 -->
            <div class="card">
                <h2>測試 2: 反射型 XSS (GET)</h2>
                <p>嘗試輸入 <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
                <form action="/search" method="get">
                    關鍵字: <input type="text" name="q">
                    <input type="submit" value="搜尋">
                </form>
            </div>

            <!-- 目錄遍歷測試 -->
            <div class="card">
                <h2>測試 3: 目錄遍歷 Directory Traversal (GET)</h2>
                <p>嘗試輸入 <code>../../etc/passwd</code></p>
                <form action="/view_file" method="get">
                    讀取檔案: <input type="text" name="file" placeholder="例如: profile.txt">
                    <input type="submit" value="讀取">
                </form>
            </div>

            <!-- 敏感檔案洩漏說明 -->
            <div class="card">
                <h2>測試 4: 敏感檔案洩漏</h2>
                <p>自動化工具會嘗試存取以下路徑：</p>
                <ul>
                    <li><a href="/.env">/.env</a> (環境設定檔)</li>
                    <li><a href="/.git/config">/.git/config</a> (版本控制紀錄)</li>
                </ul>
            </div>
        </body>
    </html>
    """

# ---------------------------------------------------------
# 2. 漏洞後端邏輯
# ---------------------------------------------------------

# SQLi 測試路徑
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    # 模擬資料庫報錯
    if "'" in username:
        return HTMLResponse(
            content="MySQL Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''", 
            status_code=500
        )
    return {"status": "success", "user": username}

# XSS 測試路徑
@app.get("/search")
async def search(q: str = ""):
    # 直接反射輸入內容，不進行過濾
    content = f"<html><body><h1>搜尋結果</h1><p>你搜尋的是: {q}</p></body></html>"
    return HTMLResponse(content=content)

# 目錄遍歷測試路徑
@app.get("/view_file")
async def view_file(file: str = ""):
    # 模擬讀取系統敏感檔案
    if "../../etc/passwd" in file or "/etc/passwd" in file:
        return PlainTextResponse(content="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
    
    # 模擬讀取 Windows 系統檔案
    if "win.ini" in file.lower():
        return PlainTextResponse(content="[extensions]\nbit=bitmap\n[fonts]\nArial=arial.ttf")
    
    return PlainTextResponse(content=f"正在讀取檔案: {file}\n(內容為空)")

# ---------------------------------------------------------
# 3. 敏感檔案路徑 (直接模擬檔案存在)
# ---------------------------------------------------------

@app.get("/.env")
async def get_env():
    return PlainTextResponse(content="DB_PASSWORD=super_secret_password_123\nSTRIPE_API_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc")

@app.get("/.git/config")
async def get_git_config():
    return PlainTextResponse(content="[remote \"origin\"]\n  url = https://github.com/user/secret_repo.git\n  fetch = +refs/heads/*:refs/remotes/origin/*")

@app.get("/phpinfo.php")
async def get_phpinfo():
    return HTMLResponse(content="<h1>phpinfo()</h1><p>PHP Version 7.4.3</p><p>System: Linux ubuntu 5.4.0</p>")

if __name__ == "__main__":
    import uvicorn
    # 啟動伺服器在 http://127.0.0.1:8000
    uvicorn.run(app, host="127.0.0.1", port=8000)