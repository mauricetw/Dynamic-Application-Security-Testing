# -*- coding: utf-8 -*-
"""
Created on Thu Mar 19 14:32:09 2026

@author: mauri

測試用漏洞實驗環境
"""

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse

app = FastAPI()

# 模擬一個簡單的 HTML 頁面，包含兩個有漏洞的表單
@app.get("/", response_class=HTMLResponse)
async def index():
    return """
    <html>
        <head><title>Vulnerable Lab</title></head>
        <body>
            <h1>弱點測試實驗室</h1>
            
            <!-- 模擬 SQL 注入漏洞的表單 -->
            <div style="border: 1px solid black; padding: 10px; margin-bottom: 20px;">
                <h3>測試 1: 登入頁面 (SQL Injection 測試)</h3>
                <form action="/login" method="post">
                    帳號: <input type="text" name="username"><br>
                    密碼: <input type="password" name="password"><br>
                    <input type="submit" value="登入">
                </form>
            </div>

            <!-- 模擬 XSS 漏洞的表單 -->
            <div style="border: 1px solid black; padding: 10px;">
                <h3>測試 2: 搜尋功能 (XSS 測試)</h3>
                <form action="/search" method="get">
                    關鍵字: <input type="text" name="q">
                    <input type="submit" value="搜尋">
                </form>
            </div>
        </body>
    </html>
    """

# 測試 1 的後端：當收到特定字串時回傳 SQL 錯誤訊息
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    # 故意偵測單引號，並回傳資料庫錯誤訊息，讓掃描器偵測
    if "'" in username or "'" in password:
        return HTMLResponse(content="Internal Server Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", status_code=500)
    return {"message": "Login Failed"}

# 測試 2 的後端：將輸入直接反射回頁面（XSS 典型特徵）
@app.get("/search")
async def search(q: str = ""):
    # 故意不進行任何過濾，直接把使用者的輸入填回 HTML
    content = f"<h1>搜尋結果</h1><p>你搜尋的是: {q}</p>"
    return HTMLResponse(content=content)

if __name__ == "__main__":
    import uvicorn
    # 啟動伺服器在 http://127.0.0.1:8000
    uvicorn.run(app, host="127.0.0.1", port=8000)