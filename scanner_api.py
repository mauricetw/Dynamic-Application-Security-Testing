# -*- coding: utf-8 -*-
"""
Created on Mon Mar 23 16:32:05 2026

@author: mauri

title:scanner_api.py ver3.0

自動化弱點掃描工具(含美化報表功能) ver2.0
自動化弱點掃描工具(多功能擴充版) ver3.0
自動化弱點掃描工具 (支援儀表板版) ver4.0
"""

import datetime
import json
import uuid
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import mysql.connector

app = FastAPI(title="自動化弱點掃描工具 API")

# --- 1. 加入 CORS 支援，讓前端網頁可以存取 API ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在正式環境應限制特定網域
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db_config = {
    "host": "localhost",
    "user": "root",
    "password": "", 
    "database": "vuln_scanner"
}

class ScannerEngine:
    def __init__(self, target_url, scan_id):
        self.target_url = target_url
        self.scan_id = scan_id
        self.session = requests.Session()
        self.db_errors = ["you have an error in your sql syntax", "mysql_fetch_array()"]
        self.payloads = {
            "sqli": ["'", "' OR '1'='1"],
            "xss": ["<script>alert('xss')</script>"],
            "traversal": ["../../etc/passwd"]
        }
        self.sensitive_paths = [".env", ".git/config", "phpinfo.php"]

    def save_to_db(self, vuln_type, action, payload, risk="High"):
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            query = "INSERT INTO vulnerabilities (scan_id, type, url, payload, risk_level) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(query, (self.scan_id, vuln_type, action, payload, risk))
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"[-] DB Error: {e}")

    def _update_scan_status(self, status):
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("UPDATE scans SET status = %s WHERE id = %s", (status, self.scan_id))
        conn.commit()
        cursor.close()
        conn.close()

    def run_full_scan(self):
        """核心掃描主邏輯"""
        try:
            self._update_scan_status("Scanning")
            
            # A. 敏感檔案探測
            for path in self.sensitive_paths:
                check_url = urljoin(self.target_url, path)
                try:
                    res = self.session.get(check_url, timeout=3)
                    if res.status_code == 200:
                        self.save_to_db("Sensitive File Exposure", check_url, "Path Discovery", "High")
                except: pass

            # B. 表單漏洞掃描
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.content, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                action = form.attrs.get("action")
                target_action_url = urljoin(self.target_url, action)
                
                # XSS
                for p in self.payloads["xss"]:
                    res = self.session.get(target_action_url, params={"q": p})
                    if p in res.text: self.save_to_db("XSS", target_action_url, p, "Medium")

                # SQLi
                for p in self.payloads["sqli"]:
                    res = self.session.post(target_action_url, data={"username": p, "password": "p"})
                    for err in self.db_errors:
                        if err in res.text.lower(): self.save_to_db("SQLi", target_action_url, p, "High")

            self._update_scan_status("Completed")
        except Exception as e:
            self._update_scan_status("Failed")
            print(f"[-] Scan Error: {e}")

# --- API 路由 ---

class ScanRequest(BaseModel):
    url: str

@app.post("/start_scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())[:8]
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scans (id, target_url, status) VALUES (%s, %s, %s)", (scan_id, request.url, "Pending"))
    conn.commit()
    cursor.close()
    conn.close()
    
    scanner = ScannerEngine(request.url, scan_id)
    background_tasks.add_task(scanner.run_full_scan)
    return {"message": "Started", "scan_id": scan_id}

@app.get("/scans")
async def list_scans():
    """獲取所有掃描任務紀錄"""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM scans ORDER BY created_at DESC")
    scans = cursor.fetchall()
    cursor.close()
    conn.close()
    return scans

@app.get("/scan_status/{scan_id}")
async def get_status(scan_id: str):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
    scan = cursor.fetchone()
    cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = %s", (scan_id,))
    findings = cursor.fetchall()
    cursor.close()
    conn.close()
    return {"scan_info": scan, "findings": findings}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)