# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.

title:crawler_v2.py

goal:SQLi/XSS 的注入檢測
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class VulnerabilityScanner:
    """
    弱點掃描器類別：
    負責管理掃描目標、爬取輸入點，並執行漏洞檢測邏輯。
    """
    def __init__(self, target_url):
        """
        初始化：設定目標 URL、Session 以及定義漏洞測試字串 (Payloads)。
        """
        self.target_url = target_url
        self.session = requests.Session()
        
        # 定義常見漏洞的測試字串 (Payloads)
        self.payloads = {
            "sqli": ["'", "''", "' OR '1'='1", '" OR "1"="1'],
            "xss": ["<script>alert('xss')</script>", "<img src=x onerror=alert(1)>"],
            "traversal": ["../etc/passwd", "..\\windows\\win.ini"]
        }
        
        # 常見的資料庫錯誤訊息關鍵字，用於判斷 SQL 注入是否存在
        self.db_errors = [
            "you have an error in your sql syntax",
            "unclosed quotation mark after the character string",
            "mysql_fetch_array()",
            "oracle error",
            "postgreSQL query failed"
        ]

    def extract_forms(self, url):
        """
        函式作用：從 URL 提取所有 HTML 表單。
        """
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            print(f"[-] 抓取失敗: {e}")
            return []

    def get_form_details(self, form):
        """
        函式作用：解析表單結構（Action, Method, Inputs）。
        """
        details = {"action": form.attrs.get("action"),
                   "method": form.attrs.get("method", "get").lower(),
                   "inputs": []}
        for input_tag in form.find_all(["input", "textarea"]):
            details["inputs"].append({"type": input_tag.attrs.get("type", "text"),
                                      "name": input_tag.attrs.get("name")})
        return details

    def submit_form(self, form_details, url, value):
        """
        函式作用：自動填入測試值並發送表單。
        功能說明：將所有的輸入欄位都填入相同的測試 Payload，模擬攻擊行為。
        """
        target_url = urljoin(url, form_details["action"])
        data = {}
        for input_field in form_details["inputs"]:
            if input_field["type"] in ["text", "search", "textarea"]:
                data[input_field["name"]] = value # 在欄位中填入 Payload
            else:
                data[input_field["name"]] = "test" # 其他欄位填入預設值

        if form_details["method"] == "post":
            return self.session.post(target_url, data=data)
        return self.session.get(target_url, params=data)

    def scan_xss(self, form_details, url):
        """
        函式作用：執行 XSS 漏洞檢測。
        功能說明：發送 XSS Payload，並檢查回傳的 HTML 是否包含未被過濾的腳本標籤。
        """
        for payload in self.payloads["xss"]:
            res = self.submit_form(form_details, url, payload)
            if payload in res.text:
                print(f"[!!!] 發現 XSS 漏洞於: {url}")
                print(f"[*] 弱點表單 Action: {form_details['action']}")
                print(f"[*] 使用 Payload: {payload}")
                return True
        return False

    def scan_sqli(self, form_details, url):
        """
        函式作用：執行 SQL 注入漏洞檢測。
        功能說明：發送 SQLi Payload，並檢查回傳頁面是否出現資料庫報錯資訊。
        """
        for payload in self.payloads["sqli"]:
            res = self.submit_form(form_details, url, payload)
            for error in self.db_errors:
                if error in res.text.lower():
                    print(f"[!!!] 發現 SQL 注入漏洞於: {url}")
                    print(f"[*] 報錯訊息: {error}")
                    return True
        return False

    def run_scanner(self):
        """
        函式作用：啟動完整掃描流程。
        功能說明：主控制迴圈，負責協調爬蟲與檢測邏輯。
        """
        print(f"[*] 開始掃描目標: {self.target_url}")
        forms = self.extract_forms(self.target_url)
        
        for form in forms:
            form_details = self.get_form_details(form)
            # 針對每個表單執行檢測
            self.scan_xss(form_details, self.target_url)
            self.scan_sqli(form_details, self.target_url)

if __name__ == "__main__":
    # 使用者輸入測試目標
    target = "http://127.0.0.1:8000" 
    scanner = VulnerabilityScanner(target)
    scanner.run_scanner()