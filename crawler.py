# -*- coding: utf-8 -*-
"""
Created on Sat Mar 14 04:40:39 2026

@author: mauri

file:crawler.py

goal:解析目標網頁，並回傳所有發現的輸入點（表單）
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class VulnerabilityScanner:
    """
    弱點掃描器類別：
    負責管理掃描目標、網路連線狀態以及核心的爬蟲邏輯。
    """
    def __init__(self, target_url):
        """
        初始化函式：
        1. 設定目標 URL。
        2. 建立 Session 物件（這能讓掃描器在多次請求間維持 Cookie，模擬真實使用者）。
        3. 定義基礎的 Payload 字典，作為後續測試 SQLi, XSS 等漏洞的攻擊字串庫。
        """
        self.target_url = target_url
        self.session = requests.Session()
        
        # 定義常見漏洞的測試字串 (Payloads)
        self.payloads = {
            "sqli": ["'", "''", "' OR '1'='1", '" OR "1"="1'], # SQL 注入測試
            "xss": ["<script>alert('xss')</script>", "<img src=x onerror=alert(1)>"], # 跨站腳本測試
            "traversal": ["../etc/passwd", "..\\windows\\win.ini"] # 目錄遍歷測試
        }

    def extract_forms(self, url):
        """
        函式作用：從指定的 URL 中抓取並提取所有的 HTML 表單元素 (<form>)。
        功能說明：使用 BeautifulSoup 解析網頁內容，這是自動化弱點測試的第一步，找出潛在的輸入點。
        """
        try:
            # 發送 GET 請求獲取網頁 HTML
            response = self.session.get(url)
            # 使用 html.parser 解析器將原始文字轉為可搜尋的 soup 物件
            soup = BeautifulSoup(response.content, "html.parser")
            # 找出頁面中所有的 <form> 標籤並回傳列表
            return soup.find_all("form")
        except Exception as e:
            # 若 URL 無法連線或解析失敗，列印錯誤訊息並回傳空列表
            print(f"[-] 抓取頁面失敗: {url}, 錯誤: {e}")
            return []

    def get_form_details(self, form):
        """
        函式作用：深入解析單一表單的詳細屬性。
        功能說明：提取表單發送的目的地 (Action)、方法 (GET/POST) 以及所有輸入欄位的名稱與類型。
        """
        details = {}
        
        # 1. 提取表單的 Action (提交的目標網址)
        action = form.attrs.get("action")
        # 2. 提取提交方法 (預設為 get)
        method = form.attrs.get("method", "get").lower()
        
        inputs = []
        # 3. 遍歷表單內所有的 input 與 textarea 標籤，找出使用者可以輸入的地方
        for input_tag in form.find_all(["input", "textarea"]):
            input_type = input_tag.attrs.get("type", "text") # 欄位類型 (如 text, password, submit)
            input_name = input_tag.attrs.get("name")         # 欄位名稱 (後續發送 Payload 時需要對應這個名稱)
            inputs.append({"type": input_type, "name": input_name})
            
        # 將解析結果打包成字典回傳
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

# ---------------------------------------------------------
# 測試執行區塊：當直接執行此檔案時，會跑下面的測試 logic
# ---------------------------------------------------------
if __name__ == "__main__":
    # 建立一個測試目標（請確保你有權限測試該網站）
    target = "http://example.com" 
    
    # 執行個體化掃描器
    scanner = VulnerabilityScanner(target)
    
    # 執行爬蟲：抓取表單
    forms = scanner.extract_forms(target)
    
    print(f"[*] 在 {target} 發現了 {len(forms)} 個表單。")
    
    # 逐一顯示表單內容，方便開發者確認解析是否正確
    for i, form in enumerate(forms):
        form_info = scanner.get_form_details(form)
        print(f"[+] 表單 {i+1} 詳細資訊: {form_info}")