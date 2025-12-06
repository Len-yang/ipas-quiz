// ==========================================
// 2025 資安工程師模擬題庫 - 第一批次 (Batch 1)
// 包含：防護實務 30 題 + 規劃實務 30 題
// ==========================================

const protectionQuestions = [
    // --- 網路與通訊安全 ---
    {
        "id": "B1-Prot-01",
        "question": "關於網路位址轉換 (NAT) 的敘述，下列何者正確？",
        "options": [
            "(A) 主要是為了增加網路傳輸速度",
            "(B) 可以緩解 IPv4 位址不足的問題，並隱藏內部網路結構",
            "(C) 可以完全取代防火牆的功能",
            "(D) 必須使用 IPv6 才能運作"
        ],
        "answer": "B",
        "note": "NAT 允許私有 IP 轉換為公有 IP 上網，解決了 IPv4 耗盡問題並提供基本的隱蔽性。"
    },
    {
        "id": "B1-Prot-02",
        "question": "在 OSI 模型中，SSL/TLS 加密協定主要運作於哪一層？",
        "options": [
            "(A) 網路層 (Network Layer)",
            "(B) 資料連結層 (Data Link Layer)",
            "(C) 傳輸層 (Transport Layer) 與應用層之間",
            "(D) 實體層 (Physical Layer)"
        ],
        "answer": "C",
        "note": "SSL/TLS 運作於傳輸層 (TCP) 之上，應用層 (HTTP) 之下，常被視為表達層或傳輸層的安全擴充。"
    },
    {
        "id": "B1-Prot-03",
        "question": "下列哪一種攻擊手法是利用 TCP 三向交握 (Three-way Handshake) 的漏洞，發送大量 SYN 封包耗盡伺服器資源？",
        "options": [
            "(A) SQL Injection",
            "(B) SYN Flood",
            "(C) Phishing",
            "(D) Ransomware"
        ],
        "answer": "B",
        "note": "SYN Flood 是典型的 DoS 攻擊，攻擊者發送 SYN 但不回應 ACK，導致伺服器等待連線直至逾時。"
    },
    {
        "id": "B1-Prot-04",
        "question": "關於 DMZ (非軍事區) 的配置原則，下列何者正確？",
        "options": [
            "(A) 應將資料庫伺服器直接放置於 DMZ",
            "(B) DMZ 內的設備應該可以任意存取內部網路 (LAN)",
            "(C) 用於放置對外服務的伺服器 (如 Web, Mail)，並限制其對內網的存取",
            "(D) DMZ 不需要防火牆保護"
        ],
        "answer": "C",
        "note": "DMZ 用於隔離對外服務，若 DMZ 被駭，攻擊者仍無法直接存取高安全性的內網。"
    },
    {
        "id": "B1-Prot-05",
        "question": "關於 VPN 通道協定，下列何者安全性較低，已不建議單獨使用？",
        "options": [
            "(A) PPTP",
            "(B) L2TP/IPsec",
            "(C) OpenVPN",
            "(D) SSTP"
        ],
        "answer": "A",
        "note": "PPTP 加密演算法較弱 (MS-CHAP v2)，易被破解，現多建議使用 L2TP/IPsec 或 SSL VPN。"
    },
    {
        "id": "B1-Prot-06",
        "question": "在無線網路安全中，WPA3 相較於 WPA2 最大的改進為何？",
        "options": [
            "(A) 支援更高的傳輸速度",
            "(B) 使用 SAE (Simultaneous Authentication of Equals) 取代四向交握，防範離線字典攻擊",
            "(C) 移除加密功能以提升效能",
            "(D) 僅支援 5GHz 頻段"
        ],
        "answer": "B",
        "note": "WPA3 引入 SAE 協議 (Dragonfly Key Exchange)，有效防範針對 WPA2 的 KRACK 攻擊與字典攻擊。"
    },
    // --- Web 應用程式安全 (OWASP) ---
    {
        "id": "B1-Prot-07",
        "question": "若網頁應用程式未對使用者輸入進行過濾，攻擊者輸入 `<script>alert(1)</script>` 並成功執行，這是屬於哪種攻擊？",
        "options": [
            "(A) SQL Injection",
            "(B) XSS (Cross-Site Scripting)",
            "(C) CSRF (Cross-Site Request Forgery)",
            "(D) SSRF (Server-Side Request Forgery)"
        ],
        "answer": "B",
        "note": "這是典型的反射型或儲存型 XSS 攻擊，攻擊目標是瀏覽器端的腳本執行。"
    },
    {
        "id": "B1-Prot-08",
        "question": "關於 CSRF (跨站請求偽造) 的防禦措施，下列何者最有效？",
        "options": [
            "(A) 使用 HTTPS 加密",
            "(B) 在表單中加入隨機產生的 Anti-CSRF Token 並驗證",
            "(C) 過濾使用者輸入的特殊字元",
            "(D) 隱藏網頁原始碼"
        ],
        "answer": "B",
        "note": "CSRF 利用使用者的身分驗證狀態，Anti-CSRF Token 確保請求是從合法頁面發出。"
    },
    {
        "id": "B1-Prot-09",
        "question": "防禦 SQL Injection 的最佳實作 (Best Practice) 為何？",
        "options": [
            "(A) 使用 WAF (Web Application Firewall)",
            "(B) 在前端使用 JavaScript 檢查",
            "(C) 使用參數化查詢 (Parameterized Queries) 或預處理 (Prepared Statements)",
            "(D) 定期重啟資料庫"
        ],
        "answer": "C",
        "note": "參數化查詢能確保資料庫將輸入視為數據而非指令，從根本解決 SQL 注入。"
    },
    {
        "id": "B1-Prot-10",
        "question": "攻擊者透過修改 URL 中的參數 (如 `id=100` 改為 `id=101`) 成功查看到他人的訂單，這屬於 OWASP Top 10 中的哪一類風險？",
        "options": [
            "(A) Injection",
            "(B) Broken Access Control (權限控制失效 - IDOR)",
            "(C) Security Misconfiguration",
            "(D) Cryptographic Failures"
        ],
        "answer": "B",
        "note": "這是 IDOR (Insecure Direct Object References)，屬於存取控制失效的一種。"
    },
    // --- 系統與端點安全 ---
    {
        "id": "B1-Prot-11",
        "question": "下列何者不是「勒索軟體 (Ransomware)」感染後的常見特徵？",
        "options": [
            "(A) 檔案副檔名被更改",
            "(B) 桌面出現勒索訊息文字檔",
            "(C) 系統 CPU 使用率突然飆高 (進行加密運算)",
            "(D) 硬體設備物理燒毀"
        ],
        "answer": "D",
        "note": "勒索軟體主要針對軟體資料進行加密，不會導致硬體物理損壞。"
    },
    {
        "id": "B1-Prot-12",
        "question": "Windows 系統中，哪一個指令可以用來檢查目前的網路連線狀態與開放的 Port？",
        "options": [
            "(A) ipconfig",
            "(B) netstat",
            "(C) ping",
            "(D) tracert"
        ],
        "answer": "B",
        "note": "netstat -an 可以列出所有作用中的 TCP/UDP 連線與聆聽的埠號。"
    },
    {
        "id": "B1-Prot-13",
        "question": "關於 EDR (Endpoint Detection and Response) 與傳統防毒軟體的差異，何者正確？",
        "options": [
            "(A) EDR 只能依賴特徵碼 (Signature) 偵測",
            "(B) 防毒軟體通常具備完整的行為分析與鑑識能力",
            "(C) EDR 強調對端點行為的持續監控、分析與主動回應 (如隔離主機)",
            "(D) 兩者功能完全相同"
        ],
        "answer": "C",
        "note": "EDR 重點在於「行為分析」與「回應」，能偵測無檔案攻擊等進階威脅。"
    },
    {
        "id": "B1-Prot-14",
        "question": "在 Linux 系統中，權限設定 `chmod 755 filename` 代表的意義為何？",
        "options": [
            "(A) 擁有者可讀寫執行，群組與其他人可讀執行",
            "(B) 所有人皆可讀寫執行",
            "(C) 只有擁有者可讀寫",
            "(D) 擁有者可讀寫，其他人無權限"
        ],
        "answer": "A",
        "note": "7(rwx) = 4+2+1 (Owner), 5(r-x) = 4+0+1 (Group), 5(r-x) = 4+0+1 (Others)。"
    },
    {
        "id": "B1-Prot-15",
        "question": "APT (進階持續性滲透攻擊) 的生命週期中，攻擊者在進入內部網路後，試圖獲取更高權限的階段稱為？",
        "options": [
            "(A) Reconnaissance (偵察)",
            "(B) Privilege Escalation (權限提升)",
            "(C) Exfiltration (資料外洩)",
            "(D) Impact (衝擊)"
        ],
        "answer": "B",
        "note": "攻擊者通常先以低權限帳號入侵，再透過漏洞提升至管理員權限 (Privilege Escalation)。"
    },
    // --- 加密與身分認證 ---
    {
        "id": "B1-Prot-16",
        "question": "下列哪一種演算法屬於「雜湊函數 (Hash Function)」，且具有不可逆性？",
        "options": [
            "(A) AES",
            "(B) RSA",
            "(C) SHA-256",
            "(D) DES"
        ],
        "answer": "C",
        "note": "SHA-256 是雜湊演算法，用於驗證完整性；AES/DES 是對稱加密；RSA 是非對稱加密。"
    },
    {
        "id": "B1-Prot-17",
        "question": "關於數位簽章 (Digital Signature) 的功能，下列何者錯誤？",
        "options": [
            "(A) 確保資料完整性 (Integrity)",
            "(B) 確保來源不可否認性 (Non-repudiation)",
            "(C) 確保資料機密性 (Confidentiality)",
            "(D) 驗證發送者身分"
        ],
        "answer": "C",
        "note": "數位簽章使用「私鑰簽名」，他人可用公鑰驗證，但不對內容加密，故不具機密性。"
    },
    {
        "id": "B1-Prot-18",
        "question": "在 PKI (公開金鑰基礎建設) 中，負責發放與撤銷數位憑證的機構是？",
        "options": [
            "(A) RA (Registration Authority)",
            "(B) CA (Certificate Authority)",
            "(C) VA (Validation Authority)",
            "(D) ISP (Internet Service Provider)"
        ],
        "answer": "B",
        "note": "CA (憑證授權中心) 是 PKI 的核心，負責簽發憑證。"
    },
    {
        "id": "B1-Prot-19",
        "question": "關於多因子認證 (MFA)，下列哪一種組合符合 MFA 定義？",
        "options": [
            "(A) 密碼 + PIN 碼 (兩者皆為知識)",
            "(B) 密碼 + 手機簡訊驗證碼 (知識 + 擁有)",
            "(C) 指紋 + 臉部辨識 (兩者皆為生物特徵)",
            "(D) 晶片卡 + 手機 (兩者皆為擁有)"
        ],
        "answer": "B",
        "note": "MFA 需包含三要素 (知識、擁有、生物特徵) 中的至少兩種不同類型。"
    },
    {
        "id": "B1-Prot-20",
        "question": "如果要對稱式加密演算法達到足夠的安全性，目前建議的金鑰長度至少應為多少？",
        "options": [
            "(A) 56 bits",
            "(B) 128 bits",
            "(C) 512 bits",
            "(D) 1024 bits"
        ],
        "answer": "B",
        "note": "AES-128 是目前的標準起跳；56 bits (DES) 已不安全；512/1024 通常指 RSA (非對稱)。"
    },
    // --- 資安維運與攻防 ---
    {
        "id": "B1-Prot-21",
        "question": "在資安監控中心 (SOC) 中，用來收集、正規化並關聯分析日誌的系統稱為？",
        "options": [
            "(A) IDS",
            "(B) SIEM (Security Information and Event Management)",
            "(C) DLP",
            "(D) IAM"
        ],
        "answer": "B",
        "note": "SIEM 是 SOC 的核心平台，用於事件關聯分析。"
    },
    {
        "id": "B1-Prot-22",
        "question": "弱點掃描 (Vulnerability Scanning) 與滲透測試 (Penetration Testing) 的主要差異為何？",
        "options": [
            "(A) 弱點掃描由人工執行，滲透測試由工具自動執行",
            "(B) 弱點掃描僅發現漏洞，滲透測試會嘗試利用漏洞驗證影響程度",
            "(C) 兩者完全相同",
            "(D) 弱點掃描破壞性較高"
        ],
        "answer": "B",
        "note": "弱點掃描是廣度檢查（通常自動化）；滲透測試是深度攻擊模擬（通常人工+工具）。"
    },
    {
        "id": "B1-Prot-23",
        "question": "下列哪一個工具主要用於網路封包側錄與分析？",
        "options": [
            "(A) Nmap",
            "(B) Wireshark",
            "(C) Metasploit",
            "(D) Burp Suite"
        ],
        "answer": "B",
        "note": "Wireshark 是標準的網路協定分析儀；Nmap 掃描 Port；Metasploit 攻擊框架；Burp Suite Web 代理。"
    },
    {
        "id": "B1-Prot-24",
        "question": "社交工程攻擊中，攻擊者偽裝成高階主管要求員工緊急匯款，這屬於哪種類型？",
        "options": [
            "(A) Phishing (釣魚)",
            "(B) BEC (Business Email Compromise, 商務電子郵件詐騙)",
            "(C) Vishing (語音釣魚)",
            "(D) SQL Injection"
        ],
        "answer": "B",
        "note": "BEC 專門針對企業，透過偽冒身分詐騙資金或資料。"
    },
    {
        "id": "B1-Prot-25",
        "question": "為了防禦零日攻擊 (Zero-day Attack)，下列哪種技術最為有效？",
        "options": [
            "(A) 僅依賴特徵碼的防毒軟體",
            "(B) 沙箱 (Sandbox) 與行為分析",
            "(C) 定期更換密碼",
            "(D) 關閉螢幕保護程式"
        ],
        "answer": "B",
        "note": "零日攻擊沒有特徵碼，需依賴沙箱模擬執行或行為分析來識別異常。"
    },
    // --- 新興科技安全 ---
    {
        "id": "B1-Prot-26",
        "question": "針對容器化技術 (如 Docker) 的安全，下列敘述何者錯誤？",
        "options": [
            "(A) 應使用最小化的 Base Image",
            "(B) 容器應以 Root 權限執行以確保功能正常",
            "(C) 應限制容器的資源使用量 (CPU/Memory)",
            "(D) 應定期掃描映像檔 (Image) 中的漏洞"
        ],
        "answer": "B",
        "note": "容器應避免以 Root 執行，以降低逃逸 (Container Escape) 後的風險。"
    },
    {
        "id": "B1-Prot-27",
        "question": "在工控安全 (OT Security) 中，普渡模型 (Purdue Model) 的 Level 0 是指？",
        "options": [
            "(A) 企業網路層",
            "(B) 監控層 (SCADA)",
            "(C) 控制層 (PLC)",
            "(D) 現場設備層 (Sensor/Actuator)"
        ],
        "answer": "D",
        "note": "Level 0 是物理過程層 (感測器、致動器)；Level 1 是控制器。"
    },
    {
        "id": "B1-Prot-28",
        "question": "關於 AI 安全，攻擊者在圖片中加入人眼無法察覺的雜訊，導致 AI 模型誤判，這屬於哪種攻擊？",
        "options": [
            "(A) Model Inversion",
            "(B) Adversarial Attack (對抗式攻擊)",
            "(C) Data Poisoning",
            "(D) Prompt Injection"
        ],
        "answer": "B",
        "note": "對抗式攻擊 (Adversarial Example) 是針對 AI 模型的典型攻擊手法。"
    },
    {
        "id": "B1-Prot-29",
        "question": "下列何者是行動裝置管理 (MDM) 的主要資安功能？",
        "options": [
            "(A) 加速手機上網",
            "(B) 遠端抹除資料 (Remote Wipe) 與強制密碼策略",
            "(C) 自動回覆簡訊",
            "(D) 增加電池續航力"
        ],
        "answer": "B",
        "note": "MDM 用於管理企業行動裝置，確保遺失時可清除資料並強制合規。"
    },
    {
        "id": "B1-Prot-30",
        "question": "關於蜜罐 (Honeypot) 的用途，下列敘述何者正確？",
        "options": [
            "(A) 是生產環境的主要資料庫",
            "(B) 是一種誘捕系統，用來混淆攻擊者並收集攻擊情資",
            "(C) 用來加速網路存取",
            "(D) 是使用者的登入介面"
        ],
        "answer": "B",
        "note": "蜜罐是偽裝的系統，誘使駭客攻擊以分析其手法，並保護真實資產。"
    }
];

const planningQuestions = [
    // --- 法規與遵循 ---
    {
        "id": "B1-Plan-01",
        "question": "依據《資通安全管理法》，公務機關知悉資通安全事件後，應於多久內進行通報？",
        "options": [
            "(A) 1 小時內",
            "(B) 4 小時內",
            "(C) 24 小時內",
            "(D) 36 小時內"
        ],
        "answer": "A",
        "note": "依據《資通安全事件通報及應變辦法》，知悉事件後應於 1 小時內通報。"
    },
    {
        "id": "B1-Plan-02",
        "question": "依據《資通安全責任等級分級辦法》，A 級機關應多久辦理一次「資通安全事件通報及應變演練」？",
        "options": [
            "(A) 每半年 1 次",
            "(B) 每年 1 次",
            "(C) 每 2 年 1 次",
            "(D) 無強制要求"
        ],
        "answer": "B",
        "note": "A 級機關規定：每年辦理 1 次通報應變演練；社交工程演練則為每半年 1 次。"
    },
    {
        "id": "B1-Plan-03",
        "question": "關於個人資料保護法，公務機關保有個人資料檔案者，應指定專人辦理安全維護事項，這稱為？",
        "options": [
            "(A) 隱私保護官",
            "(B) 資安長",
            "(C) 專責人員",
            "(D) 資料保護長 (DPO)"
        ],
        "answer": "C",
        "note": "個資法要求指定「專人」辦理安全維護；GDPR 才稱為 DPO。"
    },
    {
        "id": "B1-Plan-04",
        "question": "依據《資通安全管理法》，下列何者「不屬於」關鍵基礎設施提供者 (CI)？",
        "options": [
            "(A) 台灣電力公司",
            "(B) 台灣中油",
            "(C) 一般小型電商平台",
            "(D) 醫學中心"
        ],
        "answer": "C",
        "note": "關鍵基礎設施指能源、水資源、通訊傳播、交通、銀行金融、緊急救援與醫院、高科技園區、政府機關。"
    },
    {
        "id": "B1-Plan-05",
        "question": "關於 GDPR (歐盟通用資料保護規則) 的「被遺忘權 (Right to be forgotten)」，其意義為何？",
        "options": [
            "(A) 資料主體有權要求控制者刪除其個人資料",
            "(B) 資料主體可以要求更正錯誤資料",
            "(C) 資料主體可以要求攜帶資料",
            "(D) 企業可以遺忘備份資料"
        ],
        "answer": "A",
        "note": "被遺忘權即「刪除權」，在特定條件下可要求刪除個資。"
    },
    // --- ISMS 與風險管理 ---
    {
        "id": "B1-Plan-06",
        "question": "在 ISO 27001:2022 中，下列哪一個階段包含「內部稽核」與「管理審查」？",
        "options": [
            "(A) Plan (規劃)",
            "(B) Do (執行)",
            "(C) Check (查核)",
            "(D) Act (行動)"
        ],
        "answer": "C",
        "note": "Check 階段負責監控、量測、分析、評估、稽核與審查 ISMS 績效。"
    },
    {
        "id": "B1-Plan-07",
        "question": "風險評鑑中，將「資產價值」乘以「暴露因素 (Exposure Factor)」是用來計算什麼？",
        "options": [
            "(A) 年度發生率 (ARO)",
            "(B) 單一損失預期值 (SLE)",
            "(C) 年度損失預期值 (ALE)",
            "(D) 殘餘風險"
        ],
        "answer": "B",
        "note": "SLE (Single Loss Expectancy) = Asset Value × Exposure Factor。"
    },
    {
        "id": "B1-Plan-08",
        "question": "關於風險處理策略，機關決定「購買資安保險」屬於下列何者？",
        "options": [
            "(A) 風險規避 (Avoidance)",
            "(B) 風險降低 (Reduction)",
            "(C) 風險移轉/分擔 (Transfer/Sharing)",
            "(D) 風險保留 (Retention)"
        ],
        "answer": "C",
        "note": "透過保險將財務損失風險轉嫁給保險公司，屬於風險移轉。"
    },
    {
        "id": "B1-Plan-09",
        "question": "在 ISO 27001 中，關於「適用性聲明書 (SoA)」的用途，下列何者正確？",
        "options": [
            "(A) 宣告組織不採用任何 ISO 標準",
            "(B) 條列組織所選用的控制措施及其理由，以及排除的理由",
            "(C) 僅列出法律法規要求",
            "(D) 用來申請預算"
        ],
        "answer": "B",
        "note": "SoA (Statement of Applicability) 是 ISMS 驗證的關鍵文件，說明控制措施的適用性。"
    },
    {
        "id": "B1-Plan-10",
        "question": "關於 PDCA 循環，當內部稽核發現不符合事項時，應在隨後的哪個階段進行修正？",
        "options": [
            "(A) Plan",
            "(B) Do",
            "(C) Check",
            "(D) Act"
        ],
        "answer": "D",
        "note": "Act (行動) 階段負責採取矯正措施與持續改善。"
    },
    // --- 營運持續管理 (BCP) ---
    {
        "id": "B1-Plan-11",
        "question": "在 BCP 中，若業務單位要求「系統中斷後必須在 4 小時內恢復服務」，這是指哪一個指標？",
        "options": [
            "(A) RTO (Recovery Time Objective)",
            "(B) RPO (Recovery Point Objective)",
            "(C) MTPD (Maximum Tolerable Period of Disruption)",
            "(D) WRT (Work Recovery Time)"
        ],
        "answer": "A",
        "note": "RTO (復原時間目標) 是指服務中斷到恢復運作所允許的最大時間。"
    },
    {
        "id": "B1-Plan-12",
        "question": "承上題，若要求「資料最多只能遺失 1 小時前的數據」，這是指？",
        "options": [
            "(A) RTO",
            "(B) RPO",
            "(C) MTPD",
            "(D) MTBF"
        ],
        "answer": "B",
        "note": "RPO (復原點目標) 決定了備份的頻率，即容許遺失多少資料。"
    },
    {
        "id": "B1-Plan-13",
        "question": "關於備援站點 (Recovery Site) 的類型，哪一種站點已具備所有硬體與即時資料，可立即接手運作？",
        "options": [
            "(A) Cold Site (冷站)",
            "(B) Warm Site (溫站)",
            "(C) Hot Site (熱站)",
            "(D) Mobile Site"
        ],
        "answer": "C",
        "note": "Hot Site 具備完整設備與即時資料同步，復原時間最短但成本最高。"
    },
    {
        "id": "B1-Plan-14",
        "question": "營運衝擊分析 (BIA) 的主要目的是什麼？",
        "options": [
            "(A) 找出系統的技術漏洞",
            "(B) 識別關鍵業務流程及其對組織中斷的影響",
            "(C) 計算備份磁帶的成本",
            "(D) 測試防火牆效能"
        ],
        "answer": "B",
        "note": "BIA 用於確定業務優先順序、RTO 與 RPO。"
    },
    {
        "id": "B1-Plan-15",
        "question": "依據備份 3-2-1 原則，其中的「1」代表什麼？",
        "options": [
            "(A) 1 位專責管理員",
            "(B) 1 份異地保存 (Off-site)",
            "(C) 1 年稽核一次",
            "(D) 1 小時內復原"
        ],
        "answer": "B",
        "note": "3 份複本、2 種介質、1 份異地。"
    },
    // --- 資安治理與框架 ---
    {
        "id": "B1-Plan-16",
        "question": "NIST CSF 2.0 框架中，新增的第六個核心功能是？",
        "options": [
            "(A) Identify",
            "(B) Protect",
            "(C) Govern (治理)",
            "(D) Respond"
        ],
        "answer": "C",
        "note": "NIST CSF 2.0 新增 Govern，強調資安治理、供應鏈風險管理的重要性。"
    },
    {
        "id": "B1-Plan-17",
        "question": "關於「縱深防禦 (Defense in Depth)」的概念，下列何者正確？",
        "options": [
            "(A) 依賴單一強大的防火牆",
            "(B) 透過多層次的控制措施 (如網路、端點、應用程式) 來降低風險",
            "(C) 只要做好實體安全即可",
            "(D) 是指深層網頁 (Deep Web) 的防護"
        ],
        "answer": "B",
        "note": "縱深防禦強調多層次保護，避免單點失效。"
    },
    {
        "id": "B1-Plan-18",
        "question": "下列何者屬於 ISO 27002 中的「組織控制 (Organizational Controls)」？",
        "options": [
            "(A) 威脅情資 (Threat Intelligence)",
            "(B) 惡意軟體防護",
            "(C) 佈纜安全",
            "(D) 安全程式碼開發"
        ],
        "answer": "A",
        "note": "威脅情資歸類於組織控制；惡意軟體是技術控制；佈纜是實體控制。"
    },
    {
        "id": "B1-Plan-19",
        "question": "關於「最小權限原則 (Principle of Least Privilege)」，下列敘述何者正確？",
        "options": [
            "(A) 給予使用者所有權限以便工作方便",
            "(B) 僅給予使用者完成工作所需的最小權限",
            "(C) 只有管理員需要遵循此原則",
            "(D) 適用於實體門禁，不適用於系統帳號"
        ],
        "answer": "B",
        "note": "最小權限是存取控制的核心原則，能降低帳號被駭後的災損。"
    },
    {
        "id": "B1-Plan-20",
        "question": "在供應鏈安全中，CMMC (Cybersecurity Maturity Model Certification) 是哪個國家的國防供應鏈標準？",
        "options": [
            "(A) 歐盟",
            "(B) 日本",
            "(C) 美國",
            "(D) 台灣"
        ],
        "answer": "C",
        "note": "CMMC 是美國國防部 (DoD) 針對國防工業基地 (DIB) 的資安成熟度認證。"
    },
    // --- 存取控制與稽核 ---
    {
        "id": "B1-Plan-21",
        "question": "下列哪一種存取控制模型是基於使用者的「職位或工作功能」來分配權限？",
        "options": [
            "(A) DAC (Discretionary Access Control)",
            "(B) MAC (Mandatory Access Control)",
            "(C) RBAC (Role-Based Access Control)",
            "(D) ABAC (Attribute-Based Access Control)"
        ],
        "answer": "C",
        "note": "RBAC (角色基礎存取控制) 是企業最常用的模型。"
    },
    {
        "id": "B1-Plan-22",
        "question": "關於「職務區隔 (Separation of Duties, SoD)」的目的，下列何者正確？",
        "options": [
            "(A) 加速工作流程",
            "(B) 防止單一人員擁有過大權限，降低舞弊風險",
            "(C) 節省人力成本",
            "(D) 簡化帳號管理"
        ],
        "answer": "B",
        "note": "SoD 要求關鍵任務須由多人共同完成 (如開發與部署分離)。"
    },
    {
        "id": "B1-Plan-23",
        "question": "下列何者是「雙因子認證 (2FA)」的正確範例？",
        "options": [
            "(A) 密碼 + PIN 碼 (兩者皆為知識)",
            "(B) 密碼 + 提款卡 (知識 + 擁有)",
            "(C) 指紋 + 虹膜 (兩者皆為生物特徵)",
            "(D) 兩組不同的密碼"
        ],
        "answer": "B",
        "note": "2FA 需包含 Knowledge (知), Possession (有), Inherence (是) 中的兩種。"
    },
    {
        "id": "B1-Plan-24",
        "question": "關於資安稽核，由組織內部人員進行的稽核稱為？",
        "options": [
            "(A) 第一方稽核",
            "(B) 第二方稽核",
            "(C) 第三方稽核",
            "(D) 外部稽核"
        ],
        "answer": "A",
        "note": "第一方是內部稽核；第二方是客戶稽核供應商；第三方是驗證機構 (如 BSI, SGS)。"
    },
    {
        "id": "B1-Plan-25",
        "question": "在雲端安全責任共擔模型中，SaaS 模式下，使用者主要負責？",
        "options": [
            "(A) 實體機房",
            "(B) 作業系統修補",
            "(C) 應用程式維護",
            "(D) 資料內容與存取權限管理"
        ],
        "answer": "D",
        "note": "SaaS 模式下，基礎設施與應用程式由供應商負責，使用者負責資料與權限。"
    },
    // --- 其他重要觀念 ---
    {
        "id": "B1-Plan-26",
        "question": "關於軟體物料清單 (SBOM)，下列敘述何者正確？",
        "options": [
            "(A) 是一種硬體資產清單",
            "(B) 詳列軟體組件及其版本，有助於供應鏈漏洞管理",
            "(C) 用於計算軟體授權費用",
            "(D) 是防火牆的黑名單"
        ],
        "answer": "B",
        "note": "SBOM (Software Bill of Materials) 是提升軟體供應鏈透明度的關鍵。"
    },
    {
        "id": "B1-Plan-27",
        "question": "個資法中，關於「去識別化」的正確理解是？",
        "options": [
            "(A) 只要隱藏姓名就是去識別化",
            "(B) 必須達到「無從識別特定當事人」的程度",
            "(C) 僅限內部使用就不需去識別化",
            "(D) 假名化等同於匿名化"
        ],
        "answer": "B",
        "note": "個資法要求去識別化須達到直接或間接均無法識別的程度。"
    },
    {
        "id": "B1-Plan-28",
        "question": "關於社交工程演練，下列何者是最佳實務？",
        "options": [
            "(A) 演練前事先通知所有員工郵件標題",
            "(B) 僅針對 IT 人員進行演練",
            "(C) 模擬真實釣魚郵件，並對點擊者進行機會教育",
            "(D) 演練結果應作為解雇依據"
        ],
        "answer": "C",
        "note": "演練目的在於教育訓練與提升意識，而非懲罰。"
    },
    {
        "id": "B1-Plan-29",
        "question": "下列何者屬於「實體安全」控制措施？",
        "options": [
            "(A) 防火牆設定",
            "(B) 門禁刷卡系統與監視器 (CCTV)",
            "(C) 資料加密",
            "(D) 防毒軟體"
        ],
        "answer": "B",
        "note": "實體安全關注實體環境的保護。"
    },
    {
        "id": "B1-Plan-30",
        "question": "關於資通安全長的職責，下列何者正確？",
        "options": [
            "(A) 負責修電腦與印表機",
            "(B) 綜理資通安全政策推動與資源調度",
            "(C) 僅負責撰寫程式碼",
            "(D) 不需要參與管理審查"
        ],
        "answer": "B",
        "note": "資安長 (CISO) 是高階管理職，負責策略規劃與治理。"
    }
];
// ==========================================
// 2025 資安工程師模擬題庫 - 第二批次 (Batch 2)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：OSI, 加密細節, Web 攻擊, 風險計算, 法規分級
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch2 = [
    // --- 網路與通訊安全 ---
    {
        "id": "B2-Prot-01",
        "question": "在 OSI 模型中，ARP (Address Resolution Protocol) 的主要功能為何？",
        "options": [
            "(A) 將網域名稱解析為 IP 位址",
            "(B) 將 IP 位址解析為 MAC 位址",
            "(C) 將 MAC 位址解析為 IP 位址",
            "(D) 自動分配 IP 位址"
        ],
        "answer": "B",
        "note": "ARP 運作於 L2/L3 之間，用於透過已知的 IP 查詢對應的實體 MAC 位址。"
    },
    {
        "id": "B2-Prot-02",
        "question": "下列哪一個通訊埠 (Port) 是 HTTPS 服務預設使用的？",
        "options": [
            "(A) 80",
            "(B) 22",
            "(C) 443",
            "(D) 3389"
        ],
        "answer": "C",
        "note": "80=HTTP, 22=SSH, 443=HTTPS, 3389=RDP。"
    },
    {
        "id": "B2-Prot-03",
        "question": "關於 DNSSEC (Domain Name System Security Extensions) 的功能，下列何者正確？",
        "options": [
            "(A) 加密 DNS 查詢流量，防止被監聽",
            "(B) 透過數位簽章確保 DNS 回應紀錄未被竄改",
            "(C) 隱藏 DNS 伺服器的 IP",
            "(D) 加速 DNS 解析速度"
        ],
        "answer": "B",
        "note": "DNSSEC 主要提供來源驗證與資料完整性，防止 DNS Spoofing/Cache Poisoning，不提供機密性加密 (那是 DoH/DoT)。"
    },
    {
        "id": "B2-Prot-04",
        "question": "下列哪一種 VPN 技術屬於 Layer 2 VPN，常用於延伸區域網路？",
        "options": [
            "(A) IPsec VPN",
            "(B) MPLS VPN",
            "(C) SSL VPN",
            "(D) PPTP"
        ],
        "answer": "B",
        "note": "MPLS (Multiprotocol Label Switching) 可運作於 Layer 2 或 Layer 3，常用於企業多點廣域網路連接。"
    },
    // --- 系統與應用程式安全 ---
    {
        "id": "B2-Prot-05",
        "question": "攻擊者在輸入欄位輸入 `' OR '1'='1`，試圖繞過登入驗證，這是屬於哪種攻擊？",
        "options": [
            "(A) Cross-Site Scripting (XSS)",
            "(B) SQL Injection (SQLi)",
            "(C) Command Injection",
            "(D) Buffer Overflow"
        ],
        "answer": "B",
        "note": "這是經典的 SQL Injection 萬能鑰匙語法，利用邏輯 OR 1=1 恆真來繞過驗證。"
    },
    {
        "id": "B2-Prot-06",
        "question": "關於「儲存型 XSS (Stored XSS)」的特性，下列何者正確？",
        "options": [
            "(A) 惡意腳本僅存在於惡意連結中，需誘使使用者點擊",
            "(B) 惡意腳本被永久儲存在目標伺服器（如資料庫、留言板），受害者瀏覽頁面即中招",
            "(C) 惡意腳本利用 DOM 環境進行攻擊",
            "(D) 攻擊者直接修改伺服器的原始碼"
        ],
        "answer": "B",
        "note": "Stored XSS 危害最大，因為惡意腳本存在伺服器端，所有瀏覽該頁面的使用者都會受害。"
    },
    {
        "id": "B2-Prot-07",
        "question": "在 Windows 系統中，哪一個指令可以用來查詢目前的帳號權限與群組資訊？",
        "options": [
            "(A) ipconfig",
            "(B) whoami /all",
            "(C) systeminfo",
            "(D) netstat"
        ],
        "answer": "B",
        "note": "`whoami` 顯示當前使用者，加上 `/all` 可顯示完整的 SID 與群組權限資訊。"
    },
    {
        "id": "B2-Prot-08",
        "question": "關於 Linux 系統中的 `root` 帳號，下列資安最佳實務何者正確？",
        "options": [
            "(A) 允許 root 透過 SSH 遠端直接登入",
            "(B) 平時使用一般帳號，需要時使用 `sudo` 執行特權指令",
            "(C) 將 root 密碼設定為空以方便維護",
            "(D) 將所有使用者都加入 root 群組"
        ],
        "answer": "B",
        "note": "禁止 root 遠端登入並使用 sudo 是 Linux 系統強化的基本原則。"
    },
    {
        "id": "B2-Prot-09",
        "question": "針對 Web 應用程式，設定 `HttpOnly` 屬性的 Cookie 可以防範下列何種攻擊？",
        "options": [
            "(A) SQL Injection",
            "(B) XSS 竊取 Cookie",
            "(C) CSRF",
            "(D) DDoS"
        ],
        "answer": "B",
        "note": "HttpOnly 標記可防止 JavaScript (如 `document.cookie`) 讀取該 Cookie，有效降低 XSS 竊取 Session 的風險。"
    },
    // --- 加密與認證 ---
    {
        "id": "B2-Prot-10",
        "question": "下列哪一種加密模式 (Cipher Mode) 因安全性較低（相同的明文區塊會產生相同的密文區塊），不建議使用？",
        "options": [
            "(A) ECB (Electronic Codebook)",
            "(B) CBC (Cipher Block Chaining)",
            "(C) GCM (Galois/Counter Mode)",
            "(D) CTR (Counter)"
        ],
        "answer": "A",
        "note": "ECB 模式無法隱藏明文的模式 (Pattern)，容易被統計分析破解 (如企鵝圖片加密案例)。"
    },
    {
        "id": "B2-Prot-11",
        "question": "在使用公開金鑰基礎建設 (PKI) 時，若憑證私鑰洩漏，應立即執行什麼動作？",
        "options": [
            "(A) 重新安裝作業系統",
            "(B) 通知 CA 撤銷憑證並發布 CRL (憑證撤銷清單)",
            "(C) 更改密碼",
            "(D) 關閉防火牆"
        ],
        "answer": "B",
        "note": "私鑰洩漏代表身分可被偽冒，必須立即撤銷 (Revoke) 該憑證。"
    },
    {
        "id": "B2-Prot-12",
        "question": "關於雜湊函數 (Hash) 的「碰撞 (Collision)」是指？",
        "options": [
            "(A) 兩個不同的輸入產生了相同的雜湊值",
            "(B) 無法從雜湊值還原回原始輸入",
            "(C) 輸入長度等於輸出長度",
            "(D) 加密過程發生錯誤"
        ],
        "answer": "A",
        "note": "抗碰撞性 (Collision Resistance) 是雜湊函數的重要安全指標，MD5 與 SHA-1 因碰撞風險已被淘汰。"
    },
    // --- 資安維運與新興科技 ---
    {
        "id": "B2-Prot-13",
        "question": "在資安事故鑑識中，數位證據的蒐集應遵循「Order of Volatility (揮發性順序)」，下列何者應最先蒐集？",
        "options": [
            "(A) 硬碟資料",
            "(B) 記憶體 (RAM) 與 CPU 快取",
            "(C) 備份磁帶",
            "(D) 光碟內容"
        ],
        "answer": "B",
        "note": "記憶體資料斷電即失，揮發性最高，應最先蒐集；硬碟資料相對穩定。"
    },
    {
        "id": "B2-Prot-14",
        "question": "關於「蜜罐 (Honeypot)」的部署目的，下列何者錯誤？",
        "options": [
            "(A) 誘捕攻擊者以延緩其對真實系統的攻擊",
            "(B) 收集攻擊者的 TTP (戰術、技術、程序) 情資",
            "(C) 作為主要的對外服務伺服器",
            "(D) 產生高可信度的告警 (因為正常使用者不應觸碰蜜罐)"
        ],
        "answer": "C",
        "note": "蜜罐不應承載真實業務，否則會增加被攻擊風險且影響服務。"
    },
    {
        "id": "B2-Prot-15",
        "question": "DevSecOps 強調「Shift Left (左移)」的概念，其意義為何？",
        "options": [
            "(A) 將資安預算移給開發部門",
            "(B) 在軟體開發生命週期 (SDLC) 的早期階段就導入資安測試與控制",
            "(C) 將伺服器向左移動",
            "(D) 僅在軟體上線後才進行資安檢測"
        ],
        "answer": "B",
        "note": "左移代表在需求分析、設計、編碼階段就加入資安，而非等到測試或維運階段。"
    },
    {
        "id": "B2-Prot-16",
        "question": "關於 APT 攻擊中的「C&C 伺服器 (Command and Control)」，其功能為何？",
        "options": [
            "(A) 儲存企業備份資料",
            "(B) 攻擊者用來遠端發送指令控制受駭電腦的中繼站",
            "(C) 企業內部的網域控制站",
            "(D) 負載平衡器"
        ],
        "answer": "B",
        "note": "C2 Server 是駭客控制殭屍網路或受駭主機的核心。"
    },
    {
        "id": "B2-Prot-17",
        "question": "在 OWASP Top 10 (2021) 中，A05 Security Misconfiguration (安全設定缺陷) 包含了下列哪種情況？",
        "options": [
            "(A) 使用了預設的帳號密碼",
            "(B) 錯誤的例外處理導致錯誤訊息洩漏堆疊資訊 (Stack Trace)",
            "(C) 啟用不必要的功能或服務",
            "(D) 以上皆是"
        ],
        "answer": "D",
        "note": "安全設定缺陷包含預設帳密、未修補、錯誤訊息洩漏、未關閉不必要服務等。"
    },
    {
        "id": "B2-Prot-18",
        "question": "下列哪一種工具主要用於「靜態應用程式安全測試 (SAST)」，即源碼檢測？",
        "options": [
            "(A) SonarQube / Fortify",
            "(B) OWASP ZAP",
            "(C) Nmap",
            "(D) Wireshark"
        ],
        "answer": "A",
        "note": "SonarQube, Fortify, Checkmarx 是常見的 SAST 工具；ZAP 是 DAST 工具。"
    },
    {
        "id": "B2-Prot-19",
        "question": "關於容器安全 (Container Security)，下列敘述何者正確？",
        "options": [
            "(A) 容器與虛擬機 (VM) 一樣擁有獨立的 Kernel，隔離性極佳",
            "(B) 容器共用 Host OS 的 Kernel，若 Kernel 有漏洞可能導致容器逃逸 (Container Escape)",
            "(C) 容器映像檔 (Image) 下載後絕對安全，不需掃描",
            "(D) 容器不需要限制資源使用"
        ],
        "answer": "B",
        "note": "容器是輕量級虛擬化，共用 Kernel 是其主要安全風險來源。"
    },
    {
        "id": "B2-Prot-20",
        "question": "針對 Deepfake (深度偽造) 語音詐騙的防禦，下列何種非技術性措施最為有效？",
        "options": [
            "(A) 安裝防毒軟體",
            "(B) 建立「回撥確認」或「通關密語」機制",
            "(C) 封鎖所有語音通話",
            "(D) 使用變聲器回擊"
        ],
        "answer": "B",
        "note": "面對 AI 偽造語音，建立雙方約定的驗證機制 (如回撥分機、密語) 是最有效的行政控制。"
    },
    {
        "id": "B2-Prot-21",
        "question": "在工業控制系統 (ICS) 中，負責連接實體設備 (Sensors/Actuators) 與控制網路的裝置通常是？",
        "options": [
            "(A) ERP 系統",
            "(B) PLC (Programmable Logic Controller) 或 RTU",
            "(C) Web Server",
            "(D) Mail Server"
        ],
        "answer": "B",
        "note": "PLC/RTU 位於 Purdue Model 的 Level 1，直接控制物理過程。"
    },
    {
        "id": "B2-Prot-22",
        "question": "關於「供應鏈攻擊 (Supply Chain Attack)」的敘述，下列何者正確？",
        "options": [
            "(A) 攻擊者直接攻擊目標企業的防火牆",
            "(B) 攻擊者透過入侵信任的第三方供應商 (如軟體更新主機)，間接感染目標企業",
            "(C) 只有硬體供應鏈會有風險",
            "(D) 只要簽署合約就能完全避免"
        ],
        "answer": "B",
        "note": "著名的 SolarWinds 事件即為供應鏈攻擊，利用軟體更新派送惡意程式。"
    },
    {
        "id": "B2-Prot-23",
        "question": "下列何者不是「社交工程」攻擊常見的心理誘餌？",
        "options": [
            "(A) 急迫性 (Urgency) - 帳號即將被鎖定",
            "(B) 權威性 (Authority) - 假冒執行長指令",
            "(C) 好奇心 (Curiosity) - 薪資明細附件",
            "(D) 完整性 (Integrity) - 雜湊值比對"
        ],
        "answer": "D",
        "note": "完整性是資安目標，非社交工程誘餌；前三者皆利用人性弱點。"
    },
    {
        "id": "B2-Prot-24",
        "question": "關於 FIDO (Fast Identity Online) 認證標準，下列敘述何者正確？",
        "options": [
            "(A) 仍需將密碼傳輸到伺服器進行驗證",
            "(B) 使用公開金鑰加密技術，生物特徵僅儲存在本地裝置，不傳輸至伺服器",
            "(C) 安全性比傳統密碼低",
            "(D) 必須購買特定的 USB 金鑰才能使用"
        ],
        "answer": "B",
        "note": "FIDO 的核心優勢在於生物特徵不出裝置，伺服器僅驗證簽章，隱私性高。"
    },
    {
        "id": "B2-Prot-25",
        "question": "在 Windows AD 環境中，Kerberos 協定使用哪一種機制來防止重送攻擊 (Replay Attack)？",
        "options": [
            "(A) 時間戳記 (Timestamp)",
            "(B) 來源 IP",
            "(C) MAC 位址",
            "(D) 序列號"
        ],
        "answer": "A",
        "note": "Kerberos 票據包含時間戳記，若與伺服器時間差距過大 (預設 5 分鐘) 則拒絕，故時間同步很重要。"
    },
    {
        "id": "B2-Prot-26",
        "question": "針對 IoT 設備的安全性，下列哪項措施是「最不建議」的？",
        "options": [
            "(A) 修改預設密碼",
            "(B) 更新韌體",
            "(C) 將 IoT 設備直接暴露在公網 (Public IP) 以方便管理",
            "(D) 建立獨立的 IoT 網段"
        ],
        "answer": "C",
        "note": "IoT 設備常有漏洞，暴露在公網極易成為殭屍網路 (如 Mirai) 的目標。"
    },
    {
        "id": "B2-Prot-27",
        "question": "關於「沙箱 (Sandbox)」技術的用途，下列何者正確？",
        "options": [
            "(A) 用來備份資料",
            "(B) 在隔離環境中執行可疑檔案，觀察其行為以判斷是否為惡意軟體",
            "(C) 用來加密通訊",
            "(D) 提升系統運算速度"
        ],
        "answer": "B",
        "note": "沙箱是防禦未知威脅 (APT/Zero-day) 的重要檢測技術。"
    },
    {
        "id": "B2-Prot-28",
        "question": "下列哪一種無線網路加密協定已被證實極不安全，容易被瞬間破解，應絕對避免使用？",
        "options": [
            "(A) WPA2-AES",
            "(B) WPA3",
            "(C) WEP",
            "(D) WPA2-Enterprise"
        ],
        "answer": "C",
        "note": "WEP 使用 RC4 演算法且 IV 過短，存在嚴重弱點，數分鐘內即可被破解。"
    },
    {
        "id": "B2-Prot-29",
        "question": "在進行滲透測試時，使用 Google Hacking (Google Dorks) 搜尋敏感資料屬於哪一個階段？",
        "options": [
            "(A) 資訊蒐集 (Information Gathering)",
            "(B) 漏洞利用 (Exploitation)",
            "(C) 權限提升 (Privilege Escalation)",
            "(D) 報告撰寫 (Reporting)"
        ],
        "answer": "A",
        "note": "Google Hacking 是被動資訊蒐集 (OSINT) 的一種常用手法。"
    },
    {
        "id": "B2-Prot-30",
        "question": "下列何者是防禦「密碼潑灑 (Password Spraying)」攻擊的有效手段？",
        "options": [
            "(A) 限制密碼長度",
            "(B) 設定帳戶鎖定策略 (Account Lockout Policy) 與多因子認證 (MFA)",
            "(C) 允許使用弱密碼",
            "(D) 關閉日誌記錄"
        ],
        "answer": "B",
        "note": "Password Spraying 是用同一個常用密碼嘗試登入多個帳號，以規避單一帳號鎖定；MFA 可有效防禦。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch2 = [
    // --- 法規與標準 (ISO/CNS) ---
    {
        "id": "B2-Plan-01",
        "question": "依據《資通安全責任等級分級辦法》，C 級機關應多久辦理一次「資通安全健診」？",
        "options": [
            "(A) 每年 1 次",
            "(B) 每 2 年 1 次",
            "(C) 每 3 年 1 次",
            "(D) 無強制要求"
        ],
        "answer": "B",
        "note": "C 級機關資安健診頻率為每 2 年 1 次；A/B 級為每年 1 次。"
    },
    {
        "id": "B2-Plan-02",
        "question": "ISO 27001:2022 標準中，關於「最高管理階層」的責任，下列何者錯誤？",
        "options": [
            "(A) 確保資訊安全政策與目標已建立",
            "(B) 確保 ISMS 整合至組織的過程",
            "(C) 確保資源可用性",
            "(D) 不需要參與管理審查會議，授權給資安官即可"
        ],
        "answer": "D",
        "note": "Clause 5 領導統御要求最高管理階層必須展現領導力與承諾，包括主持管理審查。"
    },
    {
        "id": "B2-Plan-03",
        "question": "關於「個人資料保護法」，非公務機關未訂定安全維護計畫導致個資外洩，最高可處罰鍰多少元？",
        "options": [
            "(A) 20 萬元",
            "(B) 50 萬元",
            "(C) 200 萬元 (屆期未改)",
            "(D) 1500 萬元 (新法修正後上限)"
        ],
        "answer": "D",
        "note": "依據 112 年修法，非公務機關違法且情節重大者，最高可處 1500 萬元罰鍰。"
    },
    {
        "id": "B2-Plan-04",
        "question": "依據 CNS 27001，組織在規劃 ISMS 時，必須考量全景 (Context)，下列何者屬於「內部議題」？",
        "options": [
            "(A) 法律法規要求",
            "(B) 競爭對手的動向",
            "(C) 組織文化、知識與現有資源",
            "(D) 客戶的需求"
        ],
        "answer": "C",
        "note": "內部議題包含組織結構、文化、資源等；A/B/D 屬於外部議題。"
    },
    {
        "id": "B2-Plan-05",
        "question": "關於資通安全專職人員的配置，A 級公務機關要求至少配置幾名資安專職人員？",
        "options": [
            "(A) 1 名",
            "(B) 2 名",
            "(C) 4 名",
            "(D) 6 名"
        ],
        "answer": "C",
        "note": "A 級機關需配置 4 名資安專職人員；B 級為 2 名；C 級為 1 名。"
    },
    // --- 風險管理 ---
    {
        "id": "B2-Plan-06",
        "question": "風險評鑑方法中，「定量分析 (Quantitative Analysis)」的主要特徵為何？",
        "options": [
            "(A) 使用高、中、低來描述風險",
            "(B) 使用具體的數值或金額來描述風險 (如 SLE, ALE)",
            "(C) 依賴專家的主觀判斷",
            "(D) 不需收集數據"
        ],
        "answer": "B",
        "note": "定量分析使用數據與金額計算；定性分析使用等級描述。"
    },
    {
        "id": "B2-Plan-07",
        "question": "若某資產價值 100 萬元，暴露因素 (EF) 為 50%，年度發生率 (ARO) 為 0.1 (十年一次)，則年度損失預期值 (ALE) 為多少？",
        "options": [
            "(A) 5 萬元",
            "(B) 10 萬元",
            "(C) 50 萬元",
            "(D) 500 萬元"
        ],
        "answer": "A",
        "note": "SLE = 100萬 * 0.5 = 50萬；ALE = SLE * ARO = 50萬 * 0.1 = 5萬。"
    },
    {
        "id": "B2-Plan-08",
        "question": "在風險處理計畫中，決定「不採取任何行動，監控風險」是屬於哪一種策略？",
        "options": [
            "(A) 風險規避",
            "(B) 風險降低",
            "(C) 風險移轉",
            "(D) 風險保留 (Retention/Acceptance)"
        ],
        "answer": "D",
        "note": "當風險在可接受範圍內，或處理成本高於損失時，採取保留策略。"
    },
    {
        "id": "B2-Plan-09",
        "question": "關於資產盤點，下列哪一項不屬於「資訊資產」？",
        "options": [
            "(A) 伺服器硬體",
            "(B) 客戶資料庫",
            "(C) 辦公室清潔用品",
            "(D) 應用程式原始碼"
        ],
        "answer": "C",
        "note": "資訊資產指對組織有價值的資訊及其載體；清潔用品屬一般總務資產。"
    },
    {
        "id": "B2-Plan-10",
        "question": "在資安風險評鑑中，威脅 (Threat) 與脆弱性 (Vulnerability) 的關係為何？",
        "options": [
            "(A) 兩者無關",
            "(B) 威脅利用脆弱性造成資產損害，產生風險",
            "(C) 脆弱性利用威脅",
            "(D) 消除脆弱性就能消除所有威脅"
        ],
        "answer": "B",
        "note": "風險 = 資產 x 威脅 x 脆弱性。威脅利用弱點造成衝擊。"
    },
    // --- 營運持續管理 (BCP) ---
    {
        "id": "B2-Plan-11",
        "question": "在 BCP 演練中，哪一種類型的演練成本最低，僅透過討論確認流程？",
        "options": [
            "(A) 桌面演練 (Tabletop Exercise)",
            "(B) 模擬演練 (Simulation)",
            "(C) 平行測試 (Parallel Test)",
            "(D) 全面中斷測試 (Full Interruption Test)"
        ],
        "answer": "A",
        "note": "桌面演練是紙上談兵，成本最低；全面測試風險與成本最高。"
    },
    {
        "id": "B2-Plan-12",
        "question": "關於「備援中心」的選擇，下列何者是「溫站 (Warm Site)」的特徵？",
        "options": [
            "(A) 僅有空機房與水電，無設備",
            "(B) 有部分設備與備份資料，需一段時間安裝與設定才能接手",
            "(C) 設備與資料完全同步，可即時接手",
            "(D) 位於移動車輛上"
        ],
        "answer": "B",
        "note": "冷站(空屋) < 溫站(部分設備/非即時資料) < 熱站(全備/即時)。"
    },
    {
        "id": "B2-Plan-13",
        "question": "進行 BIA (營運衝擊分析) 時，主要評估的是什麼？",
        "options": [
            "(A) 駭客的攻擊手法",
            "(B) 業務中斷對組織造成的財務與非財務損失",
            "(C) 防火牆的吞吐量",
            "(D) 員工的滿意度"
        ],
        "answer": "B",
        "note": "BIA 旨在量化與質化業務中斷的衝擊，以決定復原優先順序。"
    },
    {
        "id": "B2-Plan-14",
        "question": "在 BCP 中，MTPD (最大可容忍中斷時間) 與 RTO 的關係通常為何？",
        "options": [
            "(A) RTO 必須小於 MTPD",
            "(B) RTO 必須大於 MTPD",
            "(C) 兩者必須相等",
            "(D) 兩者無關"
        ],
        "answer": "A",
        "note": "復原目標 (RTO) 必須設定在組織能忍受的極限 (MTPD) 之前完成。"
    },
    {
        "id": "B2-Plan-15",
        "question": "關於備份類型的比較，下列何者正確？",
        "options": [
            "(A) 完整備份還原最慢",
            "(B) 增量備份 (Incremental) 備份速度快，但還原需依序回補，速度最慢",
            "(C) 差異備份 (Differential) 比增量備份更節省空間",
            "(D) 增量備份是備份自上次完整備份後的變更"
        ],
        "answer": "B",
        "note": "增量備份只備份自「上次備份（無論完整或增量）」後的變更，還原鏈最長。"
    },
    // --- 資安治理與管理 ---
    {
        "id": "B2-Plan-16",
        "question": "關於供應鏈安全，下列何者是驗證供應商資安能力的有效方式？",
        "options": [
            "(A) 要求提供 ISO 27001 證書或第三方稽核報告 (SOC 2)",
            "(B) 僅檢視其公司網站介紹",
            "(C) 相信業務員的口頭承諾",
            "(D) 要求供應商提供所有員工個資"
        ],
        "answer": "A",
        "note": "第三方驗證是客觀評估供應商資安水準的依據。"
    },
    {
        "id": "B2-Plan-17",
        "question": "在資安事件應變中，Triage (檢傷分類) 的主要目的是？",
        "options": [
            "(A) 立即修復所有漏洞",
            "(B) 判斷事件的優先順序與嚴重程度，決定資源投入",
            "(C) 懲罰犯錯員工",
            "(D) 撰寫結案報告"
        ],
        "answer": "B",
        "note": "Triage 用於在資源有限下，決定優先處理哪些緊急事件。"
    },
    {
        "id": "B2-Plan-18",
        "question": "關於「職務輪調 (Job Rotation)」在資安管理上的效益，下列何者正確？",
        "options": [
            "(A) 讓員工更累",
            "(B) 防止單一人員長期把持特定權限，隱藏舞弊行為",
            "(C) 降低員工技能",
            "(D) 增加權限管理的複雜度"
        ],
        "answer": "B",
        "note": "職務輪調可強制交接，有助於發現前手可能隱藏的錯誤或舞弊。"
    },
    {
        "id": "B2-Plan-19",
        "question": "依據資通安全管理法，資通安全維護計畫實施情形，應多久提出一次？",
        "options": [
            "(A) 每月",
            "(B) 每季",
            "(C) 每年",
            "(D) 每兩年"
        ],
        "answer": "C",
        "note": "資通安全維護計畫實施情形應「每年」向上級或主管機關提出。"
    },
    {
        "id": "B2-Plan-20",
        "question": "關於社交工程演練，若員工開啟釣魚郵件並點擊連結，後續最適合的處置是？",
        "options": [
            "(A) 立即開除",
            "(B) 記大過處分",
            "(C) 安排資安教育訓練，加強觀念",
            "(D) 公布姓名羞辱"
        ],
        "answer": "C",
        "note": "演練目的為教育，應以鼓勵學習取代懲罰，避免員工未來隱瞞資安事件。"
    },
    {
        "id": "B2-Plan-21",
        "question": "在雲端服務中，關於「資料可攜性 (Data Portability)」的考量是為了避免？",
        "options": [
            "(A) 資料外洩",
            "(B) 廠商鎖定 (Vendor Lock-in)",
            "(C) 效能低落",
            "(D) 駭客攻擊"
        ],
        "answer": "B",
        "note": "資料可攜性確保客戶能將資料從一家雲端供應商遷移到另一家，避免被綁死。"
    },
    {
        "id": "B2-Plan-22",
        "question": "關於「特權帳號管理 (PAM)」，下列敘述何者最佳？",
        "options": [
            "(A) 特權帳號密碼應設定為永久有效",
            "(B) 應監控並側錄特權帳號的操作行為",
            "(C) 特權帳號可以多人共用以方便維運",
            "(D) 特權帳號不需要 MFA"
        ],
        "answer": "B",
        "note": "特權帳號風險極高，必須嚴格監控、側錄並實施 MFA 與定期換密。"
    },
    {
        "id": "B2-Plan-23",
        "question": "下列何者屬於「預防性 (Preventive)」控制措施？",
        "options": [
            "(A) 防火牆",
            "(B) 監視器 (CCTV)",
            "(C) 備份還原",
            "(D) 入侵偵測系統 (IDS)"
        ],
        "answer": "A",
        "note": "防火牆主動阻擋攻擊；IDS/CCTV 是偵測性；還原是矯正性。"
    },
    {
        "id": "B2-Plan-24",
        "question": "關於「資安長 (CISO)」的角色，下列敘述何者正確？",
        "options": [
            "(A) 應由 IT 主管兼任，不需獨立",
            "(B) 負責制定資安策略，並直接向高層管理階層報告",
            "(C) 主要工作是修電腦",
            "(D) 只負責防火牆設定"
        ],
        "answer": "B",
        "note": "CISO 應具備獨立性與高階溝通能力，負責組織整體的資安治理與策略。"
    },
    {
        "id": "B2-Plan-25",
        "question": "在資產分類與分級中，通常將「個資」或「營運機密」列為哪一等級？",
        "options": [
            "(A) 公開 (Public)",
            "(B) 內部使用 (Internal)",
            "(C) 機密 (Confidential) 或 極機密",
            "(D) 不需分級"
        ],
        "answer": "C",
        "note": "個資與營業秘密外洩衝擊大，應列為高敏感等級。"
    },
    {
        "id": "B2-Plan-26",
        "question": "關於「實體安全」，針對機房的門禁管制，下列何者最為嚴謹？",
        "options": [
            "(A) 喇叭鎖",
            "(B) 刷卡門禁",
            "(C) 生物特徵辨識 + 尾隨偵測 (Anti-tailgating)",
            "(D) 開放式進出"
        ],
        "answer": "C",
        "note": "生物辨識結合防尾隨設施 (如曼通門 Mantrap) 是高安全機房的標準配置。"
    },
    {
        "id": "B2-Plan-27",
        "question": "關於「行動裝置管理 (MDM)」，下列何項功能可防止公司資料外洩？",
        "options": [
            "(A) 遠端抹除 (Remote Wipe)",
            "(B) 增加螢幕亮度",
            "(C) 自動備份照片到個人雲端",
            "(D) 允許安裝任意 APP"
        ],
        "answer": "A",
        "note": "當裝置遺失時，遠端抹除可確保機敏資料不外流。"
    },
    {
        "id": "B2-Plan-28",
        "question": "NIST CSF 的「核心 (Core)」不包含下列哪一項？",
        "options": [
            "(A) Tier (層級)",
            "(B) Functions (功能)",
            "(C) Categories (類別)",
            "(D) Subcategories (子類別)"
        ],
        "answer": "A",
        "note": "Core 包含 Function, Category, Subcategory, References。Tier 是 Implementation Tiers，屬於框架的另一部分。"
    },
    {
        "id": "B2-Plan-29",
        "question": "關於 GDPR，若發生個資外洩，原則上應在知悉後多久內通報主管機關？",
        "options": [
            "(A) 24 小時",
            "(B) 72 小時",
            "(C) 7 天",
            "(D) 1 個月"
        ],
        "answer": "B",
        "note": "GDPR 第 33 條規定，除非不太可能導致風險，否則應在 72 小時內通報。"
    },
    {
        "id": "B2-Plan-30",
        "question": "在稽核過程中，查核員發現「有政策但未落實執行」，這屬於？",
        "options": [
            "(A) 設計缺失",
            "(B) 執行缺失 (有效性缺失)",
            "(C) 觀察事項",
            "(D) 符合規範"
        ],
        "answer": "B",
        "note": "有規定但沒做，屬於執行面的有效性缺失 (Non-conformity)。"
    }
];

// 將 Batch 2 的題目合併到主陣列 (請確保主陣列已定義)
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch2);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch2);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第三批次 (Batch 3)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：進階攻擊技術 (AD/Web)、鑑識分析、資安治理細節
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch3 = [
    // --- 進階攻擊技術與分析 (114-113 歷屆精選) ---
    {
        "id": "B3-Prot-01",
        "question": "在 C# 原始碼檢測中，下列何種程式寫法最有可能導致「緩衝區溢位 (Buffer Overflow)」風險？",
        "options": [
            "(A) 使用 List<T> 類型的集合並頻繁添加元素",
            "(B) 在遞迴函數中未設置適當的退出條件",
            "(C) 使用 unsafe 程式碼區塊並直接操作指標 (Pointers)",
            "(D) 進行大量的非同步操作和多執行緒存取"
        ],
        "answer": "C",
        "note": "114-1 防護實務。C# 的 unsafe 模式允許直接記憶體操作，若處理不當易造成溢位，受控代碼 (Managed Code) 則較安全。"
    },
    {
        "id": "B3-Prot-02",
        "question": "關於「DLL Side Loading (DLL 側載)」攻擊，攻擊者通常利用 Windows 載入 DLL 的順序特性。下列哪一個路徑通常是應用程式搜尋 DLL 的第一優先順序？",
        "options": [
            "(A) C:\\Windows\\System32",
            "(B) 應用程式所在的執行目錄 (Application Directory)",
            "(C) 環境變數 PATH 指定的路徑",
            "(D) C:\\Windows"
        ],
        "answer": "B",
        "note": "114-1 防護實務。攻擊者將惡意 DLL 放在與合法程式同一目錄下，程式啟動時就會優先載入惡意 DLL。"
    },
    {
        "id": "B3-Prot-03",
        "question": "在分析受駭主機的 Webshell 時，發現檔案開頭包含 `GIF89a` 字串，其目的為何？",
        "options": [
            "(A) 這是一個正常的 GIF 圖片檔",
            "(B) 為了啟用 GIF 動畫功能",
            "(C) 偽造檔案標頭 (File Header) 以繞過上傳檢查機制，讓伺服器誤判為圖片",
            "(D) 加密 PHP 程式碼"
        ],
        "answer": "C",
        "note": "114-1 防護實務。`GIF89a` 是 GIF 檔頭，攻擊者藉此繞過僅檢查 Magic Number 的上傳防護。"
    },
    {
        "id": "B3-Prot-04",
        "question": "攻擊者在取得 Linux 系統控制權後，為了維持權限 (Persistence)，可能會在下列哪個檔案寫入惡意指令，使使用者登入時自動執行？",
        "options": [
            "(A) /etc/passwd",
            "(B) ~/.bashrc 或 ~/.profile",
            "(C) /var/log/syslog",
            "(D) /proc/cpuinfo"
        ],
        "answer": "B",
        "note": "114-1 防護實務。`.bashrc` 是使用者登入 Shell 時會自動執行的腳本，常用於植入後門。"
    },
    {
        "id": "B3-Prot-05",
        "question": "在 Windows 事件檢視器中，Event ID 4625 代表什麼意義？",
        "options": [
            "(A) 帳號成功登入",
            "(B) 帳號登入失敗",
            "(C) 帳號被鎖定",
            "(D) 系統關機"
        ],
        "answer": "B",
        "note": "113-2 防護實務。4624 為登入成功，4625 為登入失敗 (常見於暴力破解偵測)。"
    },
    {
        "id": "B3-Prot-06",
        "question": "在 Active Directory 滲透測試中，攻擊者常試圖提取 AD 資料庫檔案 `ntds.dit`。下列何種工具或方法可用於提取此檔案（即便它被鎖定）？",
        "options": [
            "(A) 使用 `notepad.exe` 開啟",
            "(B) 使用 `vssadmin` 建立磁碟區陰影複製 (Volume Shadow Copy)",
            "(C) 使用 `ping` 指令",
            "(D) 使用 `net user` 指令"
        ],
        "answer": "B",
        "note": "113-2 防護實務。`ntds.dit` 執行時被鎖定，需透過 VSS (Shadow Copy) 來複製。"
    },
    {
        "id": "B3-Prot-07",
        "question": "關於「GTFOBins」，它主要收集了什麼資訊？",
        "options": [
            "(A) Linux 系統中可被利用於權限提升 (Privilege Escalation) 或繞過限制的合法二進位檔 (Binaries)",
            "(B) Windows 系統的惡意軟體清單",
            "(C) 網路設備的預設密碼表",
            "(D) 網站漏洞掃描工具"
        ],
        "answer": "A",
        "note": "113-1 防護實務。例如利用 sudo 權限執行 vim、find 等指令來獲取 root shell。"
    },
    {
        "id": "B3-Prot-08",
        "question": "使用 WSL (Windows Subsystem for Linux) 時，若要增強安全性，下列措施何者最為重要？",
        "options": [
            "(A) 經常使用 root 帳戶進行日常操作",
            "(B) 監控並記錄 WSL 內對敏感二進位檔案的使用 (如 GTFOBins)",
            "(C) 移除 Windows Defender",
            "(D) 開放所有連接埠"
        ],
        "answer": "B",
        "note": "113-1 防護實務。WSL 與 Windows 互通，攻擊者可能利用 Linux Binaries (GTFOBins) 攻擊 Windows。"
    },
    {
        "id": "B3-Prot-09",
        "question": "在密碼破解攻擊中，「彩虹表 (Rainbow Table)」的主要功能是？",
        "options": [
            "(A) 即時暴力破解密碼",
            "(B) 使用預先計算好的雜湊鏈 (Hash Chain) 加速反查雜湊值",
            "(C) 攔截網路封包",
            "(D) 竊取加密金鑰"
        ],
        "answer": "B",
        "note": "彩虹表是以空間換取時間的技術。防禦方式是加鹽 (Salting)。"
    },
    {
        "id": "B3-Prot-10",
        "question": "關於 JWT (JSON Web Token) 的安全性，下列敘述何者錯誤？",
        "options": [
            "(A) JWT 的 Payload 僅使用 Base64Url 編碼，未加密，不應放入敏感個資",
            "(B) 應驗證 JWT 的簽章 (Signature) 以確保未被竄改",
            "(C) 為了方便測試，伺服器端應允許 `alg: none` 的演算法",
            "(D) JWT 應設定過期時間 (exp)"
        ],
        "answer": "C",
        "note": "絕對禁止允許 `alg: none`，這會導致攻擊者可移除簽章並偽造任意 Token。"
    },
    // --- 網路安全與通訊協定 ---
    {
        "id": "B3-Prot-11",
        "question": "下列哪一種電子郵件驗證機制，是利用 DNS 記錄來驗證寄件來源 IP 是否被授權？",
        "options": [
            "(A) SPF (Sender Policy Framework)",
            "(B) DKIM (DomainKeys Identified Mail)",
            "(C) DMARC",
            "(D) PGP"
        ],
        "answer": "A",
        "note": "SPF 透過 DNS TXT 記錄列出允許發信的 IP；DKIM 是數位簽章；DMARC 是政策宣告。"
    },
    {
        "id": "B3-Prot-12",
        "question": "關於 SSH (Secure Shell) 安全設定，下列何者是最佳實務？",
        "options": [
            "(A) 允許 root 直接遠端登入",
            "(B) 使用密碼認證代替金鑰認證",
            "(C) 禁止 root 遠端登入，改用金鑰認證 (Key-based Authentication)",
            "(D) 使用預設 Port 22 且不限制來源 IP"
        ],
        "answer": "C",
        "note": "禁止 Root 登入與使用金鑰認證能大幅降低暴力破解風險。"
    },
    {
        "id": "B3-Prot-13",
        "question": "下列哪一種協定主要用於「網路設備」的集中式身分驗證與授權 (AAA)？",
        "options": [
            "(A) DHCP",
            "(B) RADIUS 或 TACACS+",
            "(C) SNMP",
            "(D) DNS"
        ],
        "answer": "B",
        "note": "RADIUS/TACACS+ 是標準的 AAA 協定 (Authentication, Authorization, Accounting)。"
    },
    {
        "id": "B3-Prot-14",
        "question": "在 Wireshark 中，若要過濾出源自 IP 192.168.1.5 的封包，過濾語法應為？",
        "options": [
            "(A) ip.addr == 192.168.1.5",
            "(B) ip.src == 192.168.1.5",
            "(C) ip.dst == 192.168.1.5",
            "(D) ip.host == 192.168.1.5"
        ],
        "answer": "B",
        "note": "ip.src 代表來源 IP；ip.dst 代表目的 IP；ip.addr 代表兩者皆可。"
    },
    {
        "id": "B3-Prot-15",
        "question": "關於 TLS 1.3 相較於 TLS 1.2 的改進，下列何者正確？",
        "options": [
            "(A) 握手過程 (Handshake) 更慢",
            "(B) 移除了不安全的加密套件 (如 RC4, DES) 並強制使用 PFS (完全前向保密)",
            "(C) 支援 SSL 3.0",
            "(D) 必須使用 RSA 金鑰"
        ],
        "answer": "B",
        "note": "TLS 1.3 簡化握手流程提升速度，並移除了大量不安全演算法，強制 PFS。"
    },
    // --- 應用程式安全 (AppSec) ---
    {
        "id": "B3-Prot-16",
        "question": "在軟體開發中，使用「靜態應用程式安全測試 (SAST)」的主要時機點為何？",
        "options": [
            "(A) 軟體上線後的維運階段",
            "(B) 程式碼編寫與提交 (Commit) 階段",
            "(C) 應用程式執行時",
            "(D) 廢棄軟體時"
        ],
        "answer": "B",
        "note": "SAST 分析原始碼，適合在開發早期 (Coding/Build) 進行。"
    },
    {
        "id": "B3-Prot-17",
        "question": "下列哪一種漏洞通常是因為應用程式直接將使用者輸入傳遞給系統 Shell 執行而產生？",
        "options": [
            "(A) OS Command Injection",
            "(B) SQL Injection",
            "(C) LDAP Injection",
            "(D) XPath Injection"
        ],
        "answer": "A",
        "note": "Command Injection 發生在應用程式呼叫系統指令 (如 system(), exec()) 時未過濾輸入。"
    },
    {
        "id": "B3-Prot-18",
        "question": "關於「反序列化漏洞 (Insecure Deserialization)」，下列敘述何者正確？",
        "options": [
            "(A) 僅發生在 Java 語言",
            "(B) 攻擊者透過竄改序列化物件，在反序列化過程中執行惡意程式碼",
            "(C) 可以透過防火牆完全阻擋",
            "(D) 屬於前端 JavaScript 漏洞"
        ],
        "answer": "B",
        "note": "反序列化漏洞廣泛存在於 Java, PHP, Python 等語言，可導致 RCE。"
    },
    {
        "id": "B3-Prot-19",
        "question": "在 Android App 安全中，將敏感資料儲存在 `SharedPreferences` 時，應注意什麼？",
        "options": [
            "(A) 不需要加密，因為只有 App 自己能讀取",
            "(B) 應使用 `EncryptedSharedPreferences` 進行加密儲存",
            "(C) 應設定為 `MODE_WORLD_READABLE`",
            "(D) 應儲存在 SD 卡上"
        ],
        "answer": "B",
        "note": "明文儲存並不安全 (Root 後可讀)，應使用 EncryptedSharedPreferences。"
    },
    {
        "id": "B3-Prot-20",
        "question": "關於 API 安全，防止 BOLA (Broken Object Level Authorization) 的最佳方式是？",
        "options": [
            "(A) 隱藏 API 文件",
            "(B) 每次存取物件時，後端都必須驗證當前使用者是否有權存取該特定 ID 的物件",
            "(C) 僅使用 HTTPS",
            "(D) 使用複雜的 ID"
        ],
        "answer": "B",
        "note": "BOLA (或稱 IDOR) 必須在後端邏輯層進行嚴格的權限檢查，不能僅依賴前端。"
    },
    // --- 新興科技與雲端 ---
    {
        "id": "B3-Prot-21",
        "question": "在 Kubernetes (K8s) 中，為了遵循最小權限原則，Pod 應避免使用哪種設定？",
        "options": [
            "(A) `privileged: true`",
            "(B) `readOnlyRootFilesystem: true`",
            "(C) `runAsNonRoot: true`",
            "(D) `allowPrivilegeEscalation: false`"
        ],
        "answer": "A",
        "note": "`privileged: true` 會給予容器幾乎等同於 Host 的權限，極度危險。"
    },
    {
        "id": "B3-Prot-22",
        "question": "關於雲端原生的「Serverless (無伺服器)」架構，下列資安風險何者依然存在？",
        "options": [
            "(A) 作業系統修補 (由廠商負責)",
            "(B) 應用程式層的漏洞 (如 Injection, Broken Auth)",
            "(C) 實體機房安全",
            "(D) 電源管理"
        ],
        "answer": "B",
        "note": "Serverless 免去了 OS 管理，但應用程式邏輯與代碼安全仍是使用者的責任。"
    },
    {
        "id": "B3-Prot-23",
        "question": "AI 模型面臨的「資料毒化 (Data Poisoning)」攻擊，主要發生在 AI 生命週期的哪個階段？",
        "options": [
            "(A) 推論階段 (Inference)",
            "(B) 訓練階段 (Training)",
            "(C) 部署階段 (Deployment)",
            "(D) 廢棄階段"
        ],
        "answer": "B",
        "note": "攻擊者在訓練資料集中注入惡意數據，導致模型學習到錯誤的行為。"
    },
    {
        "id": "B3-Prot-24",
        "question": "在容器安全掃描中，CI/CD Pipeline 階段主要掃描的對象是？",
        "options": [
            "(A) 執行中的容器 (Runtime)",
            "(B) 容器映像檔 (Container Image) 的漏洞與設定",
            "(C) 實體伺服器",
            "(D) 防火牆規則"
        ],
        "answer": "B",
        "note": "在 Build 階段掃描 Image (如 Trivy, Claire) 是確保供應鏈安全的重要環節。"
    },
    {
        "id": "B3-Prot-25",
        "question": "關於 Dockerfile 的安全實踐，下列何者建議「避免」？",
        "options": [
            "(A) 使用 `COPY` 代替 `ADD` (ADD 可能自動解壓或下載)",
            "(B) 在 Dockerfile 中直接寫入密碼或 API Key",
            "(C) 指定具體的 Base Image 版本 (如 node:14-alpine)",
            "(D) 使用非 Root 使用者執行"
        ],
        "answer": "B",
        "note": "機敏資訊 (Secrets) 不應寫死在 Dockerfile 中，應透過環境變數或 Secret Management 掛載。"
    },
    // --- 其他綜合 ---
    {
        "id": "B3-Prot-26",
        "question": "勒索軟體攻擊鏈中，攻擊者通常會先刪除或加密什麼，以防止被害者自行復原？",
        "options": [
            "(A) 瀏覽器歷史紀錄",
            "(B) 備份檔案與磁碟區陰影複製 (Shadow Copies)",
            "(C) 暫存檔",
            "(D) 桌面捷徑"
        ],
        "answer": "B",
        "note": "刪除備份與 Shadow Copies 是勒索軟體的標準動作 (如 `vssadmin delete shadows /all /quiet`)。"
    },
    {
        "id": "B3-Prot-27",
        "question": "關於「跳板機 (Bastion Host / Jump Server)」的安全配置，下列何者錯誤？",
        "options": [
            "(A) 應強制使用 MFA 登入",
            "(B) 應記錄所有操作日誌與連線過程 (Session Recording)",
            "(C) 允許從任意來源 IP 登入",
            "(D) 應作為進入內部管理網段的唯一入口"
        ],
        "answer": "C",
        "note": "跳板機應嚴格限制來源 IP (白名單)，不應開放給任意來源。"
    },
    {
        "id": "B3-Prot-28",
        "question": "在 Wi-Fi 安全中，若是開放式網路 (Open) 但需要登入網頁認證 (Captive Portal)，通常容易受到什麼攻擊？",
        "options": [
            "(A) WPA 握手破解",
            "(B) 側錄 (Sniffing) 與 Session Hijacking (因為空中傳輸未加密)",
            "(C) SQL Injection",
            "(D) Buffer Overflow"
        ],
        "answer": "B",
        "note": "Captive Portal 僅認證身分，通常不對無線傳輸進行 L2 加密 (除非使用 OWE)，故易被側錄。"
    },
    {
        "id": "B3-Prot-29",
        "question": "關於 ARP Spoofing (ARP 欺騙) 攻擊，主要發生在 OSI 模型的哪一層？",
        "options": [
            "(A) Layer 2 (Data Link Layer)",
            "(B) Layer 3 (Network Layer)",
            "(C) Layer 4 (Transport Layer)",
            "(D) Layer 7 (Application Layer)"
        ],
        "answer": "A",
        "note": "ARP 是 L2 協定 (MAC Address)，攻擊者偽造 ARP 回應以進行中間人攻擊。"
    },
    {
        "id": "B3-Prot-30",
        "question": "資安鑑識中，「時間戳記 (Timeline)」分析的主要目的是？",
        "options": [
            "(A) 計算硬碟容量",
            "(B) 重建事件發生的先後順序，關聯檔案、日誌與行為",
            "(C) 加速開機時間",
            "(D) 校正系統時間"
        ],
        "answer": "B",
        "note": "建立時間軸 (Timeline Analysis) 是釐清攻擊流程與因果關係的關鍵步驟。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch3 = [
    // --- 法規與標準 (進階) ---
    {
        "id": "B3-Plan-01",
        "question": "關於 SOC (Service Organization Control) 報告，若企業需要一份「包含詳細測試結果、僅供稽核員與管理層閱讀」的報告，應選擇？",
        "options": [
            "(A) SOC 1",
            "(B) SOC 2 Type 1",
            "(C) SOC 2 Type 2",
            "(D) SOC 3"
        ],
        "answer": "C",
        "note": "114-1 規劃實務。SOC 2 Type 2 包含一段時間的控制有效性測試細節，屬機密報告；SOC 3 才是公開摘要。"
    },
    {
        "id": "B3-Plan-02",
        "question": "依據《資通安全責任等級分級辦法》，B 級機關的資通系統防護需求分級，至少應多久檢視一次？",
        "options": [
            "(A) 每半年",
            "(B) 每年",
            "(C) 每兩年",
            "(D) 每三年"
        ],
        "answer": "B",
        "note": "114 概論教材。A/B/C 級機關皆應「每年」至少檢視 1 次資通系統分級妥適性。"
    },
    {
        "id": "B3-Plan-03",
        "question": "在 ISO 27001:2022 中，關於「變更管理 (Change Management)」的要求，下列何者正確？",
        "options": [
            "(A) 只要口頭告知即可",
            "(B) 變更應經過規劃、測試、評估風險並獲得授權後方可實施",
            "(C) 緊急變更不需要記錄",
            "(D) 只有重大變更才需要管理"
        ],
        "answer": "B",
        "note": "變更管理的核心在於受控 (Controlled)：文件化、測試、核准、回滾計畫。"
    },
    {
        "id": "B3-Plan-04",
        "question": "關於 GDPR 中的「資料保護長 (DPO)」，下列敘述何者正確？",
        "options": [
            "(A) 所有企業都必須指派 DPO",
            "(B) DPO 對資料處理行為負完全法律責任",
            "(C) DPO 必須保持獨立性，不受管理階層關於執行任務的指示",
            "(D) DPO 必須是公司內部員工，不可委外"
        ],
        "answer": "C",
        "note": "獨立性是 DPO 的關鍵要求；GDPR 允許委外 DPO，且非所有企業皆強制設置。"
    },
    {
        "id": "B3-Plan-05",
        "question": "歐盟最新發布的「Cyber Resilience Act (CRA)」主要規範對象為何？",
        "options": [
            "(A) 僅限政府機關",
            "(B) 具有數位元素產品 (如 IoT 設備、軟體) 的製造商與開發商",
            "(C) 僅限金融業",
            "(D) 社群媒體平台"
        ],
        "answer": "B",
        "note": "113-1 規劃實務。CRA 旨在強化連網產品的資安，要求產品生命週期內的安全性。"
    },
    // --- 風險管理與 BCP ---
    {
        "id": "B3-Plan-06",
        "question": "在風險評鑑矩陣 (Risk Matrix) 中，若「衝擊 (Impact)」為高，「可能性 (Likelihood)」為低，通常風險等級為何？",
        "options": [
            "(A) 極低",
            "(B) 低",
            "(C) 中或高 (視組織定義)",
            "(D) 可忽略"
        ],
        "answer": "C",
        "note": "113-1 規劃實務。雖然發生率低，但衝擊高 (如地震)，通常仍會被列為中度或高度風險，需制定應變計畫。"
    },
    {
        "id": "B3-Plan-07",
        "question": "關於 BCP 的「異地備援」，依據我國規範，主機房與異地備援機房的距離建議至少多少公里以上？",
        "options": [
            "(A) 10 公里",
            "(B) 30 公里",
            "(C) 100 公里",
            "(D) 300 公里"
        ],
        "answer": "B",
        "note": "113-2 規劃實務 (情境題)。通常建議 30 公里以上以避免同一個區域性災害 (如地震、停電) 同時影響兩地。"
    },
    {
        "id": "B3-Plan-08",
        "question": "若某系統的 RTO 為 4 小時，這意味著什麼？",
        "options": [
            "(A) 資料最多損失 4 小時",
            "(B) 必須在災害發生後 4 小時內恢復系統運作",
            "(C) 系統每 4 小時備份一次",
            "(D) 系統可以容忍停機 4 天"
        ],
        "answer": "B",
        "note": "RTO (復原時間目標) 是指「時間長度」，即從中斷到恢復的目標時間。"
    },
    {
        "id": "B3-Plan-09",
        "question": "在供應鏈風險管理中，下列何者不是「軟體供應鏈」的常見風險？",
        "options": [
            "(A) 開源套件被植入惡意程式",
            "(B) 開發環境被入侵",
            "(C) 硬體設備老化",
            "(D) 軟體更新伺服器被劫持"
        ],
        "answer": "C",
        "note": "硬體老化屬硬體維護問題，非軟體供應鏈攻擊 (如 SolarWinds, Log4j)。"
    },
    {
        "id": "B3-Plan-10",
        "question": "關於「風險胃納 (Risk Appetite)」，下列敘述何者正確？",
        "options": [
            "(A) 組織願意接受的風險總量或程度",
            "(B) 已經發生的風險",
            "(C) 無法處理的風險",
            "(D) 保險公司理賠的上限"
        ],
        "answer": "A",
        "note": "風險胃納是組織在追求目標時，願意承擔的風險水準。"
    },
    // --- 資安治理與稽核 ---
    {
        "id": "B3-Plan-11",
        "question": "資安稽核中，稽核員發現「防火牆規則半年未審查」，但公司政策規定「每季審查」。這是屬於？",
        "options": [
            "(A) 符合規範",
            "(B) 不符合事項 (Non-conformity)",
            "(C) 觀察事項",
            "(D) 改進機會"
        ],
        "answer": "B",
        "note": "未落實公司明文規定的政策，屬於明確的不符合 (Non-conformity)。"
    },
    {
        "id": "B3-Plan-12",
        "question": "關於「社交工程演練」的後續處置，對於多次點擊釣魚郵件的員工，最有效的管理措施是？",
        "options": [
            "(A) 直接開除",
            "(B) 限制其上網權限",
            "(C) 強制參加加強版資安教育訓練與測驗",
            "(D) 忽略不計"
        ],
        "answer": "C",
        "note": "教育訓練與再測驗是矯正行為的最佳方式，而非單純懲罰。"
    },
    {
        "id": "B3-Plan-13",
        "question": "依據資通安全管理法，A 級機關應在初次核定後多久內完成導入 CNS 27001 並通過驗證？",
        "options": [
            "(A) 1 年內",
            "(B) 2 年內",
            "(C) 3 年內",
            "(D) 4 年內"
        ],
        "answer": "C",
        "note": "114 概論教材。A/B 級機關需在 3 年內完成公正第三方驗證 (ISO/CNS 27001)。"
    },
    {
        "id": "B3-Plan-14",
        "question": "在 ISO 27002 中，關於「資產歸還 (Return of Assets)」的控制措施，主要發生在什麼時候？",
        "options": [
            "(A) 員工入職時",
            "(B) 員工聘用終止 (離職) 或合約結束時",
            "(C) 每年盤點時",
            "(D) 設備故障時"
        ],
        "answer": "B",
        "note": "確保離職時歸還所有資產（設備、權限、資料）是重要的人員安全控制。"
    },
    {
        "id": "B3-Plan-15",
        "question": "關於「資訊分類與分級 (Information Classification)」，下列何者是分類的主要依據？",
        "options": [
            "(A) 資料的大小",
            "(B) 資料的法律價值、機密性與敏感度",
            "(C) 資料的建立日期",
            "(D) 資料的格式 (Word/PDF)"
        ],
        "answer": "B",
        "note": "分類分級應基於資料洩露或損壞對組織造成的衝擊程度 (C.I.A. 價值)。"
    },
    // --- 技術管理與維運 ---
    {
        "id": "B3-Plan-16",
        "question": "關於「漏洞修補管理 (Patch Management)」，對於高風險漏洞，一般建議的修補時限為何？",
        "options": [
            "(A) 1 個月內",
            "(B) 儘速，建議 1 週內或依機關規範 (如 48 小時)",
            "(C) 半年內",
            "(D) 等到下次改版再修"
        ],
        "answer": "B",
        "note": "高風險漏洞 (如 CVSS > 9) 應立即或儘速修補，許多規範要求 48 小時或 1 週內。"
    },
    {
        "id": "B3-Plan-17",
        "question": "關於「特權帳號 (Privileged Account)」的管理，下列何者不是最佳實務？",
        "options": [
            "(A) 實施 MFA",
            "(B) 採最小權限原則",
            "(C) 允許多人共用一個 Administrator 帳號以方便交接",
            "(D) 側錄並監控特權操作"
        ],
        "answer": "C",
        "note": "禁止共用帳號是可歸責性 (Accountability) 的基本要求。"
    },
    {
        "id": "B3-Plan-18",
        "question": "在 SSDLC (安全軟體開發生命週期) 中，應該在什麼階段進行「威脅建模 (Threat Modeling)」？",
        "options": [
            "(A) 需求與設計階段",
            "(B) 程式碼開發階段",
            "(C) 測試階段",
            "(D) 部署階段"
        ],
        "answer": "A",
        "note": "威脅建模應在設計階段進行，以儘早發現架構層面的安全缺陷 (Security by Design)。"
    },
    {
        "id": "B3-Plan-19",
        "question": "關於「日誌管理 (Log Management)」，下列哪一種日誌對於追查「未經授權的存取」最重要？",
        "options": [
            "(A) 效能監控日誌",
            "(B) 登入/登出與認證日誌 (Auth Logs)",
            "(C) 印表機日誌",
            "(D) 電源管理日誌"
        ],
        "answer": "B",
        "note": "登入失敗、權限變更等認證日誌是入侵偵測與鑑識的核心。"
    },
    {
        "id": "B3-Plan-20",
        "question": "關於「BYOD (Bring Your Own Device)」政策，下列何者是主要的資安風險？",
        "options": [
            "(A) 節省公司硬體成本",
            "(B) 員工使用習慣與效率提升",
            "(C) 公司資料與個人資料混雜，且裝置安全狀態難以管控",
            "(D) 辦公室無線網路變慢"
        ],
        "answer": "C",
        "note": "BYOD 的核心風險在於裝置不受控 (可能已越獄/中毒) 及資料外洩 (DLP)。"
    },
    // --- 綜合情境 ---
    {
        "id": "B3-Plan-21",
        "question": "某公司發生勒索軟體事件，駭客宣稱已竊取個資並加密檔案。作為資安長，首要的應變行動是？",
        "options": [
            "(A) 立即支付贖金",
            "(B) 啟動緊急應變小組，隔離受駭範圍並保存證據",
            "(C) 格式化所有電腦",
            "(D) 關閉公司對外營運網站"
        ],
        "answer": "B",
        "note": "遏制 (Containment) 與證據保全是事故應變 (IR) 的第一優先。"
    },
    {
        "id": "B3-Plan-22",
        "question": "關於「資安保險」的理賠範圍，下列何者通常「不」包含在內？",
        "options": [
            "(A) 資料救援費用",
            "(B) 法律訴訟費用",
            "(C) 營業中斷損失",
            "(D) 因資安事件導致的商譽損失之長期估價"
        ],
        "answer": "D",
        "note": "商譽等無形資產的長期損失通常難以量化且不在理賠範圍，保險多針對具體財務損失。"
    },
    {
        "id": "B3-Plan-23",
        "question": "在進行「個資衝擊評估 (DPIA)」時，主要評估的是什麼？",
        "options": [
            "(A) 專案的獲利能力",
            "(B) 個資處理流程對當事人隱私權益的影響與風險",
            "(C) 系統的運算效能",
            "(D) 備份媒體的容量"
        ],
        "answer": "B",
        "note": "DPIA 關注的是資料處理對「當事人 (Data Subject)」權益的風險。"
    },
    {
        "id": "B3-Plan-24",
        "question": "關於「網路實體隔離 (Air Gap)」的敘述，下列何者正確？",
        "options": [
            "(A) 實體隔離就絕對安全，不會中毒",
            "(B) 仍可能透過 USB 隨身碟或內部人員惡意行為感染 (如 Stuxnet)",
            "(C) 實體隔離不需要做資產盤點",
            "(D) 實體隔離可以透過 Wi-Fi 連線"
        ],
        "answer": "B",
        "note": "Stuxnet 證明了即使是 Air Gap 的工控網路，也能透過 USB 介質進行攻擊。"
    },
    {
        "id": "B3-Plan-25",
        "question": "關於「雲端存取安全代理 (CASB)」的功能，下列何者錯誤？",
        "options": [
            "(A) 提供雲端服務的可視性 (Visibility)",
            "(B) 取代雲端供應商的底層安全防護",
            "(C) 實施資料外洩防護 (DLP)",
            "(D) 偵測異常的使用者行為"
        ],
        "answer": "B",
        "note": "CASB 是位於使用者與雲端服務之間的安全閘道，無法取代供應商本身的底層安全。"
    },
    {
        "id": "B3-Plan-26",
        "question": "在 NIST SP 800-53 中，控制措施被分為三大類，除了技術類 (Technical) 與管理類 (Management) 外，還有一類是？",
        "options": [
            "(A) 財務類 (Financial)",
            "(B) 法律類 (Legal)",
            "(C) 作業類/實體類 (Operational)",
            "(D) 虛擬類 (Virtual)"
        ],
        "answer": "C",
        "note": "三大類控制：Management (管理), Operational (作業/實體), Technical (技術)。"
    },
    {
        "id": "B3-Plan-27",
        "question": "關於「數位韌性 (Digital Resilience)」的概念，其重點在於？",
        "options": [
            "(A) 防止所有攻擊發生",
            "(B) 在遭受攻擊或災害時，能快速恢復並維持核心業務運作的能力",
            "(C) 購買最貴的資安設備",
            "(D) 聘請最多的資安人員"
        ],
        "answer": "B",
        "note": "韌性強調的是「恢復力」與「適應力」，承認攻擊不可避免。"
    },
    {
        "id": "B3-Plan-28",
        "question": "下列何者是「資安健診」的主要工作項目之一？",
        "options": [
            "(A) 撰寫應用程式碼",
            "(B) 網路封包側錄分析 (Network Sniffing Analysis) 以發現異常連線",
            "(C) 更換老舊硬體",
            "(D) 員工績效考核"
        ],
        "answer": "B",
        "note": "資安健診通常包含：網路架構檢視、封包側錄分析、惡意程式檢視、更新檢視等。"
    },
    {
        "id": "B3-Plan-29",
        "question": "關於「容器 (Container)」與「虛擬機 (VM)」的比較，就資安隔離性而言：",
        "options": [
            "(A) 容器的隔離性優於虛擬機",
            "(B) 虛擬機 (VM) 的隔離性通常優於容器，因為 VM 有獨立的 OS Kernel",
            "(C) 兩者隔離性完全相同",
            "(D) 容器不需要隔離"
        ],
        "answer": "B",
        "note": "容器共用 Kernel，若 Kernel 有漏洞可能導致逃逸；VM 有 Hypervisor 層級的硬體隔離，安全性較高。"
    },
    {
        "id": "B3-Plan-30",
        "question": "在資安教育訓練中，對於一般員工最應強調的重點是？",
        "options": [
            "(A) 如何設定防火牆規則",
            "(B) 如何撰寫安全的 C++ 程式碼",
            "(C) 辨識釣魚郵件與社交工程攻擊",
            "(D) 滲透測試技巧"
        ],
        "answer": "C",
        "note": "社交工程是針對一般員工最常見的攻擊，提升意識是人為防護的關鍵。"
    }
];

// 將 Batch 3 的題目合併到主陣列 (請確保主陣列已定義)
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch3);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch3);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第四批次 (Batch 4)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：進階 Web 攻擊、生物辨識指標、隱私標準 (ISO 27701)、風險評鑑方法
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch4 = [
    // --- Web 與應用程式安全進階 ---
    {
        "id": "B4-Prot-01",
        "question": "攻擊者透過輸入 `../../../../etc/passwd` 試圖讀取 Linux 系統帳號檔案，這是屬於哪一種攻擊？",
        "options": [
            "(A) SQL Injection",
            "(B) Directory Traversal (目錄遍歷 / Path Traversal)",
            "(C) Cross-Site Scripting (XSS)",
            "(D) Command Injection"
        ],
        "answer": "B",
        "note": "利用 `../` (Dot-dot-slash) 跳脫網站根目錄限制，存取系統敏感檔案。"
    },
    {
        "id": "B4-Prot-02",
        "question": "為了防禦「點擊劫持 (Clickjacking)」攻擊，應在網頁伺服器設定哪一個 HTTP Header？",
        "options": [
            "(A) X-XSS-Protection",
            "(B) X-Frame-Options",
            "(C) Strict-Transport-Security",
            "(D) Access-Control-Allow-Origin"
        ],
        "answer": "B",
        "note": "設定 `X-Frame-Options: DENY` 或 `SAMEORIGIN` 可禁止網頁被嵌入 iframe 中，防止點擊劫持。"
    },
    {
        "id": "B4-Prot-03",
        "question": "攻擊者在網頁中注入惡意程式碼，當管理者檢視後台日誌或留言時觸發執行，這屬於哪種類型的 XSS？",
        "options": [
            "(A) Reflected XSS (反射型)",
            "(B) Stored XSS (儲存型)",
            "(C) DOM-based XSS",
            "(D) Self-XSS"
        ],
        "answer": "B",
        "note": "惡意腳本被「儲存」在資料庫或日誌中，等待受害者讀取時觸發，危害通常最大。"
    },
    {
        "id": "B4-Prot-04",
        "question": "關於 SSTI (Server-Side Template Injection) 攻擊，通常發生在什麼環境？",
        "options": [
            "(A) 傳統靜態 HTML 網站",
            "(B) 使用樣板引擎 (如 Jinja2, FreeMarker) 的動態網站",
            "(C) 資料庫伺服器",
            "(D) 防火牆設備"
        ],
        "answer": "B",
        "note": "攻擊者將惡意樣板語法注入輸入欄位，導致伺服器端執行任意程式碼 (RCE)。"
    },
    {
        "id": "B4-Prot-05",
        "question": "在 API 安全中，攻擊者發送大量請求導致後端資源耗盡，除了 DDoS 防護外，API Gateway 應設定什麼機制來防禦？",
        "options": [
            "(A) Rate Limiting (速率限制)",
            "(B) SQL Injection Filter",
            "(C) CORS (跨來源資源共用)",
            "(D) Data Masking"
        ],
        "answer": "A",
        "note": "Rate Limiting 可限制單一 IP 或 Token 在單位時間內的請求次數，防止濫用。"
    },
    // --- 系統與網路安全進階 ---
    {
        "id": "B4-Prot-06",
        "question": "在 Linux 系統權限中，若一個執行檔被設定了 `SUID` (Set User ID) 位元，代表什麼意義？",
        "options": [
            "(A) 該檔案無法被刪除",
            "(B) 執行該檔案時，會暫時擁有「檔案擁有者 (通常是 root)」的權限",
            "(C) 該檔案只能由 root 執行",
            "(D) 該檔案是系統核心模組"
        ],
        "answer": "B",
        "note": "SUID 權限若設定不當 (如 vim, find)，常被攻擊者用來提權 (Privilege Escalation)。"
    },
    {
        "id": "B4-Prot-07",
        "question": "關於 Windows Registry (登錄檔) 中的 `Run` 或 `RunOnce` 機碼，攻擊者修改它的主要目的是？",
        "options": [
            "(A) 破壞系統開機",
            "(B) 建立持久性 (Persistence)，讓惡意程式隨系統開機自動執行",
            "(C) 提升權限",
            "(D) 隱藏檔案"
        ],
        "answer": "B",
        "note": "這是惡意軟體最常見的維持權限手段之一。"
    },
    {
        "id": "B4-Prot-08",
        "question": "下列哪一種 VPN 通訊協定被認為是新一代、輕量級且高效能的選擇？",
        "options": [
            "(A) PPTP",
            "(B) L2TP",
            "(C) WireGuard",
            "(D) SSTP"
        ],
        "answer": "C",
        "note": "WireGuard 程式碼精簡、效能高且加密安全性強，是現代 VPN 的主流選擇之一。"
    },
    {
        "id": "B4-Prot-09",
        "question": "關於 DHCP Starvation (DHCP 耗盡) 攻擊，攻擊者的手法為何？",
        "options": [
            "(A) 發送大量偽造的 DHCP Request，耗盡 DHCP 伺服器的 IP Pool",
            "(B) 偽裝成 DHCP 伺服器分配錯誤 IP",
            "(C) 竊聽 DHCP 封包",
            "(D) 修改 DNS 設定"
        ],
        "answer": "A",
        "note": "攻擊者偽造不同 MAC 位址請求 IP，導致合法使用者無法取得 IP 上網。防禦方式為 DHCP Snooping / Port Security。"
    },
    {
        "id": "B4-Prot-10",
        "question": "在 IDS/IPS 中，「誤報 (False Positive)」是指什麼情況？",
        "options": [
            "(A) 有攻擊發生，但系統沒偵測到",
            "(B) 系統將正常的流量誤判為攻擊並發出警報",
            "(C) 系統當機",
            "(D) 攻擊者繞過防禦"
        ],
        "answer": "B",
        "note": "False Positive (誤報) 會造成管理員疲勞；False Negative (漏報) 則會導致安全破口。"
    },
    // --- 密碼學與認證進階 ---
    {
        "id": "B4-Prot-11",
        "question": "在儲存密碼時，除了使用雜湊 (Hash) 外，加入「鹽 (Salt)」的主要目的是什麼？",
        "options": [
            "(A) 加速雜湊運算",
            "(B) 防止彩虹表 (Rainbow Table) 攻擊，確保相同密碼產生不同的雜湊值",
            "(C) 讓密碼可以被還原",
            "(D) 增加密碼長度"
        ],
        "answer": "B",
        "note": "Salt 是隨機值，能讓兩個使用相同密碼，123456 的人，擁有完全不同的 Hash 結果。"
    },
    {
        "id": "B4-Prot-12",
        "question": "關於 Diffie-Hellman (DH) 演算法的主要用途，下列何者正確？",
        "options": [
            "(A) 對資料進行加密",
            "(B) 對檔案進行數位簽章",
            "(C) 在不安全的通道上安全地交換/協商密鑰",
            "(D) 壓縮資料"
        ],
        "answer": "C",
        "note": "DH 演算法本身不加密資料，而是讓雙方協商出一個共用的對稱金鑰。"
    },
    {
        "id": "B4-Prot-13",
        "question": "在生物辨識技術中，若系統要求安全性極高 (如金庫門禁)，應如何調整參數？",
        "options": [
            "(A) 調高 FAR (錯誤接受率)",
            "(B) 調低 FRR (錯誤拒絕率)",
            "(C) 盡量降低 FAR (錯誤接受率)，即使 FRR 上升",
            "(D) 讓 FAR 與 FRR 相等 (EER)"
        ],
        "answer": "C",
        "note": "高安全性場景不能容許誤放 (False Accept)，因此需極力降低 FAR，代價是可能誤拒合法使用者 (高 FRR)。"
    },
    {
        "id": "B4-Prot-14",
        "question": "關於 OAuth 2.0 協定，Access Token 的主要用途是？",
        "options": [
            "(A) 用來證明使用者的身分 (Authentication)",
            "(B) 用來存取受保護的資源 (Authorization)",
            "(C) 用來加密傳輸資料",
            "(D) 用來簽署文件"
        ],
        "answer": "B",
        "note": "OAuth 2.0 是授權協定，Access Token 用於換取資源；OpenID Connect (OIDC) 的 ID Token 才是用於身分認證。"
    },
    {
        "id": "B4-Prot-15",
        "question": "PKI 架構中，「CRL (Certificate Revocation List)」的作用為何？",
        "options": [
            "(A) 儲存所有有效的憑證",
            "(B) 列出已經被撤銷（廢止）的憑證清單",
            "(C) 用來備份私鑰",
            "(D) 用來產生金鑰對"
        ],
        "answer": "B",
        "note": "當私鑰洩漏或憑證不再信任時，會被加入 CRL，驗證端需檢查此清單。"
    },
    // --- 攻防工具與新興威脅 ---
    {
        "id": "B4-Prot-16",
        "question": "Metasploit Framework 中的 `Meterpreter` 是什麼？",
        "options": [
            "(A) 一個漏洞掃描器",
            "(B) 一個在漏洞利用後 (Post-exploitation) 執行的高級 Payload，提供強大控制功能",
            "(C) 一個密碼破解工具",
            "(D) 一個防火牆"
        ],
        "answer": "B",
        "note": "Meterpreter 駐留在記憶體中，提供截圖、鍵盤側錄、提權等強大後滲透功能。"
    },
    {
        "id": "B4-Prot-17",
        "question": "關於「DNS Tunneling」攻擊手法，下列敘述何者正確？",
        "options": [
            "(A) 攻擊者癱瘓 DNS 伺服器",
            "(B) 攻擊者將資料封裝在 DNS 查詢與回應封包中，以繞過防火牆進行資料外洩或 C2 通訊",
            "(C) 攻擊者修改本機 hosts 檔案",
            "(D) 攻擊者註冊大量惡意網域"
        ],
        "answer": "B",
        "note": "因為大多數防火牆會放行 DNS (UDP 53) 流量，攻擊者常利用此通道傳輸資料。"
    },
    {
        "id": "B4-Prot-18",
        "question": "下列哪一種惡意軟體分析方式，是在虛擬機或沙箱中實際執行程式，觀察其行為？",
        "options": [
            "(A) 靜態分析 (Static Analysis)",
            "(B) 動態分析 (Dynamic Analysis)",
            "(C) 原始碼審查 (Code Review)",
            "(D) 逆向工程 (Reverse Engineering)"
        ],
        "answer": "B",
        "note": "動態分析強調「執行」並觀察其網路連線、檔案修改等行為。"
    },
    {
        "id": "B4-Prot-19",
        "question": "針對雲端環境的 SSRF 攻擊，攻擊者通常試圖存取哪一個特殊的 IP 位址來獲取 Instance Metadata？",
        "options": [
            "(A) 127.0.0.1",
            "(B) 169.254.169.254",
            "(C) 192.168.1.1",
            "(D) 8.8.8.8"
        ],
        "answer": "B",
        "note": "169.254.169.254 是 AWS/GCP/Azure 等雲端平台通用的 Metadata 服務 IP，若無防護可洩漏憑證。"
    },
    {
        "id": "B4-Prot-20",
        "question": "關於區塊鏈安全，著名的「51% 攻擊」是指？",
        "options": [
            "(A) 攻擊者擁有超過 51% 的加密貨幣",
            "(B) 攻擊者掌握超過全網 51% 的算力 (Hash Rate)，可竄改交易紀錄或進行雙重支付",
            "(C) 攻擊者控制 51% 的節點數量",
            "(D) 攻擊者竊取 51% 的私鑰"
        ],
        "answer": "B",
        "note": "POW 機制下，掌握過半算力即可控制區塊鏈的最長鏈。"
    },
    // --- 綜合防護 ---
    {
        "id": "B4-Prot-21",
        "question": "在防火牆設定中，最後一條規則 (Implicit Deny) 通常應設定為？",
        "options": [
            "(A) Allow Any Any",
            "(B) Deny Any Any (或 Drop All)",
            "(C) Allow HTTP Only",
            "(D) Forward to Honeypot"
        ],
        "answer": "B",
        "note": "正面表列 (Whitelisting) 原則：只允許明確定義的流量，其餘預設全部阻擋。"
    },
    {
        "id": "B4-Prot-22",
        "question": "關於 WPA2-Enterprise (802.1X) 的認證架構，負責儲存使用者帳號密碼並進行驗證的伺服器稱為？",
        "options": [
            "(A) Supplicant (申請者)",
            "(B) Authenticator (認證者 - AP)",
            "(C) Authentication Server (認證伺服器 - 如 RADIUS)",
            "(D) DHCP Server"
        ],
        "answer": "C",
        "note": "802.1X 架構：Supplicant (用戶端) -> Authenticator (AP/Switch) -> Authentication Server (RADIUS)。"
    },
    {
        "id": "B4-Prot-23",
        "question": "下列何種工具可以用來掃描網站目錄，找出隱藏的備份檔或管理後台？",
        "options": [
            "(A) DirBuster / Gobuster",
            "(B) Wireshark",
            "(C) John the Ripper",
            "(D) Snort"
        ],
        "answer": "A",
        "note": "DirBuster/Gobuster 透過字典檔暴力猜測網站路徑與檔案。"
    },
    {
        "id": "B4-Prot-24",
        "question": "在 Windows 系統中，哪一個指令可以用來檢查檔案的完整性 (雜湊值)？",
        "options": [
            "(A) `certutil -hashfile filename SHA256`",
            "(B) `ipconfig /all`",
            "(C) `chkdisk`",
            "(D) `sfc /scannow`"
        ],
        "answer": "A",
        "note": "Certutil 是 Windows 內建強大的憑證與雜湊工具。"
    },
    {
        "id": "B4-Prot-25",
        "question": "關於「邏輯炸彈 (Logic Bomb)」的特徵，下列何者正確？",
        "options": [
            "(A) 會自我複製",
            "(B) 在滿足特定條件 (如特定日期、特定人員離職) 時觸發惡意行為",
            "(C) 是一種硬體設備",
            "(D) 專門攻擊資料庫"
        ],
        "answer": "B",
        "note": "邏輯炸彈是潛伏的惡意程式碼，等待特定觸發條件 (Trigger)。"
    },
    {
        "id": "B4-Prot-26",
        "question": "防禦 ARP Spoofing 最有效的交換器 (Switch) 功能是？",
        "options": [
            "(A) Spanning Tree Protocol (STP)",
            "(B) Dynamic ARP Inspection (DAI) 配合 DHCP Snooping",
            "(C) VLAN Tagging",
            "(D) Quality of Service (QoS)"
        ],
        "answer": "B",
        "note": "DAI 會驗證 ARP 封包是否符合 DHCP Snooping 的綁定表，防止偽造。"
    },
    {
        "id": "B4-Prot-27",
        "question": "關於「浮水印 (Watermarking)」技術在資安上的應用，主要目的是？",
        "options": [
            "(A) 加密檔案",
            "(B) 追溯資料外洩源頭 (DLP)",
            "(C) 壓縮圖片",
            "(D) 提高下載速度"
        ],
        "answer": "B",
        "note": "數位浮水印 (尤其是隱形浮水印) 可標記資料接收者，若資料外洩可追查是誰流出的。"
    },
    {
        "id": "B4-Prot-28",
        "question": "下列何者是檢測「緩衝區溢位」漏洞的常用技術？",
        "options": [
            "(A) Fuzzing (模糊測試)",
            "(B) Phishing",
            "(C) Social Engineering",
            "(D) Port Scanning"
        ],
        "answer": "A",
        "note": "Fuzzing 輸入大量隨機或異常數據，觀察程式是否崩潰 (Crash)，是發現溢位漏洞的有效方法。"
    },
    {
        "id": "B4-Prot-29",
        "question": "關於「影子 IT (Shadow IT)」的風險，下列何者正確？",
        "options": [
            "(A) 員工使用未經公司核准的軟體或雲端服務，導致資安死角",
            "(B) 公司內部的備援伺服器",
            "(C) 駭客架設的假網站",
            "(D) 暗網 (Dark Web)"
        ],
        "answer": "A",
        "note": "Shadow IT 指員工私自使用的 IT 資源，未受公司監控與保護，風險極高。"
    },
    {
        "id": "B4-Prot-30",
        "question": "在電子郵件安全中，將附件檔案轉換為安全的格式 (如將 Word 轉為 PDF 或圖片) 再傳送給使用者，這稱為？",
        "options": [
            "(A) CDR (Content Disarm and Reconstruction, 檔案清洗/重組)",
            "(B) DLP",
            "(C) EDR",
            "(D) PKI"
        ],
        "answer": "A",
        "note": "CDR 技術移除檔案中可能含有惡意代碼的動態內容 (如巨集)，只保留安全的可視內容。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch4 = [
    // --- 法規與標準 (ISO/Privacy) ---
    {
        "id": "B4-Plan-01",
        "question": "ISO 27701 是針對哪一個領域的管理系統標準？",
        "options": [
            "(A) 雲端安全",
            "(B) 隱私資訊管理 (PIMS - Privacy Information Management System)",
            "(C) 供應鏈安全",
            "(D) 營運持續管理"
        ],
        "answer": "B",
        "note": "113-2 規劃實務。ISO 27701 是 ISO 27001 的隱私延伸標準。"
    },
    {
        "id": "B4-Plan-02",
        "question": "依據 GDPR，當資料主體行使「資料可攜權 (Right to data portability)」時，企業應提供什麼格式的資料？",
        "options": [
            "(A) 加密的二進位檔",
            "(B) 紙本列印文件",
            "(C) 結構化、通用且機器可讀的格式 (如 CSV, XML, JSON)",
            "(D) 只能在該企業系統讀取的專有格式"
        ],
        "answer": "C",
        "note": "資料可攜權旨在讓使用者能輕鬆轉移資料至其他服務商。"
    },
    {
        "id": "B4-Plan-03",
        "question": "關於 ISO 27001 中的「矯正措施 (Corrective Action)」，其主要目的為？",
        "options": [
            "(A) 懲罰犯錯員工",
            "(B) 消除不符合事項的「根本原因 (Root Cause)」，防止再發生",
            "(C) 僅修正當下的錯誤",
            "(D) 掩蓋錯誤"
        ],
        "answer": "B",
        "note": "矯正措施強調治本 (Root Cause Analysis)，而不僅是治標 (Correction)。"
    },
    {
        "id": "B4-Plan-04",
        "question": "我國《電子簽章法》的主要目的是？",
        "options": [
            "(A) 規範電子商務稅收",
            "(B) 賦予電子簽章與手寫簽名或蓋章「同等法律效力」",
            "(C) 限制電子文件使用",
            "(D) 規定所有文件必須電子化"
        ],
        "answer": "B",
        "note": "114 概論教材。電子簽章法旨在確立電子文件與簽章的法律地位。"
    },
    {
        "id": "B4-Plan-05",
        "question": "關於「營業秘密法」，營業秘密必須具備哪三個要件？",
        "options": [
            "(A) 創新性、進步性、實用性",
            "(B) 秘密性、經濟價值、採取合理保密措施",
            "(C) 公開性、完整性、可用性",
            "(D) 獨特性、藝術性、原創性"
        ],
        "answer": "B",
        "note": "營業秘密三要件：非周知性 (秘密)、因秘密而具經濟價值、所有人已採取保密措施。"
    },
    // --- 風險管理進階 ---
    {
        "id": "B4-Plan-06",
        "question": "在風險評鑑方法中，「德爾菲法 (Delphi Method)」屬於哪種類型？",
        "options": [
            "(A) 定量分析",
            "(B) 定性分析 (Qualitative)",
            "(C) 自動化分析",
            "(D) 弱點掃描"
        ],
        "answer": "B",
        "note": "德爾菲法透過專家匿名問卷反覆收斂意見，屬於定性分析。"
    },
    {
        "id": "B4-Plan-07",
        "question": "關於「風險胃納 (Risk Appetite)」與「風險容忍度 (Risk Tolerance)」的關係，下列何者描述較佳？",
        "options": [
            "(A) 兩者完全相同",
            "(B) 風險胃納是廣泛的策略性水準，風險容忍度是特定情況下的具體偏差範圍",
            "(C) 風險容忍度一定大於風險胃納",
            "(D) 風險胃納是負面的，容忍度是正面的"
        ],
        "answer": "B",
        "note": "胃納是整體「願意接受多少」，容忍度是「具體可接受的偏離程度」。"
    },
    {
        "id": "B4-Plan-08",
        "question": "在進行風險評鑑時，若發現某項風險的「影響極大」但「發生機率極低」(如千年一遇的大地震)，最適合的處理策略通常是？",
        "options": [
            "(A) 風險規避 (不在此地營運)",
            "(B) 風險移轉 (購買保險)",
            "(C) 風險降低 (投入無限成本防護)",
            "(D) 忽略不計"
        ],
        "answer": "B",
        "note": "高衝擊、低機率的風險適合透過保險進行移轉。"
    },
    {
        "id": "B4-Plan-09",
        "question": "關於 OCTAVE (Operationally Critical Threat, Asset, and Vulnerability Evaluation) 風險評鑑方法，其核心特點是？",
        "options": [
            "(A) 高度依賴外部專家",
            "(B) 自行主導 (Self-Directed)，由組織內部人員組成分析團隊",
            "(C) 僅關注技術漏洞",
            "(D) 只適用於金融業"
        ],
        "answer": "B",
        "note": "OCTAVE 強調由組織內部最了解業務的人員進行自我評估。"
    },
    {
        "id": "B4-Plan-10",
        "question": "在風險處置後，剩下的風險稱為「殘餘風險」。關於殘餘風險的管理，下列何者正確？",
        "options": [
            "(A) 必須為零",
            "(B) 必須經過管理階層正式接受 (Sign-off)",
            "(C) 可以隱瞞不報",
            "(D) 不需要監控"
        ],
        "answer": "B",
        "note": "資安無法做到零風險，殘餘風險必須被識別並由高層接受。"
    },
    // --- BCP 與事故應變 ---
    {
        "id": "B4-Plan-11",
        "question": "關於資安事故的「證據監管鏈 (Chain of Custody)」，其主要目的是？",
        "options": [
            "(A) 加速系統復原",
            "(B) 證明證據從採集到呈堂的過程中未被竄改或汙染",
            "(C) 備份資料",
            "(D) 測試防毒軟體"
        ],
        "answer": "B",
        "note": "監管鏈紀錄誰、何時、如何接觸證據，確保證據在法律上的有效性。"
    },
    {
        "id": "B4-Plan-12",
        "question": "在 BCP 中，若主要資料中心全毀，啟動異地備援中心接手營運，這屬於哪一個階段的計畫？",
        "options": [
            "(A) 預防階段",
            "(B) 災難復原 (Disaster Recovery) 階段",
            "(C) 復原後測試",
            "(D) 正常營運"
        ],
        "answer": "B",
        "note": "災難復原 (DR) 專注於 IT 系統與資料在災後的恢復。"
    },
    {
        "id": "B4-Plan-13",
        "question": "關於「磁帶備份 (Tape Backup)」的 Grandfather-Father-Son (GFS) 輪替策略，其中「Grandfather」通常代表？",
        "options": [
            "(A) 每日備份",
            "(B) 每週備份",
            "(C) 每月 (或每年) 的全備份，通常永久保存",
            "(D) 增量備份"
        ],
        "answer": "C",
        "note": "Son=日, Father=週, Grandfather=月/年 (長期存檔)。"
    },
    {
        "id": "B4-Plan-14",
        "question": "資安事件發生後，召開「檢討會議 (Lessons Learned Meeting)」的最佳時機是？",
        "options": [
            "(A) 事件發生後一年",
            "(B) 只要有空再開",
            "(C) 事件處理完成後儘速召開 (如 2 週內)",
            "(D) 不需要召開"
        ],
        "answer": "C",
        "note": "應在記憶猶新時儘速召開，以利改善未來的應變能力。"
    },
    {
        "id": "B4-Plan-15",
        "question": "關於「社交工程演練」的指標，下列何者代表員工資安意識最差？",
        "options": [
            "(A) 開啟郵件率高",
            "(B) 點擊連結率高",
            "(C) 輸入帳號密碼或下載惡意附件率高",
            "(D) 回報率高"
        ],
        "answer": "C",
        "note": "輸入帳密或下載執行檔代表員工完全落入陷阱，風險最高；回報率高代表意識好。"
    },
    // --- 治理與開發 ---
    {
        "id": "B4-Plan-16",
        "question": "在 SSDLC (安全軟體開發生命週期) 中，開發人員應遵循「OWASP Top 10」進行開發，這主要是在哪一個階段？",
        "options": [
            "(A) 需求分析",
            "(B) 實作 (Implementation / Coding)",
            "(C) 部署",
            "(D) 維運"
        ],
        "answer": "B",
        "note": "開發人員在 Coding 階段應遵循安全編碼規範 (如防禦 SQLi, XSS)。"
    },
    {
        "id": "B4-Plan-17",
        "question": "關於「源碼檢測 (Static Application Security Testing, SAST)」與「動態檢測 (DAST)」的比較，下列何者正確？",
        "options": [
            "(A) SAST 需要將程式編譯並執行後才能檢測",
            "(B) DAST 是對執行中的應用程式進行黑箱測試",
            "(C) SAST 誤報率通常極低",
            "(D) DAST 可以指出程式碼的具體行號"
        ],
        "answer": "B",
        "note": "SAST 測原始碼 (白箱)；DAST 測執行環境 (黑箱)。"
    },
    {
        "id": "B4-Plan-18",
        "question": "在 DevOps 流程中加入資安檢測，被稱為？",
        "options": [
            "(A) SecDevOps",
            "(B) DevSecOps",
            "(C) OpsSecDev",
            "(D) Agile Security"
        ],
        "answer": "B",
        "note": "DevSecOps 強調「安全人人有責」，將資安整合進 CI/CD 流程。"
    },
    {
        "id": "B4-Plan-19",
        "question": "關於「開源軟體 (Open Source)」的使用風險，下列何者是管理重點？",
        "options": [
            "(A) 授權合規性 (License Compliance) 與 已知漏洞 (Vulnerabilities)",
            "(B) 開源軟體通常沒有功能",
            "(C) 開源軟體不能用於商業用途",
            "(D) 開源軟體沒有原始碼"
        ],
        "answer": "A",
        "note": "使用開源需注意 License (如 GPL 傳染性) 與 CVE 漏洞修補。"
    },
    {
        "id": "B4-Plan-20",
        "question": "在資安稽核中，若稽核員發現受稽方為了應付稽核而臨時補做紀錄（偽造紀錄），應如何處理？",
        "options": [
            "(A) 視為符合",
            "(B) 列為嚴重不符合事項 (Major Non-conformity) 並可能涉及法律責任",
            "(C) 睜一隻眼閉一隻眼",
            "(D) 只要紀錄完整就好"
        ],
        "answer": "B",
        "note": "誠信是稽核的基礎，偽造紀錄是嚴重的違規行為。"
    },
    // --- 綜合情境題 ---
    {
        "id": "B4-Plan-21",
        "question": "公司欲導入 BYOD (員工自攜設備)，為了保障公司資料安全，應優先導入何種系統？",
        "options": [
            "(A) ERP",
            "(B) CRM",
            "(C) MDM (Mobile Device Management) / MAM (Mobile Application Management)",
            "(D) DNS Server"
        ],
        "answer": "C",
        "note": "MDM/MAM 可將公司資料與私人資料隔離 (Containerization)，並實施安全政策。"
    },
    {
        "id": "B4-Plan-22",
        "question": "依據 NIST CSF，資安事件發生後的「溝通 (Communications)」屬於哪一個功能範疇？",
        "options": [
            "(A) Protect",
            "(B) Detect",
            "(C) Respond",
            "(D) Recover"
        ],
        "answer": "C",
        "note": "Respond (回應) 功能包含 Response Planning, Communications, Analysis 等。"
    },
    {
        "id": "B4-Plan-23",
        "question": "在供應鏈資安中，若供應商需要遠端連線進入公司維護系統，下列要求何者最為重要？",
        "options": [
            "(A) 給予 Domain Admin 權限方便做事",
            "(B) 開放 Any-to-Any 防火牆規則",
            "(C) 採用 VPN 搭配 MFA，並限制來源 IP 與存取範圍，且全程側錄",
            "(D) 使用 TeamViewer 並共用密碼"
        ],
        "answer": "C",
        "note": "嚴格的遠端存取管控是防範供應商跳板攻擊的關鍵。"
    },
    {
        "id": "B4-Plan-24",
        "question": "關於「資料外洩防護 (DLP)」系統，主要功能不包括？",
        "options": [
            "(A) 偵測含有個資或機密的檔案外傳",
            "(B) 阻擋 USB 存取",
            "(C) 掃描端點電腦中的敏感資料",
            "(D) 修補作業系統漏洞"
        ],
        "answer": "D",
        "note": "修補漏洞是 Patch Management 的工作，非 DLP 功能。"
    },
    {
        "id": "B4-Plan-25",
        "question": "在資安教育訓練中，針對「高階主管」的課程重點應為何？",
        "options": [
            "(A) 防火牆指令操作",
            "(B) 程式碼撰寫技巧",
            "(C) 資安治理、風險管理與決策支持",
            "(D) 伺服器安裝"
        ],
        "answer": "C",
        "note": "不同角色需接受不同訓練，高階主管需了解風險與治理責任。"
    },
    {
        "id": "B4-Plan-26",
        "question": "關於「社交工程」的防範，下列何者屬於「技術性」控制措施？",
        "options": [
            "(A) 員工資安意識培訓",
            "(B) 電子郵件閘道器的防垃圾郵件與防釣魚過濾功能",
            "(C) 制定社交工程防範政策",
            "(D) 定期演練"
        ],
        "answer": "B",
        "note": "A/C/D 屬於管理/行政控制，B 屬於技術控制。"
    },
    {
        "id": "B4-Plan-27",
        "question": "在個資保護管理制度 (PIMS) 中，DPIA (Data Protection Impact Assessment) 應在何時進行？",
        "options": [
            "(A) 發生外洩事件後",
            "(B) 在進行高風險的個資處理活動「之前」",
            "(C) 每年年底",
            "(D) 收到罰單時"
        ],
        "answer": "B",
        "note": "DPIA 應在專案規劃階段或變更前進行，以識別並降低隱私風險 (Privacy by Design)。"
    },
    {
        "id": "B4-Plan-28",
        "question": "關於 ISO 27001 的「持續改善 (Continual Improvement)」，下列何者是主要依據？",
        "options": [
            "(A) 稽核結果與管理審查決議",
            "(B) 員工的直覺",
            "(C) 廠商的廣告",
            "(D) 網路新聞"
        ],
        "answer": "A",
        "note": "依據稽核發現的不符合事項與管理審查的決策來推動改善。"
    },
    {
        "id": "B4-Plan-29",
        "question": "在資通安全維護計畫中，「核心業務」的定義通常參考什麼？",
        "options": [
            "(A) 員工喜好",
            "(B) BIA (營運衝擊分析) 的結果",
            "(C) 設備的價格",
            "(D) 軟體的版本"
        ],
        "answer": "B",
        "note": "BIA 分析業務中斷的衝擊，藉此識別出哪些是核心業務。"
    },
    {
        "id": "B4-Plan-30",
        "question": "關於「權限審查 (Access Review)」，一般建議的執行頻率至少為？",
        "options": [
            "(A) 從不審查",
            "(B) 每 10 年一次",
            "(C) 定期審查 (如每半年或一年)，且人員異動時立即審查",
            "(D) 只有發生弊案時才審查"
        ],
        "answer": "C",
        "note": "定期審查可確保權限符合現況，移除離職或轉調人員的權限。"
    }
];

// 將 Batch 4 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch4);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch4);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第五批次 (Batch 5)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：雲端安全架構、無線安全、ISO 27001 條文細節、SSDLC 實務
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch5 = [
    // --- 雲端與新興技術安全 ---
    {
        "id": "B5-Prot-01",
        "question": "關於 CSPM (Cloud Security Posture Management) 的主要功能，下列何者正確？",
        "options": [
            "(A) 掃描雲端基礎設施的組態設定，識別錯誤配置 (Misconfiguration) 與合規風險",
            "(B) 保護執行中的雲端工作負載 (Workload)",
            "(C) 提供網頁應用程式防火牆功能",
            "(D) 管理使用者帳號權限"
        ],
        "answer": "A",
        "note": "CSPM 專注於「組態管理」與「合規性檢查」，防止因設定錯誤導致的資料外洩。"
    },
    {
        "id": "B5-Prot-02",
        "question": "CWPP (Cloud Workload Protection Platform) 與 CSPM 的主要區別為何？",
        "options": [
            "(A) CWPP 專注於保護虛擬機、容器等「運算負載」的執行時期安全；CSPM 專注於「雲端平台組態」",
            "(B) CWPP 用於防毒，CSPM 用於防火牆",
            "(C) 兩者功能完全相同，只是廠商命名不同",
            "(D) CWPP 僅適用於私有雲"
        ],
        "answer": "A",
        "note": "CWPP 保護的是 Workload (OS/App) 層面；CSPM 保護的是 Cloud Infrastructure (AWS/Azure 設定) 層面。"
    },
    {
        "id": "B5-Prot-03",
        "question": "在 MQTT (Message Queuing Telemetry Transport) 物聯網協定中，為了確保傳輸安全，應採用何種機制？",
        "options": [
            "(A) 使用預設的 TCP 1883 Port",
            "(B) 僅依賴 Client ID 認證",
            "(C) 使用 MQTTS (MQTT over TLS/SSL) 並啟用帳號密碼或憑證認證",
            "(D) MQTT 本身無法加密"
        ],
        "answer": "C",
        "note": "MQTT 明文傳輸極不安全，必須透過 TLS (Port 8883) 進行加密封裝。"
    },
    {
        "id": "B5-Prot-04",
        "question": "關於 Android 系統的「Root」與 iOS 系統的「Jailbreak (越獄)」，對企業資安的主要風險為何？",
        "options": [
            "(A) 會讓手機變慢",
            "(B) 破壞系統沙箱 (Sandbox) 機制，導致惡意程式可存取其他 App 的敏感資料",
            "(C) 無法使用相機功能",
            "(D) 增加電池消耗"
        ],
        "answer": "B",
        "note": "沙箱是行動裝置安全的核心，Root/Jailbreak 會打破此隔離機制。"
    },
    {
        "id": "B5-Prot-05",
        "question": "在資料庫安全中，針對「推論攻擊 (Inference Attack)」的防禦，下列何者較為有效？",
        "options": [
            "(A) 資料加密",
            "(B) 存取控制與資料微擾 (Perturbation) / 差分隱私 (Differential Privacy)",
            "(C) 備份資料庫",
            "(D) 使用防火牆"
        ],
        "answer": "B",
        "note": "推論攻擊是透過分析非敏感資料推導出敏感資訊，需透過統計控制或差分隱私來防禦。"
    },
    // --- 網路攻防技術 ---
    {
        "id": "B5-Prot-06",
        "question": "攻擊者架設一個 SSID 與合法 AP 相同的偽造無線基地台，誘使使用者連線以竊取資料，這稱為？",
        "options": [
            "(A) Evil Twin Attack (邪惡雙子星)",
            "(B) Rogue AP (非法 AP)",
            "(C) War Driving",
            "(D) Bluejacking"
        ],
        "answer": "A",
        "note": "Rogue AP 是未經授權的 AP；Evil Twin 是刻意偽裝成合法 AP 進行釣魚的攻擊。"
    },
    {
        "id": "B5-Prot-07",
        "question": "在 Wireshark 中，若要篩選「包含字串 'password'」的封包，應使用哪個過濾器？",
        "options": [
            "(A) ip.addr == password",
            "(B) frame contains \"password\"",
            "(C) tcp.port == password",
            "(D) http.request"
        ],
        "answer": "B",
        "note": "`frame contains` 或 `matches` 指令可用於搜尋 Payload 內容。"
    },
    {
        "id": "B5-Prot-08",
        "question": "關於 Snort 入侵偵測系統的規則 (Rule)，下列語法 `alert tcp any any -> 192.168.1.0/24 80` 代表什麼意思？",
        "options": [
            "(A) 阻擋所有到 192.168.1.0/24 Port 80 的 TCP 流量",
            "(B) 對所有從任意來源 IP/Port 到 192.168.1.0/24 Port 80 的 TCP 流量發出警報",
            "(C) 允許所有 HTTP 流量",
            "(D) 紀錄所有 UDP 流量"
        ],
        "answer": "B",
        "note": "`alert` 動作是發出警報；`->` 代表方向；`any any` 代表任意來源 IP 與 Port。"
    },
    {
        "id": "B5-Prot-09",
        "question": "下列哪一種攻擊是利用 IP 封包的「分段 (Fragmentation)」機制，試圖躲避 IDS/IPS 的偵測？",
        "options": [
            "(A) Teardrop Attack",
            "(B) Fragmentation Evasion / IP Fragmentation Attack",
            "(C) Smurf Attack",
            "(D) SYN Flood"
        ],
        "answer": "B",
        "note": "攻擊者將惡意 Payload 切割成微小片段，使 IDS 無法在單一封包中識別特徵碼，需透過重組 (Reassembly) 防禦。"
    },
    {
        "id": "B5-Prot-10",
        "question": "關於「隱寫術 (Steganography)」在資安攻擊中的應用，下列何者正確？",
        "options": [
            "(A) 用來加密硬碟",
            "(B) 將惡意程式碼或機敏資料隱藏在圖片、音訊等看似正常的檔案中，以躲避偵測",
            "(C) 用來壓縮檔案",
            "(D) 用來修復損毀的圖片"
        ],
        "answer": "B",
        "note": "隱寫術不同於加密，它是「隱藏資訊的存在」，常用於 C2 通訊或資料外洩。"
    },
    // --- 密碼學與弱點 ---
    {
        "id": "B5-Prot-11",
        "question": "Heartbleed (心臟出血) 漏洞是發生在下列哪一個函式庫的重大弱點？",
        "options": [
            "(A) OpenSSH",
            "(B) OpenSSL",
            "(C) Apache",
            "(D) Nginx"
        ],
        "answer": "B",
        "note": "Heartbleed (CVE-2014-0160) 是 OpenSSL 實作 TLS Heartbeat 擴充功能的緩衝區讀取過度漏洞。"
    },
    {
        "id": "B5-Prot-12",
        "question": "POODLE (Padding Oracle On Downgraded Legacy Encryption) 攻擊主要是針對哪一個協定的弱點？",
        "options": [
            "(A) TLS 1.2",
            "(B) SSL v3.0",
            "(C) SSH v2",
            "(D) IPsec"
        ],
        "answer": "B",
        "note": "POODLE 攻擊迫使瀏覽器降級使用 SSL v3.0，進而利用其 CBC 模式的填充弱點解密資料。"
    },
    {
        "id": "B5-Prot-13",
        "question": "相較於 RSA，橢圓曲線密碼學 (ECC) 的主要優勢為何？",
        "options": [
            "(A) 演算法更簡單",
            "(B) 在提供相同安全強度的情況下，所需的金鑰長度更短，運算效率更高",
            "(C) 不需要私鑰",
            "(D) 只能用於數位簽章"
        ],
        "answer": "B",
        "note": "例如 256-bit ECC 的安全性約等於 3072-bit RSA，適合行動裝置或 IoT。"
    },
    {
        "id": "B5-Prot-14",
        "question": "關於 Padding Oracle Attack，攻擊者利用的是伺服器在解密失敗時回傳的什麼資訊？",
        "options": [
            "(A) 密碼錯誤訊息",
            "(B) 填充 (Padding) 是否正確的錯誤訊息",
            "(C) 時間戳記",
            "(D) 伺服器版本"
        ],
        "answer": "B",
        "note": "攻擊者根據伺服器回應的 Padding Error 差異，逐步推導出明文內容。"
    },
    {
        "id": "B5-Prot-15",
        "question": "下列何者不是「混淆 (Obfuscation)」技術的主要目的？",
        "options": [
            "(A) 增加逆向工程的難度",
            "(B) 保護智慧財產權",
            "(C) 提升程式執行效能",
            "(D) 讓惡意程式躲避防毒軟體特徵偵測"
        ],
        "answer": "C",
        "note": "混淆通常會增加程式碼複雜度，反而可能稍微降低效能。"
    },
    // --- 身分認證與存取控制 ---
    {
        "id": "B5-Prot-16",
        "question": "在 SAML (Security Assertion Markup Language) 協定中，負責驗證使用者身分並發出斷言 (Assertion) 的角色是？",
        "options": [
            "(A) Service Provider (SP)",
            "(B) Identity Provider (IdP)",
            "(C) User Agent",
            "(D) Relying Party"
        ],
        "answer": "B",
        "note": "IdP (身分提供者) 負責認證；SP (服務提供者) 信任 IdP 發出的 Assertion。"
    },
    {
        "id": "B5-Prot-17",
        "question": "OIDC (OpenID Connect) 是基於哪一個授權協定之上建立的身分認證層？",
        "options": [
            "(A) OAuth 2.0",
            "(B) SAML 2.0",
            "(C) LDAP",
            "(D) Kerberos"
        ],
        "answer": "A",
        "note": "OAuth 2.0 僅處理授權，OIDC 在其之上增加了 ID Token 來處理身分認證。"
    },
    {
        "id": "B5-Prot-18",
        "question": "關於 PKI 中的 OCSP (Online Certificate Status Protocol)，其優點相較於 CRL 為何？",
        "options": [
            "(A) 可以離線使用",
            "(B) 提供即時的憑證狀態查詢，不需要下載龐大的清單",
            "(C) 不需要 CA 參與",
            "(D) 安全性較低"
        ],
        "answer": "B",
        "note": "OCSP 解決了 CRL 更新延遲與檔案過大的問題，提供即時撤銷檢查。"
    },
    {
        "id": "B5-Prot-19",
        "question": "在零信任架構中，負責決定是否允許存取請求的邏輯元件是？",
        "options": [
            "(A) PEP (Policy Enforcement Point)",
            "(B) PDP (Policy Decision Point)",
            "(C) PIP (Policy Information Point)",
            "(D) PAP (Policy Administration Point)"
        ],
        "answer": "B",
        "note": "PDP (決策點) 負責運算判斷；PEP (執行點) 負責實際阻擋或放行。"
    },
    {
        "id": "B5-Prot-20",
        "question": "關於「憑證透明度 (Certificate Transparency, CT)」的目的，下列何者正確？",
        "options": [
            "(A) 公開所有使用者的密碼",
            "(B) 提供一個公開的日誌系統，記錄所有 CA 簽發的憑證，以防止 CA 誤發或濫發憑證",
            "(C) 讓憑證過期時間透明化",
            "(D) 加速 HTTPS 連線"
        ],
        "answer": "B",
        "note": "CT Log 讓網域擁有者能監控是否有未經授權的 CA 為其網域簽發了憑證。"
    },
    // --- 綜合防護技術 ---
    {
        "id": "B5-Prot-21",
        "question": "在實體安全中，使用金屬網屏蔽空間以阻擋無線電訊號洩漏的設施稱為？",
        "options": [
            "(A) 防火牆",
            "(B) 雙重門 (Mantrap)",
            "(C) 法拉第籠 (Faraday Cage)",
            "(D) 氣隙 (Air Gap)"
        ],
        "answer": "C",
        "note": "法拉第籠利用導電材料屏蔽電磁場，防止電子訊號進出。"
    },
    {
        "id": "B5-Prot-22",
        "question": "關於模糊測試 (Fuzzing) 中的「Mutation-based (變異型)」方法，是指？",
        "options": [
            "(A) 根據協定規格從頭產生測試資料",
            "(B) 修改現有的合法樣本資料（如翻轉位元、插入字串）來產生測試資料",
            "(C) 人工手動輸入測試資料",
            "(D) 使用靜態分析工具"
        ],
        "answer": "B",
        "note": "Mutation-based (變異) vs Generation-based (生成，依規範產生)。"
    },
    {
        "id": "B5-Prot-23",
        "question": "WAF 的部屬模式中，哪一種模式可以阻擋攻擊，但不需要更改現有網路架構 IP 設定？",
        "options": [
            "(A) Reverse Proxy (反向代理)",
            "(B) Transparent / Bridge Mode (通透/橋接模式)",
            "(C) Sniffer Mode (監聽模式)",
            "(D) Router Mode"
        ],
        "answer": "B",
        "note": "橋接模式如同隱形線路，不需更動 IP，且具備阻擋能力；監聽模式無法阻擋。"
    },
    {
        "id": "B5-Prot-24",
        "question": "攻擊者利用社交工程手段，緊隨在合法人員身後進入門禁管制區域，這種行為稱為？",
        "options": [
            "(A) Dumpster Diving",
            "(B) Shoulder Surfing",
            "(C) Tailgating / Piggybacking",
            "(D) Phishing"
        ],
        "answer": "C",
        "note": "Tailgating (未經同意跟隨) / Piggybacking (經同意或默許跟隨)。"
    },
    {
        "id": "B5-Prot-25",
        "question": "關於 DNS Sinkhole 技術的用途，下列何者正確？",
        "options": [
            "(A) 加速 DNS 解析",
            "(B) 將惡意網域的 DNS 查詢回應導向到一個受控的 IP (如 127.0.0.1 或分析伺服器)，以阻斷 C2 連線",
            "(C) 備份 DNS 紀錄",
            "(D) 防止 DDoS 攻擊"
        ],
        "answer": "B",
        "note": "DNS Sinkhole 是阻斷殭屍網路與惡意軟體連線的有效技術。"
    },
    {
        "id": "B5-Prot-26",
        "question": "在 Windows 系統中，為了防止記憶體鑑識，攻擊者可能會使用什麼技術隱藏惡意程式？",
        "options": [
            "(A) DLL Injection",
            "(B) Fileless Malware (無檔案惡意軟體) / Process Hollowing",
            "(C) Disk Encryption",
            "(D) Event Log Clearing"
        ],
        "answer": "B",
        "note": "無檔案攻擊直接在記憶體中執行，不落地硬碟，增加鑑識難度。"
    },
    {
        "id": "B5-Prot-27",
        "question": "關於 Burp Suite 的 `Intruder` 模組，主要功能為何？",
        "options": [
            "(A) 攔截並修改單一請求",
            "(B) 自動化發送大量請求，用於暴力破解、參數列舉或 Fuzzing",
            "(C) 掃描網站漏洞",
            "(D) 解碼 Base64"
        ],
        "answer": "B",
        "note": "Intruder 是強大的自動化攻擊載荷 (Payload) 發送工具。"
    },
    {
        "id": "B5-Prot-28",
        "question": "下列何者是防禦「旁路攻擊 (Side-channel Attack)」(如測量電力消耗、執行時間) 的方法？",
        "options": [
            "(A) 增加金鑰長度",
            "(B) 實作常數時間演算法 (Constant-time algorithm) 與遮罩技術",
            "(C) 使用防火牆",
            "(D) 定期更換密碼"
        ],
        "answer": "B",
        "note": "旁路攻擊利用物理洩漏資訊，需透過程式碼均勻化執行時間或硬體遮罩來防禦。"
    },
    {
        "id": "B5-Prot-29",
        "question": "關於「網路隔離 (Network Segmentation)」的好處，下列何者錯誤？",
        "options": [
            "(A) 限制攻擊者的橫向移動範圍",
            "(B) 縮小廣播網域，提升效能",
            "(C) 完全消除所有資安風險",
            "(D) 能夠針對不同區域套用不同的安全政策"
        ],
        "answer": "C",
        "note": "沒有任何措施能「完全消除」風險，只能降低風險。"
    },
    {
        "id": "B5-Prot-30",
        "question": "在資安鑑識中，Windows 的 `Prefetch` 檔案可以用來分析什麼？",
        "options": [
            "(A) 網路連線紀錄",
            "(B) 應用程式的執行歷史 (曾執行過什麼程式、執行時間、執行次數)",
            "(C) 使用者密碼",
            "(D) 瀏覽器歷史紀錄"
        ],
        "answer": "B",
        "note": "Prefetch 旨在加速開機，但也留下了程式執行的詳細痕跡，是鑑識重點。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch5 = [
    // --- ISO 27001 條文與實務 ---
    {
        "id": "B5-Plan-01",
        "question": "在 ISO 27001:2022 中，Clause 4 (組織全景) 要求組織確定相關利害關係人 (Interested Parties) 的什麼？",
        "options": [
            "(A) 姓名與電話",
            "(B) 需求與期望 (Needs and expectations)",
            "(C) 薪資結構",
            "(D) 登入密碼"
        ],
        "answer": "B",
        "note": "Clause 4.2 理解利害關係人的需求與期望，是決定 ISMS 範圍的基礎。"
    },
    {
        "id": "B5-Plan-02",
        "question": "ISO 27001 Clause 5 (領導統御) 強調最高管理階層必須建立什麼？",
        "options": [
            "(A) 防火牆規則",
            "(B) 資訊安全政策 (Information Security Policy)",
            "(C) 網路拓撲圖",
            "(D) 採購清單"
        ],
        "answer": "B",
        "note": "建立資安政策並確保其與組織策略方向一致，是領導階層的責任。"
    },
    {
        "id": "B5-Plan-03",
        "question": "ISO 27001 Clause 7 (支援) 中，「認知 (Awareness)」要求工作人員應知曉什麼？",
        "options": [
            "(A) 公司的獲利狀況",
            "(B) 資安政策、其對 ISMS 有效性的貢獻、以及不符合要求的後果",
            "(C) 所有伺服器的管理員密碼",
            "(D) 稽核員的姓名"
        ],
        "answer": "B",
        "note": "認知訓練重點在於讓員工了解政策、自身責任及違規後果。"
    },
    {
        "id": "B5-Plan-04",
        "question": "ISO 27001 Clause 9 (績效評估) 規定「管理審查 (Management Review)」應由誰主持？",
        "options": [
            "(A) 外部稽核員",
            "(B) 最高管理階層 (Top Management)",
            "(C) IT 部門主管",
            "(D) 總務部門"
        ],
        "answer": "B",
        "note": "管理審查是最高管理階層確保 ISMS 持續適用、適切及有效的機制。"
    },
    {
        "id": "B5-Plan-05",
        "question": "在 ISO 27001 中，「矯正措施 (Corrective Action)」應在何時執行？",
        "options": [
            "(A) 每年年初",
            "(B) 當發生不符合事項 (Nonconformity) 時",
            "(C) 只有在外部稽核時",
            "(D) 隨時隨地"
        ],
        "answer": "B",
        "note": "Clause 10.1 規定當不符合事項發生時，應採取矯正措施消除根因。"
    },
    // --- 風險評鑑與管理 ---
    {
        "id": "B5-Plan-06",
        "question": "FAIR (Factor Analysis of Information Risk) 是一種什麼樣的風險評估模型？",
        "options": [
            "(A) 純質化 (Qualitative) 模型",
            "(B) 量化 (Quantitative) 模型，將風險轉換為財務損失金額",
            "(C) 僅適用於政府機關",
            "(D) 僅關注弱點掃描"
        ],
        "answer": "B",
        "note": "FAIR 是目前國際通用的量化風險分析標準，能計算出風險的財務衝擊。"
    },
    {
        "id": "B5-Plan-07",
        "question": "在風險處理中，決定實施控制措施 (如導入 DLP) 以減少資料外洩機率，這屬於？",
        "options": [
            "(A) 風險規避",
            "(B) 風險降低 (Risk Modification/Reduction)",
            "(C) 風險移轉",
            "(D) 風險保留"
        ],
        "answer": "B",
        "note": "導入控制措施來改變風險的可能性或衝擊，稱為風險降低/修改。"
    },
    {
        "id": "B5-Plan-08",
        "question": "關於「風險擁有者 (Risk Owner)」，下列敘述何者正確？",
        "options": [
            "(A) 一定是資安部門主管",
            "(B) 有權限與責任管理該風險，並有權批准風險處理計畫的人",
            "(C) 發現風險的人",
            "(D) 造成風險的人"
        ],
        "answer": "B",
        "note": "Risk Owner 通常是資產擁有者或業務主管，對風險決策負責。"
    },
    {
        "id": "B5-Plan-09",
        "question": "進行風險評鑑時，若缺乏歷史數據，通常會優先採用哪種方法？",
        "options": [
            "(A) 定量分析 (Quantitative)",
            "(B) 定性分析 (Qualitative，如高/中/低矩陣)",
            "(C) 擲硬幣",
            "(D) 忽略不計"
        ],
        "answer": "B",
        "note": "定性分析依賴專家經驗判斷，適合數據不足或需快速評估的場景。"
    },
    {
        "id": "B5-Plan-10",
        "question": "資產價值的評估通常基於該資產的什麼屬性？",
        "options": [
            "(A) 購買價格",
            "(B) C.I.A. (機密性、完整性、可用性) 對業務的衝擊程度",
            "(C) 重量",
            "(D) 品牌"
        ],
        "answer": "B",
        "note": "資產價值取決於其喪失 CIA 特性時對組織造成的損害。"
    },
    // --- 法規 (GDPR/個資法) ---
    {
        "id": "B5-Plan-11",
        "question": "在 GDPR 中，「資料控制者 (Data Controller)」與「資料處理者 (Data Processor)」的區別為？",
        "options": [
            "(A) 沒有區別",
            "(B) Controller 決定處理的目的與手段；Processor 代表 Controller 處理資料",
            "(C) Processor 權力比 Controller 大",
            "(D) Controller 只能是政府機關"
        ],
        "answer": "B",
        "note": "Controller 是主導者 (業主)，Processor 是被委託者 (如雲端服務商、外包商)。"
    },
    {
        "id": "B5-Plan-12",
        "question": "GDPR 要求的「Privacy by Design (設計私隱)」是指？",
        "options": [
            "(A) 產品開發完成後再加裝隱私功能",
            "(B) 在系統設計的初期階段就將隱私保護納入考量，並預設開啟隱私保護",
            "(C) 只在隱私權政策中寫明",
            "(D) 隱藏所有設計圖"
        ],
        "answer": "B",
        "note": "隱私應是預設值 (Default) 且嵌入設計 (Design) 之中。"
    },
    {
        "id": "B5-Plan-13",
        "question": "依據台灣個人資料保護法，公務機關違反本法規定，致個人資料遭不法蒐集、處理、利用或其他侵害當事人權利者，負有什麼責任？",
        "options": [
            "(A) 僅行政責任",
            "(B) 損害賠償責任 (國家賠償)",
            "(C) 無責任",
            "(D) 廠商責任"
        ],
        "answer": "B",
        "note": "公務機關適用國家賠償法；非公務機關適用民事賠償。"
    },
    {
        "id": "B5-Plan-14",
        "question": "資通安全管理法中，關於「資通安全長」的設置，下列何者正確？",
        "options": [
            "(A) 只有 A 級機關需要",
            "(B) 公務機關應指派副首長或適當人員兼任",
            "(C) 必須由外聘顧問擔任",
            "(D) 特定非公務機關不需要"
        ],
        "answer": "B",
        "note": "資安法規定公務機關應置資通安全長，由副首長或適當人員兼任；特定非公務機關亦有相應規定。"
    },
    {
        "id": "B5-Plan-15",
        "question": "關於「資通安全維護計畫」的實施情形，公務機關應於何時提出？",
        "options": [
            "(A) 每月",
            "(B) 每年",
            "(C) 每兩年",
            "(D) 發生事故後"
        ],
        "answer": "B",
        "note": "實施情形應「每年」向上級或主管機關提出。"
    },
    // --- SSDLC 與開發安全 ---
    {
        "id": "B5-Plan-16",
        "question": "在 SSDLC 的「需求階段」，最重要的資安活動是？",
        "options": [
            "(A) 滲透測試",
            "(B) 定義安全需求 (Security Requirements) 與風險評估",
            "(C) 原始碼掃描",
            "(D) 購買防火牆"
        ],
        "answer": "B",
        "note": "需求階段需確認系統需要什麼等級的保護、合規需求等。"
    },
    {
        "id": "B5-Plan-17",
        "question": "在 SSDLC 的「設計階段」，進行「威脅建模 (Threat Modeling)」的主要產出為何？",
        "options": [
            "(A) 完整的程式碼",
            "(B) 識別潛在的威脅、攻擊路徑與緩解措施",
            "(C) 測試報告",
            "(D) 系統手冊"
        ],
        "answer": "B",
        "note": "威脅建模 (如 STRIDE) 產出潛在威脅列表與對應的緩解計畫。"
    },
    {
        "id": "B5-Plan-18",
        "question": "在 SSDLC 的「開發 (Coding) 階段」，應優先執行哪種檢測？",
        "options": [
            "(A) 滲透測試",
            "(B) 靜態原始碼分析 (SAST) 與安全編碼規範審查",
            "(C) 弱點掃描",
            "(D) 效能測試"
        ],
        "answer": "B",
        "note": "SAST 可在開發當下即時發現程式碼漏洞 (如 SQLi, XSS)。"
    },
    {
        "id": "B5-Plan-19",
        "question": "在 SSDLC 的「測試階段」，動態應用程式安全測試 (DAST) 的特點是？",
        "options": [
            "(A) 需要看原始碼",
            "(B) 模擬駭客從外部對執行中的應用程式進行攻擊測試",
            "(C) 只能在系統上線後做",
            "(D) 檢查編譯器版本"
        ],
        "answer": "B",
        "note": "DAST 是黑箱測試，測試執行時期的行為。"
    },
    {
        "id": "B5-Plan-20",
        "question": "關於「開源軟體風險管理」，除了漏洞外，還需特別注意什麼？",
        "options": [
            "(A) 軟體介面美觀",
            "(B) 授權條款合規性 (License Compliance)",
            "(C) 下載速度",
            "(D) 作者國籍"
        ],
        "answer": "B",
        "note": "開源授權 (如 GPL) 可能要求強制開源衍生作品，具法律風險。"
    },
    // --- 營運持續 (BCP) 細節 ---
    {
        "id": "B5-Plan-21",
        "question": "在 BCP 中，WRT (Work Recovery Time) 是指？",
        "options": [
            "(A) 系統修復的時間",
            "(B) 系統恢復後，驗證資料、追趕積壓工作直到業務完全恢復正常所需的時間",
            "(C) 員工休息時間",
            "(D) 備份資料所需時間"
        ],
        "answer": "B",
        "note": "RTO (系統恢復) + WRT (業務恢復) = MTPD (最大容忍中斷)。"
    },
    {
        "id": "B5-Plan-22",
        "question": "關於「冷站 (Cold Site)」，下列敘述何者正確？",
        "options": [
            "(A) 設備齊全，資料即時同步",
            "(B) 僅提供機房空間、電力、空調與網路線路，無電腦設備",
            "(C) 位於寒帶地區",
            "(D) 隨時可以切換運作"
        ],
        "answer": "B",
        "note": "冷站成本最低，但復原時間 (RTO) 最長，需數週時間準備設備與資料。"
    },
    {
        "id": "B5-Plan-23",
        "question": "BCP 演練中的「模擬演練 (Simulation)」是指？",
        "options": [
            "(A) 紙上談兵",
            "(B) 實際中斷系統",
            "(C) 創造一個模擬的災害情境，讓應變團隊在不影響實際運作下，實際執行通報與決策流程",
            "(D) 用電腦軟體跑模擬"
        ],
        "answer": "C",
        "note": "模擬演練比桌面演練更真實，但不像全面中斷測試那樣高風險。"
    },
    {
        "id": "B5-Plan-24",
        "question": "關於資產管理中的「資訊分級」，下列何者是正確的流程？",
        "options": [
            "(A) 先加密再分級",
            "(B) 盤點資產 -> 建立分級標準 -> 標示資產等級 -> 實施對應保護",
            "(C) 只有機密資料需要盤點",
            "(D) 由 IT 部門全權決定所有資料等級"
        ],
        "answer": "B",
        "note": "先盤點才知道有什麼，再分級才知道保護重點，最後標示與實施控制。"
    },
    {
        "id": "B5-Plan-25",
        "question": "關於 ISC2 Code of Ethics，首要原則是？",
        "options": [
            "(A) 保護委託人利益",
            "(B) 保護社會、公共利益、公眾信任與基礎設施",
            "(C) 誠實與公正",
            "(D) 提升專業聲譽"
        ],
        "answer": "B",
        "note": "保護社會大眾與公共利益是資安專業人員的首要道德責任。"
    },
    // --- 綜合管理 ---
    {
        "id": "B5-Plan-26",
        "question": "關於「社交工程演練」的頻率，A 級公務機關的規定是？",
        "options": [
            "(A) 每年 1 次",
            "(B) 每半年 1 次",
            "(C) 每 2 年 1 次",
            "(D) 每月 1 次"
        ],
        "answer": "B",
        "note": "114 概論教材。A 級機關社交工程演練頻率為「每半年」一次。"
    },
    {
        "id": "B5-Plan-27",
        "question": "在資安事件處理中，關於「監管鏈 (Chain of Custody)」的維護，下列何者最重要？",
        "options": [
            "(A) 盡快分析證據",
            "(B) 詳細記錄證據的取得、移交、保管人員、時間與地點，確保證據未被汙染",
            "(C) 將證據複製多份",
            "(D) 將證據上傳雲端"
        ],
        "answer": "B",
        "note": "完整的監管鏈紀錄是確保數位證據具有法律效力的關鍵。"
    },
    {
        "id": "B5-Plan-28",
        "question": "關於「供應商風險評估」，下列何者不是評估重點？",
        "options": [
            "(A) 供應商的財務狀況 (是否會倒閉)",
            "(B) 供應商的資安認證 (ISO 27001)",
            "(C) 供應商的員工旅遊地點",
            "(D) 供應商對資料的存取權限與保護措施"
        ],
        "answer": "C",
        "note": "財務穩定性涉及營運持續風險，資安認證與管控措施涉及資安風險。"
    },
    {
        "id": "B5-Plan-29",
        "question": "在進行「管理審查 (Management Review)」時，輸入資訊 (Input) 通常不包含？",
        "options": [
            "(A) 稽核結果",
            "(B) 利害關係人的回饋",
            "(C) 具體的防火牆設定指令",
            "(D) 風險評鑑結果與處理計畫狀態"
        ],
        "answer": "C",
        "note": "管理審查關注高階管理資訊與績效，而非底層技術設定細節。"
    },
    {
        "id": "B5-Plan-30",
        "question": "關於「縱深防禦」在管理層面的應用，下列何者正確？",
        "options": [
            "(A) 制定政策、程序與指引 (Policy, Procedure, Guideline)",
            "(B) 購買更多設備",
            "(C) 只依賴技術人員",
            "(D) 不需進行教育訓練"
        ],
        "answer": "A",
        "note": "管理層的縱深防禦體現在完善的政策架構、人員訓練與稽核制度。"
    }
];

// 將 Batch 5 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch5);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch5);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第六批次 (Batch 6)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：數位鑑識、進階網路攻防、雲端標準、NIST RMF
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch6 = [
    // --- 數位鑑識與作業系統安全 ---
    {
        "id": "B6-Prot-01",
        "question": "在 Windows 數位鑑識中，若要調查使用者「最近開啟過哪些檔案」，下列哪一個機碼 (Registry Key) 最具參考價值？",
        "options": [
            "(A) HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "(B) HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
            "(C) HKLM\\SAM",
            "(D) HKCU\\Environment"
        ],
        "answer": "B",
        "note": "RecentDocs 記錄了使用者最近存取的檔案清單 (MRU List)，是鑑識使用者行為的重要證據。"
    },
    {
        "id": "B6-Prot-02",
        "question": "關於 Windows 的 `Amcache.hve` 檔案，在資安事件調查中的主要用途為何？",
        "options": [
            "(A) 儲存使用者的瀏覽器歷史紀錄",
            "(B) 記錄應用程式的執行歷史、SHA-1 雜湊值及安裝資訊",
            "(C) 儲存無線網路密碼",
            "(D) 記錄印表機列印內容"
        ],
        "answer": "B",
        "note": "Amcache.hve 可用來證明某個惡意程式曾經存在於系統中，即使該檔案已被刪除。"
    },
    {
        "id": "B6-Prot-03",
        "question": "在 Linux 系統中，`/var/log/secure` (或 `/var/log/auth.log`) 主要記錄什麼資訊？",
        "options": [
            "(A) 網頁伺服器的存取紀錄",
            "(B) 身分驗證相關的訊息，如 SSH 登入成功或失敗、sudo 指令執行紀錄",
            "(C) 硬體錯誤訊息",
            "(D) 電子郵件傳輸紀錄"
        ],
        "answer": "B",
        "note": "這是調查 Linux 系統是否遭暴力破解或未授權登入的核心日誌。"
    },
    {
        "id": "B6-Prot-04",
        "question": "攻擊者使用 `vssadmin delete shadows /all /quiet` 指令的主要目的是？",
        "options": [
            "(A) 備份系統資料",
            "(B) 刪除磁碟區陰影複製 (Shadow Copies) 以防止受害者還原檔案，常見於勒索軟體攻擊",
            "(C) 加速系統效能",
            "(D) 建立新的使用者帳號"
        ],
        "answer": "B",
        "note": "勒索軟體標準動作，阻斷受害者使用 Windows 內建還原功能的機會。"
    },
    {
        "id": "B6-Prot-05",
        "question": "關於「記憶體鑑識 (Memory Forensics)」，下列何種工具最為知名且常用？",
        "options": [
            "(A) Volatility",
            "(B) Nmap",
            "(C) Nessus",
            "(D) SQLMap"
        ],
        "answer": "A",
        "note": "Volatility 是開源的記憶體鑑識框架，可用來分析 RAM dump 中的 process、連線等。"
    },
    // --- 網路攻防與協定 ---
    {
        "id": "B6-Prot-06",
        "question": "攻擊者發送 ICMP Echo Request (Ping) 到廣播位址 (Broadcast Address)，並偽造來源 IP 為受害者 IP，導致受害者收到大量回應而癱瘓，這稱為？",
        "options": [
            "(A) SYN Flood",
            "(B) Smurf Attack",
            "(C) Ping of Death",
            "(D) Teardrop"
        ],
        "answer": "B",
        "note": "Smurf Attack 利用廣播放大流量攻擊受害者；現在路由器通常預設關閉廣播回應以防禦此攻擊。"
    },
    {
        "id": "B6-Prot-07",
        "question": "在 DNS 安全中，「DNS Tunneling」通常被攻擊者用來做什麼？",
        "options": [
            "(A) 加速網域名稱解析",
            "(B) 繞過防火牆進行 Command & Control (C2) 通訊或資料外洩",
            "(C) 備份 DNS 紀錄",
            "(D) 阻擋廣告"
        ],
        "answer": "B",
        "note": "將資料編碼在 DNS Query (如 `secret_data.evil.com`) 中，因 DNS 流量常被防火牆放行。"
    },
    {
        "id": "B6-Prot-08",
        "question": "關於 WPA3 的「SAE (Simultaneous Authentication of Equals)」機制，主要解決了 WPA2 的什麼弱點？",
        "options": [
            "(A) 傳輸速度過慢",
            "(B) 易受離線字典攻擊 (Offline Dictionary Attack)",
            "(C) 不支援 5GHz",
            "(D) 無法漫遊"
        ],
        "answer": "B",
        "note": "SAE (Dragonfly) 確保即使密碼較弱，攻擊者也無法透過抓取握手包進行離線暴力破解。"
    },
    {
        "id": "B6-Prot-09",
        "question": "在網路偵察中，使用 `nmap -sS` 參數代表執行哪種掃描？",
        "options": [
            "(A) TCP Connect Scan (全連接)",
            "(B) UDP Scan",
            "(C) TCP SYN Scan (半開放掃描 / Stealth Scan)",
            "(D) Ping Scan"
        ],
        "answer": "C",
        "note": "SYN Scan 不完成 TCP 三向交握，速度快且較隱蔽，是 Nmap 的預設掃描方式。"
    },
    {
        "id": "B6-Prot-10",
        "question": "關於 BGP (Border Gateway Protocol) 劫持 (Hijacking)，其原理為何？",
        "options": [
            "(A) 攻擊者入侵路由器硬體",
            "(B) 攻擊者宣告不屬於自己的 IP 前綴 (Prefix)，導致流量被錯誤導向",
            "(C) 攻擊者切斷光纖",
            "(D) 攻擊者發送大量垃圾郵件"
        ],
        "answer": "B",
        "note": "BGP 缺乏內建驗證機制，若無 RPKI 保護，攻擊者可宣告更具優勢的路徑劫持流量。"
    },
    // --- 應用程式與 Web 安全 ---
    {
        "id": "B6-Prot-11",
        "question": "針對「反序列化 (Deserialization)」漏洞，攻擊者通常利用什麼方式觸發 RCE？",
        "options": [
            "(A) 上傳圖片",
            "(B) 傳送精心構造的序列化物件 (Gadget Chain)，在反序列化時觸發惡意方法",
            "(C) 發送大量 HTTP 請求",
            "(D) 修改 CSS 樣式"
        ],
        "answer": "B",
        "note": "如 Java 的 Apache Commons Collections 漏洞，利用 Gadget Chain 在物件還原時執行指令。"
    },
    {
        "id": "B6-Prot-12",
        "question": "關於 JWT (JSON Web Token) 的 `alg: None` 攻擊，攻擊者的操作為何？",
        "options": [
            "(A) 猜測密鑰",
            "(B) 將 Header 中的演算法改為 'None' 並移除簽章，試圖欺騙後端不驗證簽章",
            "(C) 加密 Token",
            "(D) 刪除 Token"
        ],
        "answer": "B",
        "note": "若後端實作不當，接受 'None' 演算法，攻擊者即可偽造任意內容的 Token。"
    },
    {
        "id": "B6-Prot-13",
        "question": "在 Web 安全中，`Content-Security-Policy` (CSP) Header 的主要用途是？",
        "options": [
            "(A) 加密傳輸內容",
            "(B) 限制瀏覽器只能載入特定來源的資源 (如 Script, Image)，以減緩 XSS 攻擊",
            "(C) 禁止右鍵選單",
            "(D) 強制使用 HTTPS"
        ],
        "answer": "B",
        "note": "CSP 是防禦 XSS 的重要縱深防禦措施，限制惡意腳本的載入與執行。"
    },
    {
        "id": "B6-Prot-14",
        "question": "攻擊者利用 XML 解析器的漏洞，讀取伺服器上的 `/etc/passwd` 檔案，這屬於哪種攻擊？",
        "options": [
            "(A) XXE (XML External Entity) Injection",
            "(B) SQL Injection",
            "(C) XSS",
            "(D) CSRF"
        ],
        "answer": "A",
        "note": "XXE 利用 XML 解析器允許引用外部實體 (External Entity) 的特性來讀取檔案或發動 SSRF。"
    },
    {
        "id": "B6-Prot-15",
        "question": "關於「Race Condition (競爭條件)」漏洞，常見於哪種場景？",
        "options": [
            "(A) 靜態網頁瀏覽",
            "(B) 多執行緒或並發處理環境 (如轉帳、兌換券使用)，檢查與執行不同步 (TOCTOU)",
            "(C) 單機文書處理",
            "(D) 離線備份"
        ],
        "answer": "B",
        "note": "TOCTOU (Time-of-check to time-of-use) 是 Race Condition 的經典模式，可導致邏輯錯誤或權限繞過。"
    },
    // --- 加密技術 ---
    {
        "id": "B6-Prot-16",
        "question": "在 TLS 交握過程中，「完全前向保密 (Perfect Forward Secrecy, PFS)」確保了什麼？",
        "options": [
            "(A) 傳輸速度最快",
            "(B) 即使伺服器的長期私鑰 (Long-term Private Key) 未來被洩漏，過去攔截的加密流量也無法被解密",
            "(C) 不需要使用憑證",
            "(D) 加密演算法永遠不會被破解"
        ],
        "answer": "B",
        "note": "PFS 使用臨時金鑰 (Ephemeral Keys) 進行交換 (如 ECDHE)，確保金鑰獨立性。"
    },
    {
        "id": "B6-Prot-17",
        "question": "關於 HSM (Hardware Security Module) 的用途，下列何者正確？",
        "options": [
            "(A) 用來加速網路封包轉發",
            "(B) 提供實體強化的環境來生成、儲存與管理加密金鑰",
            "(C) 用來備份硬碟資料",
            "(D) 是一種防火牆"
        ],
        "answer": "B",
        "note": "HSM 是保護高價值金鑰 (如 CA 根金鑰、銀行交易金鑰) 的專用硬體。"
    },
    {
        "id": "B6-Prot-18",
        "question": "下列哪一種密碼學攻擊手法，是利用觀察加密運算過程中的物理特徵 (如耗電量、電磁波) 來推導金鑰？",
        "options": [
            "(A) 暴力破解 (Brute Force)",
            "(B) 旁路攻擊 (Side-channel Attack)",
            "(C) 字典攻擊 (Dictionary Attack)",
            "(D) 生日攻擊 (Birthday Attack)"
        ],
        "answer": "B",
        "note": "旁路攻擊不針對演算法數學弱點，而是針對實作層面的物理洩漏。"
    },
    {
        "id": "B6-Prot-19",
        "question": "在 OpenPGP 中，「信任網 (Web of Trust)」的概念是用來解決什麼問題？",
        "options": [
            "(A) 加密速度",
            "(B) 公鑰的驗證與信任問題 (去中心化的信任模型)",
            "(C) 郵件備份",
            "(D) 壓縮比率"
        ],
        "answer": "B",
        "note": "Web of Trust 透過使用者互相簽署公鑰來建立信任，不同於 PKI 的中心化 CA 架構。"
    },
    {
        "id": "B6-Prot-20",
        "question": "關於 SSH 的 `known_hosts` 檔案，其作用為何？",
        "options": [
            "(A) 儲存使用者的私鑰",
            "(B) 儲存已連線過的遠端伺服器公鑰指紋，防止中間人攻擊 (MITM)",
            "(C) 儲存登入密碼",
            "(D) 儲存網路設定"
        ],
        "answer": "B",
        "note": "若伺服器指紋改變，SSH Client 會發出警告，提示可能遭受 MITM 攻擊。"
    },
    // --- 綜合情境與工具 ---
    {
        "id": "B6-Prot-21",
        "question": "使用 `netcat` 工具執行 `nc -l -p 4444 -e /bin/bash` 的指令，會產生什麼效果？",
        "options": [
            "(A) 掃描 Port 4444",
            "(B) 在本地 Port 4444 監聽，若有連線則提供一個 Shell (Bind Shell)",
            "(C) 連線到遠端 Port 4444",
            "(D) 下載檔案"
        ],
        "answer": "B",
        "note": "這是建立 Bind Shell 的經典指令；若是由內往外連則為 Reverse Shell。"
    },
    {
        "id": "B6-Prot-22",
        "question": "在資安事件中，若發現系統時間被惡意竄改，會最直接影響下列哪項工作的正確性？",
        "options": [
            "(A) 網路速度",
            "(B) 日誌關聯分析 (Log Correlation) 與鑑識時間軸重建",
            "(C) 螢幕顯示解析度",
            "(D) 硬碟讀寫速度"
        ],
        "answer": "B",
        "note": "準確的時間戳記 (NTP 同步) 是跨系統日誌關聯與鑑識分析的基石。"
    },
    {
        "id": "B6-Prot-23",
        "question": "攻擊者利用 `Mimikatz` 工具，最主要想獲取什麼資訊？",
        "options": [
            "(A) 瀏覽器 Cookie",
            "(B) Windows 記憶體中的明文密碼、Hash 或 Kerberos Ticket",
            "(C) 資料庫內容",
            "(D) 硬體規格"
        ],
        "answer": "B",
        "note": "Mimikatz 是 Windows 內網滲透的神器，專門從 LSASS 記憶體中提取憑證。"
    },
    {
        "id": "B6-Prot-24",
        "question": "關於「零日漏洞 (Zero-day Vulnerability)」的定義，下列何者最精確？",
        "options": [
            "(A) 存在 0 天的漏洞",
            "(B) 廠商尚未發布修補程式，且已被攻擊者利用的漏洞",
            "(C) 沒有危害的漏洞",
            "(D) 昨天發現的漏洞"
        ],
        "answer": "B",
        "note": "Zero-day 意指防禦者有「0 天」的時間準備（因為攻擊已經發生且無補丁）。"
    },
    {
        "id": "B6-Prot-25",
        "question": "下列哪種技術可以用來隱藏惡意流量，使其看起來像正常的 HTTPS 流量？",
        "options": [
            "(A) Port Scanning",
            "(B) Domain Fronting (網域前置)",
            "(C) SQL Injection",
            "(D) Buffer Overflow"
        ],
        "answer": "B",
        "note": "Domain Fronting 利用 CDN 特性，DNS 查詢合法網域，但 HTTP Host Header 指向惡意網域。"
    },
    {
        "id": "B6-Prot-26",
        "question": "在 APT 攻擊鏈中，「橫向移動 (Lateral Movement)」的主要目的是？",
        "options": [
            "(A) 離開受駭網路",
            "(B) 在內部網路中尋找並存取更有價值的目標 (如 DC、資料庫)",
            "(C) 破壞防火牆",
            "(D) 降低網路速度"
        ],
        "answer": "B",
        "note": "攻擊者通常從單一端點入侵，需透過橫向移動擴大戰果。"
    },
    {
        "id": "B6-Prot-27",
        "question": "關於「資安誘捕系統 (Deception Technology)」的優勢，下列何者正確？",
        "options": [
            "(A) 可以取代防火牆",
            "(B) 誤報率極低，因為正常使用者不應觸碰誘餌",
            "(C) 只能部署在 DMZ",
            "(D) 需要大量人力監控"
        ],
        "answer": "B",
        "note": "Deception (如蜜罐、蜜標) 的高準確性是其最大優勢，能快速發現內網潛伏威脅。"
    },
    {
        "id": "B6-Prot-28",
        "question": "在行動裝置 App 安全檢測中，檢查 App 是否開啟 `android:debuggable=true` 是為了防止？",
        "options": [
            "(A) App 閃退",
            "(B) 攻擊者連結偵錯器 (Debugger) 進行動態分析與竄改",
            "(C) 耗電量增加",
            "(D) 螢幕無法旋轉"
        ],
        "answer": "B",
        "note": "發布版 App 應關閉除錯模式，否則易被逆向工程與動態分析。"
    },
    {
        "id": "B6-Prot-29",
        "question": "下列何者是防禦「供應鏈攻擊」中，針對開發環境的有效措施？",
        "options": [
            "(A) 開放所有開發者擁有 Root 權限",
            "(B) 實施程式碼簽章 (Code Signing) 並保護私鑰",
            "(C) 允許任意下載第三方套件",
            "(D) 關閉版控系統的日誌"
        ],
        "answer": "B",
        "note": "程式碼簽章確保軟體來源與完整性，防止發布過程被遭竄改。"
    },
    {
        "id": "B6-Prot-30",
        "question": "在進行網路鑑識時，若只有 NetFlow 資料而無完整封包 (PCAP)，能分析出什麼資訊？",
        "options": [
            "(A) 郵件的主旨與內容",
            "(B) 流量的來源 IP、目的 IP、Port、時間、流量大小 (Metadata)",
            "(C) 網頁的 HTML 原始碼",
            "(D) 傳輸的檔案內容"
        ],
        "answer": "B",
        "note": "NetFlow 僅記錄流量的元數據 (Metadata)，無法還原內容，但對流量分析與異常偵測很有用。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch6 = [
    // --- 國際標準與法規 (ISO/Privacy) ---
    {
        "id": "B6-Plan-01",
        "question": "ISO/IEC 27017 是針對哪一個特定領域的資訊安全控制指引？",
        "options": [
            "(A) 醫療健康",
            "(B) 雲端服務 (Cloud Services)",
            "(C) 工業控制",
            "(D) 金融交易"
        ],
        "answer": "B",
        "note": "ISO 27017 提供雲端服務提供者與客戶的資安控制實務指引。"
    },
    {
        "id": "B6-Plan-02",
        "question": "ISO/IEC 27018 的主要關注點是？",
        "options": [
            "(A) 公有雲中個人可識別資訊 (PII) 的保護",
            "(B) 網路設備安全",
            "(C) 實體安全",
            "(D) 備份流程"
        ],
        "answer": "A",
        "note": "ISO 27018 專注於雲端隱私保護 (PII)。"
    },
    {
        "id": "B6-Plan-03",
        "question": "依據 GDPR，若發生跨境資料傳輸 (Cross-border Data Transfer)，必須確保接收國具備什麼條件？",
        "options": [
            "(A) 擁有核武",
            "(B) 適足性認定 (Adequacy Decision) 或具備適當的保障措施 (如 SCC)",
            "(C) 經濟高度發展",
            "(D) 使用英語"
        ],
        "answer": "B",
        "note": "GDPR 嚴格限制資料傳輸至隱私保護不足的國家。"
    },
    {
        "id": "B6-Plan-04",
        "question": "關於 CSA STAR (Security Trust Assurance and Risk) 認證，是針對哪種服務的資安評估？",
        "options": [
            "(A) 雲端服務",
            "(B) 銀行服務",
            "(C) 餐飲服務",
            "(D) 物流服務"
        ],
        "answer": "A",
        "note": "CSA STAR 是雲端安全聯盟推出的雲端資安認證計畫。"
    },
    {
        "id": "B6-Plan-05",
        "question": "在資安治理中，「三道防線 (Three Lines of Defense)」模型的第三道防線是？",
        "options": [
            "(A) 營運管理單位",
            "(B) 風險管理與法遵單位",
            "(C) 內部稽核 (Internal Audit)",
            "(D) 外部主管機關"
        ],
        "answer": "C",
        "note": "第一道：營運；第二道：風險/法遵；第三道：內部稽核 (提供獨立保證)。"
    },
    // --- 風險管理架構 ---
    {
        "id": "B6-Plan-06",
        "question": "NIST RMF (Risk Management Framework) 的第一步是？",
        "options": [
            "(A) Select (選擇控制措施)",
            "(B) Prepare (準備)",
            "(C) Categorize (系統分類)",
            "(D) Assess (評估)"
        ],
        "answer": "B",
        "note": "NIST RMF 2.0 新增了 Prepare 步驟，強調組織層級的準備工作。"
    },
    {
        "id": "B6-Plan-07",
        "question": "在風險處理中，針對「剩餘風險 (Residual Risk)」的正確處置態度是？",
        "options": [
            "(A) 視而不見",
            "(B) 必須由管理階層確認並接受",
            "(C) 轉嫁給 IT 人員",
            "(D) 認為是零"
        ],
        "answer": "B",
        "note": "管理層必須了解並簽署接受剩餘風險，這是當責性 (Accountability) 的表現。"
    },
    {
        "id": "B6-Plan-08",
        "question": "關於「供應鏈風險管理 (SCRM)」，下列何者是有效的管理手段？",
        "options": [
            "(A) 僅以價格為採購唯一標準",
            "(B) 於合約中明訂資安要求與稽核權條款",
            "(C) 信任供應商的口頭保證",
            "(D) 不進行任何審查"
        ],
        "answer": "B",
        "note": "合約規範與稽核權是確保供應鏈資安的法律基礎。"
    },
    {
        "id": "B6-Plan-09",
        "question": "資產分類與分級 (Classification) 的主要目的是？",
        "options": [
            "(A) 為了增加工作量",
            "(B) 確保不同價值的資產獲得「適當且符合成本效益」的保護",
            "(C) 為了美觀",
            "(D) 為了方便刪除"
        ],
        "answer": "B",
        "note": "避免對低價值資產過度保護 (浪費) 或對高價值資產保護不足 (風險)。"
    },
    {
        "id": "B6-Plan-10",
        "question": "在進行 BIA (營運衝擊分析) 時，除了財務損失外，還應考量？",
        "options": [
            "(A) 員工午餐菜單",
            "(B) 聲譽損失、法律責任、營運中斷對客戶的影響",
            "(C) 辦公室裝潢",
            "(D) 電腦品牌"
        ],
        "answer": "B",
        "note": "非財務損失 (如商譽、法遵) 往往比直接財務損失影響更深遠。"
    },
    // --- 營運持續與應變 ---
    {
        "id": "B6-Plan-11",
        "question": "關於「緊急應變程序 (Emergency Response Procedures)」，首要考量是？",
        "options": [
            "(A) 搶救伺服器硬體",
            "(B) 保護人員生命安全 (Life Safety)",
            "(C) 通知媒體",
            "(D) 備份資料"
        ],
        "answer": "B",
        "note": "任何 BCP/DRP 的最高指導原則都是「人命優先」。"
    },
    {
        "id": "B6-Plan-12",
        "question": "災難復原計畫 (DRP) 測試成功後，下一步最重要的是？",
        "options": [
            "(A) 開香檳慶祝",
            "(B) 更新計畫文件 (Update Plan) 以反映測試中的發現與變更",
            "(C) 刪除備份",
            "(D) 解散團隊"
        ],
        "answer": "B",
        "note": "計畫必須保持最新，測試後的回饋與更新是 PDCA 的關鍵。"
    },
    {
        "id": "B6-Plan-13",
        "question": "關於「備援中心」的測試，哪一種方式涉及實際將業務切換到備援中心運作？",
        "options": [
            "(A) 桌面演練",
            "(B) 模擬演練",
            "(C) 全面中斷測試 (Full Interruption/Failover Test)",
            "(D) 書面審查"
        ],
        "answer": "C",
        "note": "Failover Test 最真實但也最具風險，需謹慎規劃。"
    },
    {
        "id": "B6-Plan-14",
        "question": "在資安事件應變中，決定「是否對外發布新聞稿」通常由誰負責？",
        "options": [
            "(A) IT 工程師",
            "(B) 公共關係部門 (PR) 與高階管理層、法務共同決定",
            "(C) 發現事件的員工",
            "(D) 外部駭客"
        ],
        "answer": "B",
        "note": "對外溝通涉及商譽與法律責任，需統一窗口與訊息。"
    },
    {
        "id": "B6-Plan-15",
        "question": "關於「電子證據」的蒐集，必須遵循什麼原則以確保法律效力？",
        "options": [
            "(A) 速度優先，不需記錄",
            "(B) 監管鏈 (Chain of Custody) 與證據完整性",
            "(C) 只有警察可以蒐集",
            "(D) 可以隨意修改原始檔案"
        ],
        "answer": "B",
        "note": "嚴格的監管鏈是法庭接受數位證據的前提。"
    },
    // --- 政策與人員 ---
    {
        "id": "B6-Plan-16",
        "question": "制定資安政策 (Security Policy) 時，下列何者是首要考量？",
        "options": [
            "(A) 購買最先進的科技",
            "(B) 支援組織的業務目標 (Business Objectives)",
            "(C) 模仿其他公司的政策",
            "(D) 限制員工的所有權利"
        ],
        "answer": "B",
        "note": "資安是為了支持業務而存在，政策不能阻礙業務發展。"
    },
    {
        "id": "B6-Plan-17",
        "question": "關於「可接受使用政策 (AUP)」，主要規範對象是？",
        "options": [
            "(A) 防火牆",
            "(B) 一般使用者 (員工、承包商)",
            "(C) 伺服器",
            "(D) 駭客"
        ],
        "answer": "B",
        "note": "AUP 規範使用者如何正確、安全地使用組織的 IT 資源。"
    },
    {
        "id": "B6-Plan-18",
        "question": "對於離職員工的帳號處理，最佳實務是？",
        "options": [
            "(A) 立即停用 (Disable) 或刪除權限",
            "(B) 保留一個月方便交接",
            "(C) 轉給其他同事使用",
            "(D) 更改密碼後繼續使用"
        ],
        "answer": "A",
        "note": "離職生效當下即應終止存取權限，避免報復性破壞或資料外洩。"
    },
    {
        "id": "B6-Plan-19",
        "question": "在資安稽核中，「觀察事項 (Observation)」通常代表？",
        "options": [
            "(A) 嚴重違規",
            "(B) 雖未違反標準，但有改善空間或潛在風險",
            "(C) 做得非常完美",
            "(D) 不需要理會"
        ],
        "answer": "B",
        "note": "觀察事項是稽核員提出的善意提醒，雖非缺失但建議改善。"
    },
    {
        "id": "B6-Plan-20",
        "question": "關於「資安績效指標 (KPI)」，下列何者是較佳的指標？",
        "options": [
            "(A) 防火牆阻擋的封包總數 (數量大不代表安全)",
            "(B) 關鍵系統的弱點修補平均時間 (MTTR)",
            "(C) 資安部門的加班時數",
            "(D) 購買的資安設備數量"
        ],
        "answer": "B",
        "note": "MTTR (Mean Time to Remediate) 能具體反映資安維運的效率與風險暴露時間。"
    },
    // --- 新興科技管理 ---
    {
        "id": "B6-Plan-21",
        "question": "企業導入生成式 AI (如 ChatGPT) 時，應制定政策禁止輸入何種資料？",
        "options": [
            "(A) 公開新聞稿",
            "(B) 機敏資料、個資與營業秘密",
            "(C) 一般程式語法查詢",
            "(D) 翻譯一般文章"
        ],
        "answer": "B",
        "note": "輸入公有雲 AI 的資料可能被用於模型訓練，導致機密外洩。"
    },
    {
        "id": "B6-Plan-22",
        "question": "關於 BYOD (Bring Your Own Device) 的資安策略，採用「容器化 (Containerization)」技術的主要目的是？",
        "options": [
            "(A) 隔離企業資料與員工個人資料",
            "(B) 監控員工的所有私人訊息",
            "(C) 鎖定手機",
            "(D) 刪除員工照片"
        ],
        "answer": "A",
        "note": "容器化 (如 Android Work Profile) 在同一設備上隔離公私領域，兼顧安全與隱私。"
    },
    {
        "id": "B6-Plan-23",
        "question": "在雲端遷移策略中，將應用程式重新架構以符合雲端原生特性 (Cloud Native)，稱為？",
        "options": [
            "(A) Rehost (Lift and Shift)",
            "(B) Refactor / Re-architect",
            "(C) Repurchase",
            "(D) Retire"
        ],
        "answer": "B",
        "note": "Refactor 成本最高但能發揮雲端最大效益；Rehost 僅是搬移 VM。"
    },
    {
        "id": "B6-Plan-24",
        "question": "關於「物聯網 (IoT) 安全」的採購規範，下列何者應列為必要條件？",
        "options": [
            "(A) 外型美觀",
            "(B) 不可使用預設密碼、具備韌體更新機制",
            "(C) 價格最低",
            "(D) 使用舊版作業系統"
        ],
        "answer": "B",
        "note": "預設密碼與無法更新是 IoT 最大的安全漏洞。"
    },
    {
        "id": "B6-Plan-25",
        "question": "在 DevOps 中，SAST (靜態應用程式安全測試) 工具最適合整合在 CI/CD 的哪個階段？",
        "options": [
            "(A) Deploy (部署)",
            "(B) Monitor (監控)",
            "(C) Commit / Build (提交/建置)",
            "(D) Operate (維運)"
        ],
        "answer": "C",
        "note": "在程式碼提交或建置時進行 SAST，可即時回饋給開發者修正 (Shift Left)。"
    },
    // --- 工控與關鍵基礎設施 ---
    {
        "id": "B6-Plan-26",
        "question": "針對 OT (營運技術) 環境的資安管理，下列何者最重要？",
        "options": [
            "(A) 隨意安裝防毒軟體並自動重開機",
            "(B) 確保可用性 (Availability) 與人員安全 (Safety)",
            "(C) 頻繁變更系統設定",
            "(D) 直接連接網際網路"
        ],
        "answer": "B",
        "note": "OT 環境首重可用性與工安，任何資安措施不得影響生產安全。"
    },
    {
        "id": "B6-Plan-27",
        "question": "關於 IEC 62443 標準，主要是針對哪一領域的資安標準？",
        "options": [
            "(A) 金融業",
            "(B) 工業自動化與控制系統 (IACS)",
            "(C) 醫療業",
            "(D) 電商零售"
        ],
        "answer": "B",
        "note": "IEC 62443 是目前全球通用的工控資安標準。"
    },
    {
        "id": "B6-Plan-28",
        "question": "在關鍵基礎設施保護中，「實體隔離 (Air Gap)」的管理挑戰為何？",
        "options": [
            "(A) 網路速度太快",
            "(B) 資料交換困難，常需透過 USB 等可攜式媒體，反而引入病毒風險",
            "(C) 設備太便宜",
            "(D) 沒有挑戰"
        ],
        "answer": "B",
        "note": "Stuxnet 病毒即是透過 USB 跨越 Air Gap 感染核設施。"
    },
    {
        "id": "B6-Plan-29",
        "question": "資通安全管理法規定，關鍵基礎設施提供者應多久辦理一次資通安全稽核？",
        "options": [
            "(A) 每年",
            "(B) 每半年",
            "(C) 每兩年",
            "(D) 不需稽核"
        ],
        "answer": "A",
        "note": "關鍵基礎設施提供者屬於特定非公務機關的高等級，通常要求每年稽核。"
    },
    {
        "id": "B6-Plan-30",
        "question": "關於「供應鏈資安成熟度模型 (CMMC)」的分級，Level 1 (基礎級) 要求實施多少項控制措施？",
        "options": [
            "(A) 17 項",
            "(B) 110 項",
            "(C) 500 項",
            "(D) 10 項"
        ],
        "answer": "A",
        "note": "CMMC 2.0 Level 1 要求實施 17 項基礎資安控制 (Foundational)。"
    }
];

// 將 Batch 6 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch6);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch6);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第七批次 (Batch 7)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：內網滲透(AD)、容器安全、稽核證據、ISO 27002 控制措施
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch7 = [
    // --- 內網滲透與 AD 安全 ---
    {
        "id": "B7-Prot-01",
        "question": "在 Windows AD 滲透中，「Kerberoasting」攻擊的主要目標是獲取什麼？",
        "options": [
            "(A) Domain Admin 的明文密碼",
            "(B) 服務帳號 (Service Account) 的 TGS 票據，並嘗試離線破解其雜湊值",
            "(C) 網域控制站 (DC) 的 IP",
            "(D) DNS 紀錄"
        ],
        "answer": "B",
        "note": "Kerberoasting 利用任何授權使用者均可請求服務票據 (TGS) 的特性，獲取加密的票據後離線破解。"
    },
    {
        "id": "B7-Prot-02",
        "question": "攻擊者利用「Golden Ticket (黃金票據)」攻擊，需要先取得哪一個帳號的 NTLM Hash？",
        "options": [
            "(A) Administrator",
            "(B) Guest",
            "(C) krbtgt (Key Distribution Center Service Account)",
            "(D) SYSTEM"
        ],
        "answer": "C",
        "note": "krbtgt 帳號的密碼雜湊用於簽署 TGT，擁有它即可偽造任意使用者的 TGT (黃金票據)。"
    },
    {
        "id": "B7-Prot-03",
        "question": "關於「LOLBins (Living off the Land Binaries)」的概念，下列敘述何者正確？",
        "options": [
            "(A) 使用駭客自行開發的工具",
            "(B) 利用系統內建的合法工具 (如 certutil, bitsadmin, powershell) 來執行惡意行為，以躲避偵測",
            "(C) 攻擊 Linux 系統的專用術語",
            "(D) 實體破壞硬體"
        ],
        "answer": "B",
        "note": "LOLBins 利用白名單內的合法程式進行下載、執行或編碼，能有效繞過傳統防毒。"
    },
    {
        "id": "B7-Prot-04",
        "question": "在 PowerShell 安全中，攻擊者常用 `ExecutionPolicy Bypass` 參數，其主要作用是？",
        "options": [
            "(A) 提升權限至 Administrator",
            "(B) 繞過 PowerShell 的執行策略限制，允許執行未簽署的腳本",
            "(C) 關閉防火牆",
            "(D) 加密硬碟"
        ],
        "answer": "B",
        "note": "ExecutionPolicy 僅是防止使用者誤操作的機制，並非真正的安全邊界，極易被繞過。"
    },
    {
        "id": "B7-Prot-05",
        "question": "關於「Pass-the-Hash (PtH)」攻擊，攻擊者不需要知道什麼資訊即可進行橫向移動？",
        "options": [
            "(A) 使用者名稱",
            "(B) 目標 IP",
            "(C) 使用者的明文密碼",
            "(D) 網域名稱"
        ],
        "answer": "C",
        "note": "PtH 攻擊直接使用密碼雜湊值 (NTLM Hash) 進行認證，無需破解出明文密碼。"
    },
    // --- 網路與協定進階 ---
    {
        "id": "B7-Prot-06",
        "question": "在交換器 (Switch) 安全中，攻擊者發送大量偽造 MAC 位址的封包，填滿 CAM Table (MAC Address Table)，導致交換器變成 Hub 模式，這稱為？",
        "options": [
            "(A) VLAN Hopping",
            "(B) MAC Flooding (MAC 泛洪)",
            "(C) ARP Spoofing",
            "(D) DHCP Starvation"
        ],
        "answer": "B",
        "note": "MAC Flooding 導致交換器無法學習新 MAC，轉為廣播模式 (Fail Open)，攻擊者即可側錄流量。"
    },
    {
        "id": "B7-Prot-07",
        "question": "關於 SNMP (Simple Network Management Protocol) 各版本的安全性，下列敘述何者正確？",
        "options": [
            "(A) SNMPv1 最安全",
            "(B) SNMPv2c 支援加密",
            "(C) SNMPv3 支援身分驗證與傳輸加密",
            "(D) 三個版本安全性相同"
        ],
        "answer": "C",
        "note": "v1/v2c 僅使用明文 Community String (如 public) 認證，極不安全；v3 才支援加密 (AuthPriv)。"
    },
    {
        "id": "B7-Prot-08",
        "question": "攻擊者利用 NTP 伺服器的 `monlist` 功能發動 DDoS 攻擊，這屬於哪種類型的攻擊？",
        "options": [
            "(A) Protocol Anomaly",
            "(B) Reflection and Amplification (反射與放大攻擊)",
            "(C) Syn Flood",
            "(D) Application Layer Flood"
        ],
        "answer": "B",
        "note": "攻擊者偽造受害者 IP 發送小請求，伺服器回應大封包 (放大倍率高)，造成頻寬耗盡。"
    },
    {
        "id": "B7-Prot-09",
        "question": "關於 IPSec VPN 的兩種運作模式，下列敘述何者正確？",
        "options": [
            "(A) Tunnel Mode (通道模式) 會加密整個原始 IP 封包，並加上新的 IP 表頭",
            "(B) Transport Mode (傳輸模式) 會加密整個 IP 封包",
            "(C) Tunnel Mode 只能用於主機對主機通訊",
            "(D) Transport Mode 用於站點對站點 (Site-to-Site) VPN"
        ],
        "answer": "A",
        "note": "Tunnel Mode 常用於 Gateway-to-Gateway (Site-to-Site)；Transport Mode 常用於 Host-to-Host。"
    },
    {
        "id": "B7-Prot-10",
        "question": "IPv6 的 SLAAC (Stateless Address Autoconfiguration) 機制可能面臨什麼安全風險？",
        "options": [
            "(A) IP 位址不足",
            "(B) Rogue RA (惡意路由器宣告) 攻擊，導致流量被中間人劫持",
            "(C) 無法上網",
            "(D) 速度變慢"
        ],
        "answer": "B",
        "note": "攻擊者發送偽造的 Router Advertisement (RA)，可將受害者流量導向惡意閘道。"
    },
    // --- 應用程式與新興技術 ---
    {
        "id": "B7-Prot-11",
        "question": "關於 GraphQL 安全，攻擊者利用嵌套查詢 (Nested Queries) 造成伺服器資源耗盡，這屬於？",
        "options": [
            "(A) SQL Injection",
            "(B) DoS (Denial of Service)",
            "(C) XSS",
            "(D) CSRF"
        ],
        "answer": "B",
        "note": "GraphQL 允許客戶端定義查詢結構，過深的巢狀查詢會導致伺服器運算過載。"
    },
    {
        "id": "B7-Prot-12",
        "question": "在 WebSocket 安全中，CSWSH (Cross-Site WebSocket Hijacking) 的原理類似於哪種傳統 Web 攻擊？",
        "options": [
            "(A) XSS",
            "(B) CSRF",
            "(C) SQLi",
            "(D) RCE"
        ],
        "answer": "B",
        "note": "CSWSH 利用瀏覽器自動帶入 Cookie 的特性，若 WebSocket 握手時未驗證 Origin，攻擊者可跨站建立連線。"
    },
    {
        "id": "B7-Prot-13",
        "question": "關於區塊鏈智能合約的「Reentrancy Attack (重入攻擊)」，其原理為何？",
        "options": [
            "(A) 猜測私鑰",
            "(B) 在合約更新餘額之前，遞歸調用提款函數，導致重複提款",
            "(C) 雙重支付",
            "(D) 51% 攻擊"
        ],
        "answer": "B",
        "note": "著名的 DAO 事件即為重入攻擊。需使用 Checks-Effects-Interactions 模式防禦。"
    },
    {
        "id": "B7-Prot-14",
        "question": "針對 AI 模型的「Model Extraction (模型竊取/萃取)」攻擊，攻擊者的目的是？",
        "options": [
            "(A) 破壞模型",
            "(B) 透過大量查詢 API，逆向推導出模型的參數或功能，複製一個相似的模型",
            "(C) 毒化訓練資料",
            "(D) 讓模型誤判"
        ],
        "answer": "B",
        "note": "這侵犯了模型的智慧財產權，且可能為後續的對抗式攻擊鋪路。"
    },
    {
        "id": "B7-Prot-15",
        "question": "關於 5G 網路的「Network Slicing (網路切片)」安全，主要的風險考量是？",
        "options": [
            "(A) 頻寬不足",
            "(B) 切片間的隔離性 (Isolation) 是否足夠，防止跨切片攻擊",
            "(C) 基地台被偷",
            "(D) 手機沒電"
        ],
        "answer": "B",
        "note": "不同切片服務不同等級的應用 (如自駕車 vs 上網)，若隔離失效會造成嚴重後果。"
    },
    // --- 鑑識與工具 ---
    {
        "id": "B7-Prot-16",
        "question": "YARA 規則 (Rules) 主要用於什麼用途？",
        "options": [
            "(A) 防火牆流量過濾",
            "(B) 惡意軟體分析與分類 (基於特徵字串或二進位模式)",
            "(C) 密碼破解",
            "(D) 網路掃描"
        ],
        "answer": "B",
        "note": "YARA 是惡意程式研究員用於識別和分類惡意樣本的標準工具。"
    },
    {
        "id": "B7-Prot-17",
        "question": "Windows 事件檢視器中，Event ID 4688 代表什麼？",
        "options": [
            "(A) 登入失敗",
            "(B) 建立新處理程序 (A new process has been created)",
            "(C) 系統關機",
            "(D) 清除日誌"
        ],
        "answer": "B",
        "note": "4688 配合指令列稽核 (Command Line Auditing)，是偵測惡意程式執行的關鍵日誌。"
    },
    {
        "id": "B7-Prot-18",
        "question": "關於「DGA (Domain Generation Algorithm)」技術，常見於哪類惡意軟體？",
        "options": [
            "(A) 廣告軟體",
            "(B) 殭屍網路 (Botnet) 與勒索軟體，用於動態生成 C2 網域以規避封鎖",
            "(C) 挖礦軟體",
            "(D) 鍵盤側錄器"
        ],
        "answer": "B",
        "note": "DGA 讓惡意軟體每天生成數千個網域，防守方難以單純用黑名單封鎖。"
    },
    {
        "id": "B7-Prot-19",
        "question": "在 Cyber Kill Chain (網路殺傷鏈) 中，發送釣魚郵件屬於哪一個階段？",
        "options": [
            "(A) Reconnaissance (偵察)",
            "(B) Weaponization (武器化)",
            "(C) Delivery (傳遞)",
            "(D) Exploitation (利用)"
        ],
        "answer": "C",
        "note": "Delivery 是將武器化的惡意載荷傳送給受害者的過程 (如 Email, USB, Web)。"
    },
    {
        "id": "B7-Prot-20",
        "question": "Metasploit 中的 `use auxiliary/scanner/...` 模組通常用於？",
        "options": [
            "(A) 獲取 Shell",
            "(B) 提權",
            "(C) 資訊蒐集與服務掃描 (不會直接入侵)",
            "(D) 清除日誌"
        ],
        "answer": "C",
        "note": "Auxiliary 模組主要用於掃描、嗅探、Fuzzing 等輔助工作，Exploit 模組才是用於攻擊。"
    },
    // --- 加密與硬體安全 ---
    {
        "id": "B7-Prot-21",
        "question": "關於 TPM (Trusted Platform Module) 的功能，下列何者錯誤？",
        "options": [
            "(A) 提供硬體層級的亂數產生器",
            "(B) 儲存加密金鑰 (如 BitLocker 金鑰)",
            "(C) 進行遠端驗證 (Remote Attestation)",
            "(D) 提升 CPU 運算速度"
        ],
        "answer": "D",
        "note": "TPM 是安全晶片，用於提供信任根 (Root of Trust)，與 CPU 運算速度無關。"
    },
    {
        "id": "B7-Prot-22",
        "question": "「同態加密 (Homomorphic Encryption)」的特性為何？",
        "options": [
            "(A) 加密速度最快",
            "(B) 允許在加密數據上直接進行運算，解密後的結果與對明文運算的結果相同",
            "(C) 產生的密文長度固定",
            "(D) 不需要金鑰"
        ],
        "answer": "B",
        "note": "同態加密是隱私計算的關鍵技術，允許雲端在不知曉資料內容的情況下進行處理。"
    },
    {
        "id": "B7-Prot-23",
        "question": "關於 SSL Pinning (憑證綁定) 在行動應用程式中的作用，下列何者正確？",
        "options": [
            "(A) 加速連線",
            "(B) 應用程式只信任預先寫死 (Hard-coded) 的憑證或公鑰，防止中間人攻擊 (MITM)",
            "(C) 允許使用者安裝自定義 Root CA",
            "(D) 關閉 SSL 驗證"
        ],
        "answer": "B",
        "note": "SSL Pinning 可防止攻擊者透過安裝惡意 Root CA 來攔截 App 流量。"
    },
    {
        "id": "B7-Prot-24",
        "question": "下列哪一種密碼學演算法屬於「後量子密碼學 (PQC)」的候選標準？",
        "options": [
            "(A) RSA-4096",
            "(B) CRYSTALS-Kyber / CRYSTALS-Dilithium",
            "(C) ECC P-521",
            "(D) AES-256"
        ],
        "answer": "B",
        "note": "NIST 已選定 CRYSTALS-Kyber (加密) 與 Dilithium (簽章) 作為 PQC 標準算法。"
    },
    {
        "id": "B7-Prot-25",
        "question": "關於「硬體安全金鑰 (Hardware Security Key, 如 YubiKey)」的防護能力，下列何者正確？",
        "options": [
            "(A) 只能當作隨身碟使用",
            "(B) 透過 FIDO/U2F 協定，能有效防禦釣魚網站 (因為會驗證網域來源)",
            "(C) 需要安裝驅動程式才能使用",
            "(D) 密鑰可以被匯出複製"
        ],
        "answer": "B",
        "note": "硬體金鑰具有來源綁定特性，是目前防禦釣魚最強的 MFA 手段。"
    },
    // --- 其他 ---
    {
        "id": "B7-Prot-26",
        "question": "在 Linux 中，設定檔案權限 `chmod 4000` (SetUID) 對於執行檔 `/bin/bash` 會有什麼風險？",
        "options": [
            "(A) 無法執行",
            "(B) 任何使用者執行該 Shell 時都會擁有檔案擁有者 (Root) 的權限，造成提權漏洞",
            "(C) 檔案變為唯讀",
            "(D) 檔案被隱藏"
        ],
        "answer": "B",
        "note": "這是極度危險的設定，常被用於後門 (SUID Shell)。"
    },
    {
        "id": "B7-Prot-27",
        "question": "關於 HTTP 狀態碼，`403 Forbidden` 代表？",
        "options": [
            "(A) 找不到檔案",
            "(B) 伺服器錯誤",
            "(C) 伺服器理解請求但拒絕授權 (權限不足)",
            "(D) 需要身分驗證 (Unauthorized)"
        ],
        "answer": "C",
        "note": "401 是未認證 (Unauthorized)，403 是已認證但無權限 (Forbidden)，404 是找不到。"
    },
    {
        "id": "B7-Prot-28",
        "question": "下列何者不是「Webshell」的常見特徵？",
        "options": [
            "(A) 使用 `eval()`, `system()`, `exec()` 等危險函數",
            "(B) 檔案體積通常很小 (一語法木馬)",
            "(C) 偽裝成正常的圖片或設定檔",
            "(D) 必須編譯後才能執行"
        ],
        "answer": "D",
        "note": "Webshell 通常是直譯式腳本 (PHP, ASP, JSP)，無需編譯即可在 Web Server 執行。"
    },
    {
        "id": "B7-Prot-29",
        "question": "關於「Beaconing (信標)」行為，在資安監控中代表什麼？",
        "options": [
            "(A) 正常的網頁瀏覽",
            "(B) 受駭主機定期向 C2 伺服器發送心跳訊號 (Heartbeat) 以檢查指令",
            "(C) 藍牙配對",
            "(D) Wi-Fi 訊號廣播"
        ],
        "answer": "B",
        "note": "偵測規律的 Beaconing 流量是發現內網殭屍電腦的重要指標。"
    },
    {
        "id": "B7-Prot-30",
        "question": "在應用程式安全中，Input Validation (輸入驗證) 應該在哪裡執行最安全？",
        "options": [
            "(A) 僅在客戶端 (Client-side)",
            "(B) 僅在伺服器端 (Server-side)",
            "(C) 兩端都要，但伺服器端是最後防線",
            "(D) 資料庫端"
        ],
        "answer": "C",
        "note": "客戶端驗證僅為了使用者體驗，可被繞過；伺服器端驗證才是安全性的保證。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch7 = [
    // --- ISO 27001/27002 詳細控制 ---
    {
        "id": "B7-Plan-01",
        "question": "依據 ISO 27002:2022，控制措施 5.7「威脅情資 (Threat Intelligence)」屬於哪一類控制？",
        "options": [
            "(A) 預防性 (Preventive)",
            "(B) 偵測性 (Detective)",
            "(C) 矯正性 (Corrective)",
            "(D) 組織性 (Organizational)"
        ],
        "answer": "D",
        "note": "5.7 歸類於「組織控制 (Organizational Controls)」，屬性包含預防、偵測與回應。"
    },
    {
        "id": "B7-Plan-02",
        "question": "ISO 27002:2022 控制措施 8.28「安全程式碼開發 (Secure Coding)」要求？",
        "options": [
            "(A) 開發人員自己測試即可",
            "(B) 應將安全原則應用於軟體開發生命週期 (SDLC) 的每個階段",
            "(C) 只需在上線前進行掃描",
            "(D) 使用最快的開發語言"
        ],
        "answer": "B",
        "note": "強調 Secure by Design 與縱深防禦在開發流程中的應用。"
    },
    {
        "id": "B7-Plan-03",
        "question": "在 ISO 27001 中，SoA (適用性聲明書) 必須包含？",
        "options": [
            "(A) 組織所有的資產清單",
            "(B) 必要的控制措施、選擇理由、實作狀態以及排除理由",
            "(C) 所有員工的薪資",
            "(D) 網路拓撲圖"
        ],
        "answer": "B",
        "note": "SoA 是 ISMS 的核心文件，連結了風險評鑑結果與控制措施的實施。"
    },
    {
        "id": "B7-Plan-04",
        "question": "關於「管理審查 (Management Review)」的頻率，ISO 27001 的要求是？",
        "options": [
            "(A) 每週一次",
            "(B) 按計畫的時間間隔 (通常為每年至少一次) 或發生重大變更時",
            "(C) 只有發生事故時",
            "(D) 不需定期"
        ],
        "answer": "B",
        "note": "標準要求 Planned intervals，實務上通常配合年度計畫進行。"
    },
    {
        "id": "B7-Plan-05",
        "question": "ISO 27001 中的「稽核方案 (Audit Programme)」是指？",
        "options": [
            "(A) 單一次稽核的檢查表",
            "(B) 針對特定時程內 (如一年) 規劃的一組或多次稽核安排",
            "(C) 稽核員的薪資計畫",
            "(D) 購買稽核軟體"
        ],
        "answer": "B",
        "note": "Audit Programme 是宏觀的年度稽核規劃；Audit Plan 是單次稽核的執行計畫。"
    },
    // --- 稽核實務 ---
    {
        "id": "B7-Plan-06",
        "question": "在資安稽核中，下列何種證據的證明力最強？",
        "options": [
            "(A) 面談口述 (Testimonial)",
            "(B) 文件審查 (Documentary)",
            "(C) 稽核員親自觀察或測試 (Physical / Re-performance)",
            "(D) 傳聞證據"
        ],
        "answer": "C",
        "note": "親自觀察 (如看著管理員操作) 或重新執行 (Re-performance) 的證據力高於書面紀錄。"
    },
    {
        "id": "B7-Plan-07",
        "question": "「符合性測試 (Compliance Testing)」與「實質性測試 (Substantive Testing)」的區別？",
        "options": [
            "(A) 前者測硬體，後者測軟體",
            "(B) 前者測試控制措施是否「存在且執行」，後者驗證資料的「完整性與正確性」",
            "(C) 兩者相同",
            "(D) 前者由外部稽核做，後者由內部稽核做"
        ],
        "answer": "B",
        "note": "符合性測試檢查是否有做 (如是否有簽核)；實質性測試檢查內容是否正確 (如金額計算)。"
    },
    {
        "id": "B7-Plan-08",
        "question": "稽核抽樣 (Sampling) 中，若母體數量龐大且同質性高，適合採用？",
        "options": [
            "(A) 隨機抽樣 (Random Sampling)",
            "(B) 判斷抽樣 (Judgmental Sampling)",
            "(C) 全查",
            "(D) 屬性抽樣"
        ],
        "answer": "A",
        "note": "同質性高適合隨機抽樣以獲得統計上的代表性。"
    },
    {
        "id": "B7-Plan-09",
        "question": "稽核發現的缺失 (Finding) 應包含哪些要素？",
        "options": [
            "(A) 只有問題描述",
            "(B) 準則 (Criteria)、現況 (Condition)、原因 (Cause)、影響 (Effect)",
            "(C) 只有改善建議",
            "(D) 稽核員的心情"
        ],
        "answer": "B",
        "note": "CCCE (Criteria, Condition, Cause, Effect) 是撰寫稽核發現的標準結構。"
    },
    {
        "id": "B7-Plan-10",
        "question": "內部稽核員的「獨立性 (Independence)」是指？",
        "options": [
            "(A) 稽核員必須單獨工作",
            "(B) 稽核員不得稽核自己負責的業務或系統",
            "(C) 稽核員辦公室要獨立",
            "(D) 稽核員不領薪水"
        ],
        "answer": "B",
        "note": "球員兼裁判會導致利益衝突，失去稽核的客觀性。"
    },
    // --- 隱私與個資管理 ---
    {
        "id": "B7-Plan-11",
        "question": "ISO 29100 隱私框架中，定義了多少項隱私原則？",
        "options": [
            "(A) 3 項",
            "(B) 5 項",
            "(C) 11 項",
            "(D) 20 項"
        ],
        "answer": "C",
        "note": "ISO 29100 定義了 11 項隱私原則 (如同意、目的明確、收集限制等)。"
    },
    {
        "id": "B7-Plan-12",
        "question": "關於「隱私工程 (Privacy Engineering)」，其目標是？",
        "options": [
            "(A) 隱藏程式碼",
            "(B) 將隱私保護原則嵌入系統開發與工程流程中",
            "(C) 加密所有資料",
            "(D) 刪除所有個資"
        ],
        "answer": "B",
        "note": "類似 Security by Design，Privacy by Design 要求在工程階段就落實隱私保護。"
    },
    {
        "id": "B7-Plan-13",
        "question": "依據個資法，公務機關保有個人資料檔案者，應定期將什麼資訊公開？",
        "options": [
            "(A) 所有個資內容",
            "(B) 個人資料檔案名稱、保有依據、特定目的及類別",
            "(C) 承辦人員姓名",
            "(D) 防火牆紀錄"
        ],
        "answer": "B",
        "note": "這是個資法第 17 條規定的公開義務，旨在落實透明性。"
    },
    {
        "id": "B7-Plan-14",
        "question": "關於 GDPR 的「同意 (Consent)」，下列條件何者錯誤？",
        "options": [
            "(A) 必須是自由給予的 (Freely given)",
            "(B) 必須是具體的 (Specific)",
            "(C) 可以使用預設勾選 (Pre-ticked boxes) 的方式取得",
            "(D) 必須是明確的 (Unambiguous)"
        ],
        "answer": "C",
        "note": "GDPR 禁止預設勾選或默示同意，必須是使用者的主動行為 (Opt-in)。"
    },
    {
        "id": "B7-Plan-15",
        "question": "當發生重大個資外洩事故時，除了通報主管機關，通常還需要通知誰？",
        "options": [
            "(A) 競爭對手",
            "(B) 資料當事人 (Data Subject) (若對其權益有重大影響)",
            "(C) 網紅",
            "(D) 不需通知任何人"
        ],
        "answer": "B",
        "note": "若外洩可能導致當事人權益受損，應主動通知當事人，告知應變措施。"
    },
    // --- BCP 與應變 ---
    {
        "id": "B7-Plan-16",
        "question": "關於「緊急通報樹 (Call Tree)」，其主要用途是？",
        "options": [
            "(A) 種植樹木的計畫",
            "(B) 確保在災害發生時，能依照預定順序迅速通知所有關鍵人員",
            "(C) 電話號碼簿",
            "(D) 網路拓撲圖"
        ],
        "answer": "B",
        "note": "Call Tree 確保訊息能層層傳遞，避免通訊混亂或遺漏。"
    },
    {
        "id": "B7-Plan-17",
        "question": "在災難復原技術中，「電子傳送 (Electronic Vaulting)」是指？",
        "options": [
            "(A) 用卡車運送磁帶",
            "(B) 透過網路將大量資料批次傳送到備援中心",
            "(C) 即時同步每一筆交易 (Remote Journaling)",
            "(D) 寄送 Email"
        ],
        "answer": "B",
        "note": "Electronic Vaulting 是批次傳送；Remote Journaling 是即時傳送交易日誌。"
    },
    {
        "id": "B7-Plan-18",
        "question": "關於「危機管理 (Crisis Management)」與「事故應變 (Incident Response)」的區別？",
        "options": [
            "(A) 兩者相同",
            "(B) 事故應變專注於技術問題的解決；危機管理專注於組織整體、聲譽、法律及溝通層面",
            "(C) 危機管理由 IT 部門負責",
            "(D) 事故應變由公關部門負責"
        ],
        "answer": "B",
        "note": "事故應變是戰術層面 (Tactical)，危機管理是戰略層面 (Strategic)。"
    },
    {
        "id": "B7-Plan-19",
        "question": "在 BCP 中，若主要設施無法進入，員工改在家中或替代場所工作，這屬於？",
        "options": [
            "(A) 預防措施",
            "(B) 復原策略 (Recovery Strategy)",
            "(C) 風險評估",
            "(D) 稽核活動"
        ],
        "answer": "B",
        "note": "異地辦公 (Alternative Work Site) 是人員復原策略的一種。"
    },
    {
        "id": "B7-Plan-20",
        "question": "資安事故處理的「經驗學習 (Lessons Learned)」階段，最重要的產出是？",
        "options": [
            "(A) 懲處名單",
            "(B) 結案報告與改善行動計畫 (Improvement Plan)",
            "(C) 新聞稿",
            "(D) 賠償金額"
        ],
        "answer": "B",
        "note": "將經驗轉化為具體的改善計畫 (如修訂政策、升級設備) 才能避免重蹈覆轍。"
    },
    // --- 治理與框架 ---
    {
        "id": "B7-Plan-21",
        "question": "COBIT (Control Objectives for Information and Related Technologies) 框架主要關注什麼？",
        "options": [
            "(A) 軟體開發",
            "(B) 企業 IT 的治理與管理 (Governance and Management of Enterprise IT)",
            "(C) 滲透測試",
            "(D) 網路設備設定"
        ],
        "answer": "B",
        "note": "COBIT 連接了企業目標與 IT 目標，是 IT 治理的黃金標準。"
    },
    {
        "id": "B7-Plan-22",
        "question": "ITIL (Information Technology Infrastructure Library) 主要關注什麼？",
        "options": [
            "(A) IT 服務管理 (IT Service Management, ITSM)",
            "(B) 駭客攻擊",
            "(C) 程式語言",
            "(D) 硬體維修"
        ],
        "answer": "A",
        "note": "ITIL 提供 IT 服務交付與支援的最佳實踐 (如 Incident, Problem, Change Management)。"
    },
    {
        "id": "B7-Plan-23",
        "question": "PCI-DSS 要求商家「不要」儲存下列哪項資料？",
        "options": [
            "(A) 持卡人姓名",
            "(B) 卡號 (PAN) (需加密儲存)",
            "(C) 卡片驗證碼 (CVV2/CVC2) 與 PIN Block",
            "(D) 到期日"
        ],
        "answer": "C",
        "note": "PCI-DSS 嚴格禁止儲存敏感驗證資料 (Sensitive Authentication Data)，即便加密也不行。"
    },
    {
        "id": "B7-Plan-24",
        "question": "Common Criteria (ISO 15408) 中的 EAL (Evaluation Assurance Level) 分為幾級？",
        "options": [
            "(A) 3 級",
            "(B) 5 級",
            "(C) 7 級",
            "(D) 10 級"
        ],
        "answer": "C",
        "note": "EAL1 (功能測試) 到 EAL7 (形式化驗證設計)，等級越高驗證越嚴謹。"
    },
    {
        "id": "B7-Plan-25",
        "question": "FIPS 140-2 是針對什麼產品的認證標準？",
        "options": [
            "(A) 防火牆",
            "(B) 密碼模組 (Cryptographic Modules)",
            "(C) 防毒軟體",
            "(D) 作業系統"
        ],
        "answer": "B",
        "note": "美國政府對密碼模組 (軟體或硬體 HSM) 的安全標準。"
    },
    // --- 實體與環境 ---
    {
        "id": "B7-Plan-26",
        "question": "CPTED (Crime Prevention Through Environmental Design) 的核心概念是？",
        "options": [
            "(A) 透過環境設計 (如照明、景觀、動線) 來減少犯罪機會與恐懼",
            "(B) 增加警衛人數",
            "(C) 安裝更多監視器",
            "(D) 加高圍牆"
        ],
        "answer": "A",
        "note": "CPTED 強調利用自然監控、自然存取控制與領域感來預防犯罪。"
    },
    {
        "id": "B7-Plan-27",
        "question": "在機房安全中，NIST SP 800-88 定義的媒體銷毀方法「Purge (清除)」是指？",
        "options": [
            "(A) 簡單刪除檔案",
            "(B) 透過消磁或覆寫等技術，使資料無法透過實驗室等級的技術復原",
            "(C) 物理破壞 (Destroy)",
            "(D) 格式化"
        ],
        "answer": "B",
        "note": "Clear (重置/格式化) < Purge (消磁/覆寫) < Destroy (物理銷毀)。"
    },
    {
        "id": "B7-Plan-28",
        "question": "關於機房的電力供應，UPS (不斷電系統) 的主要功能是？",
        "options": [
            "(A) 長期供電",
            "(B) 在市電中斷與發電機啟動之間的過渡期間，提供短期穩定電力",
            "(C) 節省電費",
            "(D) 加速伺服器"
        ],
        "answer": "B",
        "note": "長期供電靠發電機；UPS 負責「不斷電」的銜接與穩壓。"
    },
    {
        "id": "B7-Plan-29",
        "question": "下列何者是「身分治理與管理 (IGA)」的主要功能？",
        "options": [
            "(A) 阻擋病毒",
            "(B) 管理身分生命週期、存取請求、權限審查與合規性報告",
            "(C) 備份資料庫",
            "(D) 監控網路流量"
        ],
        "answer": "B",
        "note": "IGA 整合了 IAM (管理) 與 Governance (合規/稽核) 的需求。"
    },
    {
        "id": "B7-Plan-30",
        "question": "在資安政策體系中，「程序 (Procedure)」的特性是？",
        "options": [
            "(A) 高階指導原則",
            "(B) 強制性的技術參數",
            "(C) 詳細的、逐步的 (Step-by-step) 操作說明",
            "(D) 建議性的最佳實務"
        ],
        "answer": "C",
        "note": "Policy (政策) > Standard (標準) > Procedure (程序) > Guideline (指引)。"
    }
];

// 將 Batch 7 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch7);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch7);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第八批次 (Batch 8)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：備份還原技術、實體環境安全、系統上線策略、密碼學基礎
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch8 = [
    // --- 密碼學與認證基礎 ---
    {
        "id": "B8-Prot-01",
        "question": "關於「Base64」的敘述，下列何者正確？",
        "options": [
            "(A) 它是一種高強度的加密演算法",
            "(B) 它是一種雜湊函數",
            "(C) 它是一種編碼 (Encoding) 方式，不具備機密性保護功能",
            "(D) 它可以用來壓縮資料"
        ],
        "answer": "C",
        "note": "114 筆記重點。Base64 只是將二進位資料轉為可列印字元，任何人都能解碼，不是加密。"
    },
    {
        "id": "B8-Prot-02",
        "question": "下列哪一種機制可以確保資料在傳輸過程中「未被竄改」（完整性）？",
        "options": [
            "(A) Base64 編碼",
            "(B) HMAC (Hash-based Message Authentication Code)",
            "(C) ROT13",
            "(D) 壓縮 (Compression)"
        ],
        "answer": "B",
        "note": "HMAC 結合了雜湊函數與密鑰，可同時驗證資料完整性與來源身分。"
    },
    {
        "id": "B8-Prot-03",
        "question": "在生物辨識系統中，若要提高安全性（例如銀行金庫），應調整系統參數以降低哪一個指標？",
        "options": [
            "(A) FRR (False Rejection Rate)",
            "(B) FAR (False Acceptance Rate)",
            "(C) CER (Crossover Error Rate)",
            "(D) CPU 使用率"
        ],
        "answer": "B",
        "note": "FAR (誤受率) 越低，代表冒充者成功的機率越低，安全性越高，但可能導致合法使用者被拒絕 (高 FRR)。"
    },
    {
        "id": "B8-Prot-04",
        "question": "關於「數位信封 (Digital Envelope)」的運作流程，下列何者正確？",
        "options": [
            "(A) 用對稱金鑰加密資料，再用接收者的公鑰加密該對稱金鑰",
            "(B) 用接收者的公鑰直接加密所有資料",
            "(C) 用傳送者的私鑰加密資料",
            "(D) 用雜湊函數加密資料"
        ],
        "answer": "A",
        "note": "混合加密機制：對稱加密處理大數據（速度快），非對稱加密處理金鑰（安全交換）。"
    },
    {
        "id": "B8-Prot-05",
        "question": "SSH 協定中，`ssh-keygen` 產生的預設私鑰檔案權限應設定為多少才安全？",
        "options": [
            "(A) 777 (rwxrwxrwx)",
            "(B) 644 (rw-r--r--)",
            "(C) 600 (rw-------)",
            "(D) 755 (rwxr-xr-x)"
        ],
        "answer": "C",
        "note": "私鑰必須只有擁有人可讀寫 (600)，否則 SSH Client 會拒絕使用並報錯。"
    },
    // --- 系統備份與儲存技術 ---
    {
        "id": "B8-Prot-06",
        "question": "關於 RAID 5 磁碟陣列的特性，下列何者正確？",
        "options": [
            "(A) 至少需要 2 顆硬碟",
            "(B) 資料完全鏡像 (Mirroring)，空間利用率 50%",
            "(C) 至少需要 3 顆硬碟，允許 1 顆硬碟損壞而不遺失資料",
            "(D) 沒有容錯能力，但讀寫最快"
        ],
        "answer": "C",
        "note": "114 筆記重點。RAID 5 使用同位元檢查 (Parity)，N 顆硬碟有 N-1 的容量。"
    },
    {
        "id": "B8-Prot-07",
        "question": "若希望資料寫入速度快且具備容錯能力，但硬碟成本較高（最少 4 顆），應選擇哪種 RAID？",
        "options": [
            "(A) RAID 0",
            "(B) RAID 1",
            "(C) RAID 5",
            "(D) RAID 10 (1+0)"
        ],
        "answer": "D",
        "note": "RAID 10 結合了 RAID 1 (鏡像容錯) 與 RAID 0 (條帶化加速)，效能與安全性兼具。"
    },
    {
        "id": "B8-Prot-08",
        "question": "在備份策略中，哪一種備份方式所需的「儲存空間最少」且「備份速度最快」？",
        "options": [
            "(A) 完整備份 (Full Backup)",
            "(B) 差異備份 (Differential Backup)",
            "(C) 增量備份 (Incremental Backup)",
            "(D) 映像檔備份 (Image Backup)"
        ],
        "answer": "C",
        "note": "114 筆記重點。增量備份只備份「自上次備份（無論完整或增量）後」變更的資料，量最小。"
    },
    {
        "id": "B8-Prot-09",
        "question": "關於 LTO (Linear Tape-Open) 磁帶的特性，下列何者正確？",
        "options": [
            "(A) 存取速度比 SSD 快",
            "(B) 適合長期離線存檔 (Archive) 與異地備份",
            "(C) 容易感染勒索軟體",
            "(D) 容量非常小"
        ],
        "answer": "B",
        "note": "磁帶具備離線特性 (Air Gap)，是防禦勒索軟體加密備份檔的最後防線。"
    },
    {
        "id": "B8-Prot-10",
        "question": "在 Windows 系統中，啟用 BitLocker 加密時，通常需要搭配主機板上的哪一個晶片來儲存金鑰？",
        "options": [
            "(A) GPU",
            "(B) TPM (Trusted Platform Module)",
            "(C) BIOS",
            "(D) NIC"
        ],
        "answer": "B",
        "note": "TPM 晶片負責安全地產生與儲存加密金鑰，確保硬碟未經授權無法被解密。"
    },
    // --- 網路攻防技術 ---
    {
        "id": "B8-Prot-11",
        "question": "攻擊者利用 `ping -f` 或 `hping3` 發送大量 ICMP 封包，這屬於哪種攻擊？",
        "options": [
            "(A) ICMP Flood (Ping Flood)",
            "(B) SQL Injection",
            "(C) ARP Spoofing",
            "(D) XSS"
        ],
        "answer": "A",
        "note": "這是一種頻寬消耗型的阻斷服務攻擊 (DoS)。"
    },
    {
        "id": "B8-Prot-12",
        "question": "關於「通訊埠掃描 (Port Scanning)」，若掃描結果顯示 `Filtered`，通常代表什麼意思？",
        "options": [
            "(A) 該埠口有服務正在監聽",
            "(B) 該埠口沒有服務",
            "(C) 有防火牆或封包過濾裝置阻擋了探測封包",
            "(D) 掃描工具故障"
        ],
        "answer": "C",
        "note": "Open (有回應)、Closed (回應 RST)、Filtered (無回應或被拒絕，通常是防火牆)。"
    },
    {
        "id": "B8-Prot-13",
        "question": "下列何者是防禦「中間人攻擊 (MITM)」的有效技術？",
        "options": [
            "(A) 使用 HTTP 協定",
            "(B) 確保使用 HTTPS 並驗證憑證有效性",
            "(C) 開放 Wi-Fi 不設密碼",
            "(D) 關閉防毒軟體"
        ],
        "answer": "B",
        "note": "HTTPS 透過憑證驗證伺服器身分並加密通道，防止中間人竊聽或竄改。"
    },
    {
        "id": "B8-Prot-14",
        "question": "關於 Web 應用程式中的 `Session Fixation` (會議固定) 攻擊，攻擊者的手法是？",
        "options": [
            "(A) 暴力破解 Session ID",
            "(B) 誘使受害者使用攻擊者預先取得的有效 Session ID 進行登入",
            "(C) 刪除 Session ID",
            "(D) 注入 SQL 指令"
        ],
        "answer": "B",
        "note": "防禦方式：使用者登入成功後，伺服器應立即更換 (Regenerate) Session ID。"
    },
    {
        "id": "B8-Prot-15",
        "question": "在網路封包分析中，TCP header 中的 `RST` (Reset) 旗標通常表示什麼？",
        "options": [
            "(A) 建立連線請求",
            "(B) 連線正常結束",
            "(C) 強制中斷連線或拒絕連線",
            "(D) 資料傳輸中"
        ],
        "answer": "C",
        "note": "當連接埠關閉或防火牆阻擋時，常會收到 RST 封包。"
    },
    // --- 實體與環境安全 ---
    {
        "id": "B8-Prot-16",
        "question": "關於機房滅火系統，使用「水」來滅火主要適用於哪一類火災？",
        "options": [
            "(A) Class A (普通火災：木材、紙張)",
            "(B) Class B (油類火災)",
            "(C) Class C (電氣火災)",
            "(D) Class D (金屬火災)"
        ],
        "answer": "A",
        "note": "114 概論教材。水導電，不可用於電氣火災 (C類)；水遇油會擴大火勢 (B類)。"
    },
    {
        "id": "B8-Prot-17",
        "question": "電力問題中，「電壓瞬間增高」稱為？",
        "options": [
            "(A) Brownout (電壓驟降)",
            "(B) Spike (突波) / Surge (湧浪)",
            "(C) Blackout (斷電)",
            "(D) Sag (壓降)"
        ],
        "answer": "B",
        "note": "Spike 是極短時間的高壓；Surge 是持續較長時間的高壓。兩者皆可能損壞設備。"
    },
    {
        "id": "B8-Prot-18",
        "question": "為了防止機房內的靜電 (ESD) 損壞設備，下列措施何者正確？",
        "options": [
            "(A) 保持機房極度乾燥 (濕度 < 20%)",
            "(B) 控制相對濕度在 40%~60% 之間，並鋪設防靜電地板",
            "(C) 穿著毛衣進入機房",
            "(D) 移除所有接地線"
        ],
        "answer": "B",
        "note": "濕度過低易產生靜電；濕度過高易結露鏽蝕。40-60% 是最佳範圍。"
    },
    {
        "id": "B8-Prot-19",
        "question": "關於門禁系統中的「反潛回 (Anti-passback)」功能，其目的是？",
        "options": [
            "(A) 防止卡片遺失",
            "(B) 防止使用者進門後將卡片傳遞給身後的人再次刷卡進入 (防止尾隨)",
            "(C) 記錄打卡時間",
            "(D) 節省電力"
        ],
        "answer": "B",
        "note": "Anti-passback 要求必須有「進」的紀錄才能「出」，防止卡片被傳遞使用。"
    },
    {
        "id": "B8-Prot-20",
        "question": "在機房規劃中，「冷熱通道 (Hot/Cold Aisle)」設計的主要目的是？",
        "options": [
            "(A) 方便人員走動",
            "(B) 提升空調冷卻效率，避免冷熱空氣混合",
            "(C) 為了美觀",
            "(D) 減少噪音"
        ],
        "answer": "B",
        "note": "將伺服器面對面（冷通道）背對背（熱通道）排列，可優化氣流循環。"
    },
    // --- 應用程式與開發 ---
    {
        "id": "B8-Prot-21",
        "question": "下列哪一種 HTTP Header 可以強制瀏覽器只透過 HTTPS 連線，防止 SSL Strip 攻擊？",
        "options": [
            "(A) X-Content-Type-Options",
            "(B) Strict-Transport-Security (HSTS)",
            "(C) X-XSS-Protection",
            "(D) Cache-Control"
        ],
        "answer": "B",
        "note": "HSTS 告訴瀏覽器：「未來這段時間內，拜訪我不准用 HTTP，全部自動轉 HTTPS」。"
    },
    {
        "id": "B8-Prot-22",
        "question": "在開發階段，使用「Fuzzing (模糊測試)」的主要目的是？",
        "options": [
            "(A) 檢查程式碼風格",
            "(B) 輸入大量隨機、無效或異常的數據，試圖使程式崩潰以發現漏洞",
            "(C) 測試使用者介面",
            "(D) 加密程式碼"
        ],
        "answer": "B",
        "note": "Fuzzing 是發現緩衝區溢位、未處理例外等漏洞的有效動態測試方法。"
    },
    {
        "id": "B8-Prot-23",
        "question": "關於 Git 版本控制的安全，下列何者是常見的錯誤操作？",
        "options": [
            "(A) 使用 .gitignore 排除敏感檔案",
            "(B) 將 API Key 或密碼直接寫在程式碼中並推送到公開儲存庫",
            "(C) 使用 SSH Key 進行認證",
            "(D) 定期審查 Commit 紀錄"
        ],
        "answer": "B",
        "note": "Hard-coded Secrets 是導致雲端帳號被盜用的主因之一 (如 TruffleHog 可掃描此類問題)。"
    },
    {
        "id": "B8-Prot-24",
        "question": "下列何者不是 OWASP Top 10 (2021) 列出的風險？",
        "options": [
            "(A) Insecure Design (不安全設計)",
            "(B) Security Misconfiguration (安全設定缺陷)",
            "(C) Using Components with Known Vulnerabilities (使用已知漏洞元件)",
            "(D) Lack of Antivirus (缺乏防毒軟體)"
        ],
        "answer": "D",
        "note": "防毒軟體是防護手段，不是 Web 應用程式本身的漏洞類別。"
    },
    {
        "id": "B8-Prot-25",
        "question": "在 API 安全中，「BOLA (Broken Object Level Authorization)」漏洞通常是因為？",
        "options": [
            "(A) 伺服器未驗證使用者是否有權存取特定 ID 的資源",
            "(B) 傳輸未加密",
            "(C) API 文件公開",
            "(D) 使用了 XML 格式"
        ],
        "answer": "A",
        "note": "攻擊者修改 API 呼叫中的 ID (如 /users/123/data 改為 124)，若後端未檢查權限即回傳，即為 BOLA。"
    },
    // --- 雲端與 IoT ---
    {
        "id": "B8-Prot-26",
        "question": "IoT 裝置常見的「Mirai」惡意軟體，其主要的感染途徑是？",
        "options": [
            "(A) 利用 SQL Injection",
            "(B) 掃描網路上開放 Telnet/SSH 的裝置，並嘗試預設帳號密碼 (如 admin/admin)",
            "(C) 發送釣魚郵件",
            "(D) 物理接觸"
        ],
        "answer": "B",
        "note": "Mirai 殭屍網路利用 IoT 設備普遍存在的弱密碼問題進行大規模感染。"
    },
    {
        "id": "B8-Prot-27",
        "question": "在 AWS/Azure 等公有雲中，S3 Bucket 或 Blob Storage 資料外洩的最常見原因是？",
        "options": [
            "(A) 雲端平台被駭客攻破",
            "(B) 使用者設定錯誤 (Misconfiguration)，將權限設為 Public (公開)",
            "(C) 硬碟損壞",
            "(D) 網路斷線"
        ],
        "answer": "B",
        "note": "雲端資料外洩 90% 以上源自於客戶端的設定錯誤 (Gartner)。"
    },
    {
        "id": "B8-Prot-28",
        "question": "關於「虛擬化安全」，VM Escape (虛擬機逃逸) 是指？",
        "options": [
            "(A) 虛擬機當機",
            "(B) 攻擊者從 Guest OS 突破隔離，存取到 Hypervisor 或 Host OS",
            "(C) 虛擬機遷移到另一台主機",
            "(D) 刪除虛擬機"
        ],
        "answer": "B",
        "note": "這是虛擬化環境中最嚴重的安全威脅，可能導致整台實體機被控制。"
    },
    {
        "id": "B8-Prot-29",
        "question": "下列何種技術可以用來隔離容器 (Container) 的資源使用？",
        "options": [
            "(A) Namespaces & Cgroups",
            "(B) VLAN",
            "(C) VPN",
            "(D) SSH"
        ],
        "answer": "A",
        "note": "Linux Kernel 的 Namespaces (隔離視野) 與 Cgroups (限制資源) 是容器技術的基礎。"
    },
    {
        "id": "B8-Prot-30",
        "question": "關於 5G 安全，IMSI Catcher (偽基地台) 攻擊的主要威脅是？",
        "options": [
            "(A) 增加網速",
            "(B) 竊取用戶的手機識別碼 (IMSI) 並進行位置追蹤或通訊攔截",
            "(C) 免費上網",
            "(D) 備份手機資料"
        ],
        "answer": "B",
        "note": "5G 引入了 SUCI (加密的識別碼) 來防禦 IMSI Catcher，但在 4G/3G 仍是重大威脅。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch8 = [
    // --- 系統上線與轉換策略 ---
    {
        "id": "B8-Plan-01",
        "question": "系統轉換策略中，風險最低但成本最高（因為要維護兩套系統）的是哪一種？",
        "options": [
            "(A) 直接轉換 (Direct Cutover)",
            "(B) 平行測試 / 並行轉換 (Parallel Operation)",
            "(C) 試點轉換 (Pilot Operation)",
            "(D) 分階段轉換 (Phased Operation)"
        ],
        "answer": "B",
        "note": "114 筆記重點。新舊系統同時運作一段時間，確保新系統無誤後才關閉舊系統。"
    },
    {
        "id": "B8-Plan-02",
        "question": "系統轉換策略中，風險最高但成本最低、速度最快的是？",
        "options": [
            "(A) 直接轉換 (Direct Cutover / Abrupt)",
            "(B) 平行測試",
            "(C) 試點轉換",
            "(D) 分階段轉換"
        ],
        "answer": "A",
        "note": "直接停用舊系統啟用新系統，若新系統失敗則無退路，風險極高。"
    },
    {
        "id": "B8-Plan-03",
        "question": "關於 SSDLC 的「部署與維運階段」，下列何者是重點工作？",
        "options": [
            "(A) 需求訪談",
            "(B) 執行弱點掃描、修補漏洞、版本控制與變更管理",
            "(C) 撰寫程式碼",
            "(D) 招標採購"
        ],
        "answer": "B",
        "note": "系統上線後的持續維護、監控與漏洞修補是維運階段的核心。"
    },
    // --- 法規與標準 (進階) ---
    {
        "id": "B8-Plan-04",
        "question": "依據《資通安全責任等級分級辦法》，C 級機關的資安專職人員配置要求為？",
        "options": [
            "(A) 4 人",
            "(B) 2 人",
            "(C) 1 人",
            "(D) 無強制要求"
        ],
        "answer": "C",
        "note": "A級:4人, B級:2人, C級:1人。"
    },
    {
        "id": "B8-Plan-05",
        "question": "關於 ISO 27001 的「資訊安全目標 (Information Security Objectives)」，下列敘述何者錯誤？",
        "options": [
            "(A) 應與資訊安全政策一致",
            "(B) 應可量測 (Measurable)",
            "(C) 應傳達給相關人員",
            "(D) 一旦制定就永遠不能修改"
        ],
        "answer": "D",
        "note": "目標應在適當時機更新 (ISO 27001:2022 6.2)。"
    },
    {
        "id": "B8-Plan-06",
        "question": "在 GDPR 中，若發生個資外洩且對當事人權利自由有高風險時，企業必須？",
        "options": [
            "(A) 僅通報主管機關",
            "(B) 隱瞞事實",
            "(C) 通報主管機關並通知當事人 (Data Subject)",
            "(D) 賠償每人 100 歐元"
        ],
        "answer": "C",
        "note": "高風險情況下 (如身分盜用風險)，必須主動通知受害者。"
    },
    {
        "id": "B8-Plan-07",
        "question": "依據 NIST CSF，資安事件後的「從錯誤中學習並改進流程」屬於哪一個功能？",
        "options": [
            "(A) Identify",
            "(B) Protect",
            "(C) Respond",
            "(D) Recover"
        ],
        "answer": "C",
        "note": "雖然 Recover 也有改進，但 Incident Response Analysis (檢討) 通常歸類於 Respond 的 Analysis 類別或 Recover 的 Improvements。"
    },
    {
        "id": "B8-Plan-08",
        "question": "關於「資安險 (Cyber Insurance)」的投保評估，下列何者通常是保險公司審核的重點？",
        "options": [
            "(A) 公司的獲利能力",
            "(B) 公司的資安防護水準 (如是否實施 MFA、備份機制)",
            "(C) 員工的年齡",
            "(D) 辦公室地點"
        ],
        "answer": "B",
        "note": "資安防護越差，出險機率越高，保費越高甚至拒保。"
    },
    // --- 風險管理與稽核 ---
    {
        "id": "B8-Plan-09",
        "question": "在風險評鑑中，發現「伺服器機房位於地下室，有淹水風險」，這屬於？",
        "options": [
            "(A) 威脅 (Threat)",
            "(B) 脆弱性 (Vulnerability)",
            "(C) 衝擊 (Impact)",
            "(D) 控制措施 (Control)"
        ],
        "answer": "B",
        "note": "「位於地下室」是環境上的弱點 (Vulnerability)；「淹水」是威脅 (Threat)。"
    },
    {
        "id": "B8-Plan-10",
        "question": "關於「營運衝擊分析 (BIA)」，下列哪一項不是其產出？",
        "options": [
            "(A) 關鍵業務流程清單",
            "(B) RTO 與 RPO 目標",
            "(C) 系統漏洞掃描報告",
            "(D) 資源需求評估"
        ],
        "answer": "C",
        "note": "漏洞報告是風險評鑑的技術產出，非 BIA (關注業務面) 的產出。"
    },
    {
        "id": "B8-Plan-11",
        "question": "內部稽核計畫應考量哪些因素？",
        "options": [
            "(A) 過程的重要性、變更及以往稽核的結果",
            "(B) 稽核員的喜好",
            "(C) 天氣狀況",
            "(D) 員工的休假表"
        ],
        "answer": "A",
        "note": "ISO 27001 9.2 要求稽核方案需基於風險與過往績效來規劃。"
    },
    {
        "id": "B8-Plan-12",
        "question": "關於「獨立性」稽核原則，下列何者違反了該原則？",
        "options": [
            "(A) 財務部門稽核 IT 部門",
            "(B) IT 部門主管稽核自己部門的防火牆設定",
            "(C) 聘請外部顧問進行稽核",
            "(D) 內部稽核室進行全公司稽核"
        ],
        "answer": "B",
        "note": "球員兼裁判違反獨立性。"
    },
    {
        "id": "B8-Plan-13",
        "question": "在風險矩陣中，風險值通常是如何計算的？",
        "options": [
            "(A) 風險 = 資產 + 威脅",
            "(B) 風險 = 可能性 (Likelihood) x 衝擊 (Impact)",
            "(C) 風險 = 漏洞 - 控制",
            "(D) 風險 = 預算 / 時間"
        ],
        "answer": "B",
        "note": "最經典的定性風險公式。"
    },
    // --- BCP 與災難復原 ---
    {
        "id": "B8-Plan-14",
        "question": "下列哪一種災難復原測試方法，風險最高但驗證最徹底？",
        "options": [
            "(A) Checklist Review (檢查表審查)",
            "(B) Tabletop Exercise (桌面演練)",
            "(C) Full Interruption Test (全面中斷測試)",
            "(D) Parallel Test (平行測試)"
        ],
        "answer": "C",
        "note": "實際切斷主系統，強制切換至備援系統，風險極高。"
    },
    {
        "id": "B8-Plan-15",
        "question": "在 BCP 中，「互惠協定 (Reciprocal Agreement)」是指？",
        "options": [
            "(A) 與保險公司簽約",
            "(B) 與另一家有類似設備的公司協議，在災難時互相借用資源",
            "(C) 購買雲端備援",
            "(D) 建立熱站"
        ],
        "answer": "B",
        "note": "成本低但風險高（對方可能也同時受災，或資源不足）。"
    },
    {
        "id": "B8-Plan-16",
        "question": "關於電子資料保存，針對「不可修改、不可刪除」的法規要求 (如金融紀錄)，應使用哪種儲存技術？",
        "options": [
            "(A) RAID 0",
            "(B) WORM (Write Once Read Many)",
            "(C) USB 隨身碟",
            "(D) RAM Disk"
        ],
        "answer": "B",
        "note": "WORM 技術確保資料寫入後無法被竄改或刪除，符合合規封存需求。"
    },
    {
        "id": "B8-Plan-17",
        "question": "當發生火災導致機房全毀，啟動異地備援機制屬於 BCP 生命週期中的哪一個階段？",
        "options": [
            "(A) Business Impact Analysis",
            "(B) Risk Assessment",
            "(C) Disaster Recovery (災難復原)",
            "(D) Training"
        ],
        "answer": "C",
        "note": "災難發生後的應變與恢復屬於 DR 階段。"
    },
    // --- 供應鏈與委外管理 ---
    {
        "id": "B8-Plan-18",
        "question": "機關委外開發軟體時，要求廠商提供「原始碼掃描報告」的主要目的是？",
        "options": [
            "(A) 確認廠商有做事",
            "(B) 確保交付的程式碼不包含已知的安全漏洞 (如 SQLi, XSS)",
            "(C) 增加廠商成本",
            "(D) 取得原始碼版權"
        ],
        "answer": "B",
        "note": "這是 SSDLC 委外管理的重要控制點，確保交付品質。"
    },
    {
        "id": "B8-Plan-19",
        "question": "關於「服務水準協議 (SLA)」中的資安條款，下列何者最重要？",
        "options": [
            "(A) 廠商的員工旅遊福利",
            "(B) 服務可用性指標 (如 99.9%) 與資安事件通報時限",
            "(C) 硬體設備的顏色",
            "(D) 廠商的廣告預算"
        ],
        "answer": "B",
        "note": "SLA 需量化資安要求，如可用性 (Availability) 與回應時間。"
    },
    {
        "id": "B8-Plan-20",
        "question": "在供應鏈攻擊防護中，限制供應商遠端連線權限屬於哪一類控制？",
        "options": [
            "(A) 實體控制",
            "(B) 邏輯/技術控制 (Logical/Technical Control)",
            "(C) 矯正控制",
            "(D) 補償控制"
        ],
        "answer": "B",
        "note": "透過 VPN、FW、MFA 等技術手段限制存取。"
    },
    // --- 實體與環境安全 (規劃面) ---
    {
        "id": "B8-Plan-21",
        "question": "機房選址時，應避免下列何種地點？",
        "options": [
            "(A) 交通便利處",
            "(B) 低窪地區、斷層帶、化工廠旁",
            "(C) 警察局附近",
            "(D) 電力充足處"
        ],
        "answer": "B",
        "note": "需考量自然災害 (淹水、地震) 與人為災害 (爆炸、污染) 風險。"
    },
    {
        "id": "B8-Plan-22",
        "question": "關於「潔淨區 (Clear Desk / Clear Screen)」政策，其目的是？",
        "options": [
            "(A) 保持辦公室美觀",
            "(B) 防止敏感資訊被未經授權的人員窺視或竊取 (如貼在螢幕上的密碼條)",
            "(C) 方便打掃",
            "(D) 節省紙張"
        ],
        "answer": "B",
        "note": "這是 ISO 27001 的基本實體安全控制。"
    },
    {
        "id": "B8-Plan-23",
        "question": "資料銷毀程序中，對於存有機密資料的硬碟，最安全的報廢方式是？",
        "options": [
            "(A) 格式化 (Format)",
            "(B) 刪除檔案",
            "(C) 物理破壞 (如粉碎、消磁) 並留存紀錄",
            "(D) 丟到垃圾桶"
        ],
        "answer": "C",
        "note": "僅格式化可被救援，物理破壞才能確保資料無法復原。"
    },
    // --- 綜合題 ---
    {
        "id": "B8-Plan-24",
        "question": "關於「社交工程」防護，除了教育訓練外，下列何種程序性控制也很重要？",
        "options": [
            "(A) 採購更貴的電腦",
            "(B) 建立「雙重確認」流程 (如變更匯款帳號需電話確認)",
            "(C) 禁止員工講電話",
            "(D) 每天更換密碼"
        ],
        "answer": "B",
        "note": "針對 BEC (商務郵件詐騙)，標準作業流程 (SOP) 中的雙重確認是關鍵防線。"
    },
    {
        "id": "B8-Plan-25",
        "question": "在資安治理中，資安成效不佳的最終責任歸屬 (Accountability) 通常在於？",
        "options": [
            "(A) IT 人員",
            "(B) 廠商",
            "(C) 最高管理階層 / 董事會",
            "(D) 使用者"
        ],
        "answer": "C",
        "note": "資安是公司治理的一環，高層需負最終當責 (Accountability)。"
    },
    {
        "id": "B8-Plan-26",
        "question": "關於「行動辦公 (Mobile Work)」的資安政策，下列何者應納入規範？",
        "options": [
            "(A) 禁止在公共 Wi-Fi 處理機敏資料，或必須使用 VPN",
            "(B) 允許員工隨意安裝 App",
            "(C) 不需設定螢幕鎖定",
            "(D) 裝置遺失不需回報"
        ],
        "answer": "A",
        "note": "公共 Wi-Fi 風險高，VPN 是遠端工作的標準配備。"
    },
    {
        "id": "B8-Plan-27",
        "question": "若企業決定導入公有雲服務，在契約中應特別注意什麼？",
        "options": [
            "(A) 雲端廠商的 LOGO 顏色",
            "(B) 服務終止時的資料返還與刪除條款 (Exit Strategy)",
            "(C) 伺服器的品牌",
            "(D) 業務員的獎金"
        ],
        "answer": "B",
        "note": "退場機制 (Exit Strategy) 是防止廠商鎖定與確保資料主權的關鍵。"
    },
    {
        "id": "B8-Plan-28",
        "question": "關於「職務權限表 (Authorization Matrix)」，其功能是？",
        "options": [
            "(A) 計算薪資",
            "(B) 定義不同職位/角色對應的系統存取權限，作為授權依據",
            "(C) 紀錄員工出勤",
            "(D) 規劃座位表"
        ],
        "answer": "B",
        "note": "權限矩陣是實施 RBAC 與最小權限原則的重要工具。"
    },
    {
        "id": "B8-Plan-29",
        "question": "下列何者是「資安事件分級」的主要依據？",
        "options": [
            "(A) 駭客的國籍",
            "(B) 事件對組織業務、資產、聲譽及法規遵循的衝擊程度",
            "(C) 攻擊發生的時間",
            "(D) 使用的病毒種類"
        ],
        "answer": "B",
        "note": "分級是為了決定應變優先順序與通報層級。"
    },
    {
        "id": "B8-Plan-30",
        "question": "在制定 BCP 時，最重要的第一步是？",
        "options": [
            "(A) 購買備援設備",
            "(B) 進行 BIA (營運衝擊分析) 與風險評估",
            "(C) 撰寫復原手冊",
            "(D) 安排演練"
        ],
        "answer": "B",
        "note": "先分析 (BIA/RA) 才能知道要保護什麼、投入多少資源，後續計畫才有依據。"
    }
];

// 將 Batch 8 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch8);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch8);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第九批次 (Batch 9)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：協定分析、惡意程式逆向、雲端容器防護、治理指標
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch9 = [
    // --- 網路協定與分析 ---
    {
        "id": "B9-Prot-01",
        "question": "在 IPSec VPN 中，負責管理加密金鑰的協定是？",
        "options": [
            "(A) AH (Authentication Header)",
            "(B) ESP (Encapsulating Security Payload)",
            "(C) IKE (Internet Key Exchange)",
            "(D) SSL"
        ],
        "answer": "C",
        "note": "AH 負責驗證，ESP 負責加密，IKE 負責協商與交換金鑰 (SA)。"
    },
    {
        "id": "B9-Prot-02",
        "question": "DNSSEC 利用哪種 RR (Resource Record) 來儲存數位簽章，以驗證 DNS 回應的真偽？",
        "options": [
            "(A) DNSKEY",
            "(B) RRSIG",
            "(C) DS (Delegation Signer)",
            "(D) NSEC"
        ],
        "answer": "B",
        "note": "RRSIG (Resource Record Signature) 儲存了對 DNS 記錄集的數位簽章。"
    },
    {
        "id": "B9-Prot-03",
        "question": "關於 HTTP/2 協定的特性，下列何者正確？",
        "options": [
            "(A) 使用明文傳輸",
            "(B) 支援多工 (Multiplexing)，單一 TCP 連線可同時傳輸多個請求",
            "(C) 每個請求都需要建立新的 TCP 連線",
            "(D) 比 HTTP/1.1 慢"
        ],
        "answer": "B",
        "note": "HTTP/2 的多工特性解決了 HTTP/1.1 的 Head-of-line blocking 問題。"
    },
    {
        "id": "B9-Prot-04",
        "question": "在 TCP 表頭中，若 `SYN` 和 `FIN` 旗標同時被設定，這通常被稱為什麼攻擊？",
        "options": [
            "(A) SYN Flood",
            "(B) Xmas Scan (聖誕樹掃描) 或異常封包",
            "(C) Null Scan",
            "(D) Ping of Death"
        ],
        "answer": "B",
        "note": "正常 TCP 交握中 SYN (開始) 和 FIN (結束) 不會同時出現，這是異常組合。"
    },
    {
        "id": "B9-Prot-05",
        "question": "關於 SSH 的 Port Forwarding (通訊埠轉發) 功能，攻擊者常用於？",
        "options": [
            "(A) 加密硬碟",
            "(B) 繞過防火牆，存取內部網路服務 (Tunneling)",
            "(C) 破解密碼",
            "(D) 阻斷服務"
        ],
        "answer": "B",
        "note": "SSH Tunneling 可將受防火牆保護的內網服務映射到外部，是常見的跳板技術。"
    },
    // --- 系統與惡意程式分析 ---
    {
        "id": "B9-Prot-06",
        "question": "在惡意程式分析中，「Packing (加殼)」的主要目的是？",
        "options": [
            "(A) 減小檔案體積",
            "(B) 混淆程式碼與壓縮，以躲避靜態特徵碼偵測與逆向工程",
            "(C) 加快執行速度",
            "(D) 修復程式錯誤"
        ],
        "answer": "B",
        "note": "加殼 (如 UPX) 會改變檔案雜湊值與結構，增加靜態分析難度。"
    },
    {
        "id": "B9-Prot-07",
        "question": "Windows 系統中，攻擊者利用 `Sticky Keys` (按五次 Shift) 漏洞，通常是為了？",
        "options": [
            "(A) 建立後門，在未登入狀況下取得 SYSTEM 權限的 CMD",
            "(B) 讓鍵盤壞掉",
            "(C) 啟動螢幕小鍵盤",
            "(D) 關閉防火牆"
        ],
        "answer": "A",
        "note": "將 sethc.exe 替換為 cmd.exe，可在登入畫面直接喚起高權限 Shell。"
    },
    {
        "id": "B9-Prot-08",
        "question": "關於 Rootkit 的特徵，下列何者正確？",
        "options": [
            "(A) 會顯示明顯的視窗",
            "(B) 深入作業系統核心 (Kernel) 或底層，隱藏惡意程序、檔案與網路連線",
            "(C) 只感染 Word 文件",
            "(D) 容易被一般防毒軟體發現"
        ],
        "answer": "B",
        "note": "Rootkit 透過 Hooking 系統呼叫來欺騙 OS，使用戶無法看到惡意活動。"
    },
    {
        "id": "B9-Prot-09",
        "question": "在 Linux 鑑識中，檢查 `/root/.bash_history` 檔案可以得知？",
        "options": [
            "(A) 網頁瀏覽紀錄",
            "(B) Root 使用者曾經輸入過的指令歷史",
            "(C) 系統開機時間",
            "(D) 密碼雜湊值"
        ],
        "answer": "B",
        "note": "指令歷史紀錄是還原攻擊者操作步驟的關鍵證據。"
    },
    {
        "id": "B9-Prot-10",
        "question": "關於「無檔案惡意軟體 (Fileless Malware)」的執行方式，常利用下列哪個工具？",
        "options": [
            "(A) 小畫家",
            "(B) PowerShell 或 WMI (Windows Management Instrumentation)",
            "(C) 記事本",
            "(D) 計算機"
        ],
        "answer": "B",
        "note": "Fileless 攻擊利用系統內建的合法工具 (Living off the Land) 在記憶體中執行惡意代碼。"
    },
    // --- Web 與應用程式防護 ---
    {
        "id": "B9-Prot-11",
        "question": "關於「Clickjacking (點擊劫持)」的攻擊原理，下列何者正確？",
        "options": [
            "(A) 竊取 Cookie",
            "(B) 將惡意網頁以透明 iframe 覆蓋在正常網頁上，誘使用戶點擊",
            "(C) 修改 DNS 紀錄",
            "(D) 攔截封包"
        ],
        "answer": "B",
        "note": "使用者以為點擊的是正常按鈕，實際上點到了透明 iframe 中的惡意操作。"
    },
    {
        "id": "B9-Prot-12",
        "question": "在 Cookie 設定中，`SameSite` 屬性的主要用途是防禦什麼？",
        "options": [
            "(A) XSS",
            "(B) CSRF (跨站請求偽造)",
            "(C) SQL Injection",
            "(D) DDoS"
        ],
        "answer": "B",
        "note": "`SameSite=Strict` 或 `Lax` 可限制 Cookie 隨跨站請求發送，有效防禦 CSRF。"
    },
    {
        "id": "B9-Prot-13",
        "question": "攻擊者在網址列輸入 `http://site.com/admin/` 並成功進入後台，因為系統未檢查權限，這屬於？",
        "options": [
            "(A) Forced Browsing (強制瀏覽) / Insecure Direct Object References",
            "(B) XSS",
            "(C) SQL Injection",
            "(D) Phishing"
        ],
        "answer": "A",
        "note": "這是存取控制失效的一種，攻擊者猜測或枚舉未公開但未受保護的 URL。"
    },
    {
        "id": "B9-Prot-14",
        "question": "下列哪一種驗證機制可以區分「人」與「機器人」，防止自動化攻擊？",
        "options": [
            "(A) HTTPS",
            "(B) CAPTCHA (圖靈驗證)",
            "(C) Cookie",
            "(D) SSH"
        ],
        "answer": "B",
        "note": "113-2 防護實務。CAPTCHA 用於防止暴力破解、爬蟲或垃圾訊息機器人。"
    },
    {
        "id": "B9-Prot-15",
        "question": "關於 CORS (Cross-Origin Resource Sharing) 的設定，下列何者最危險？",
        "options": [
            "(A) Access-Control-Allow-Origin: https://trusted.com",
            "(B) Access-Control-Allow-Origin: * (允許所有來源)",
            "(C) 不設定 CORS",
            "(D) 限制 Methods 為 GET"
        ],
        "answer": "B",
        "note": "設定為 `*` 代表任何網站都可以讀取你的 API 回應，若包含敏感資料則極度危險。"
    },
    // --- 雲端與容器安全 ---
    {
        "id": "B9-Prot-16",
        "question": "在 Kubernetes 中，`Secrets` 物件預設的儲存方式為何？",
        "options": [
            "(A) 強制加密",
            "(B) 僅使用 Base64 編碼 (若未啟用 Encryption at Rest 則視同明文)",
            "(C) 儲存在外部 HSM",
            "(D) 只有 Root 可讀"
        ],
        "answer": "B",
        "note": "K8s Secrets 預設僅 Base64 編碼，必須額外設定 etcd 加密才安全。"
    },
    {
        "id": "B9-Prot-17",
        "question": "關於 Docker 的 `docker.sock`，若將其掛載到容器內部，會造成什麼風險？",
        "options": [
            "(A) 容器變慢",
            "(B) 容器內的程序可以完全控制 Host 上的 Docker Daemon，甚至取得 Root 權限",
            "(C) 無法聯網",
            "(D) 磁碟空間不足"
        ],
        "answer": "B",
        "note": "暴露 docker.sock 等同於交出 Root 權限，是極高風險的配置。"
    },
    {
        "id": "B9-Prot-18",
        "question": "AWS S3 Bucket 若設定為 `Public Read`，最直接的後果是？",
        "options": [
            "(A) 任何人都可以透過 URL 下載 Bucket 內的檔案",
            "(B) 任何人都可以上傳檔案",
            "(C) 帳號被刪除",
            "(D) 伺服器當機"
        ],
        "answer": "A",
        "note": "這是雲端資料外洩最常見的原因之一。"
    },
    {
        "id": "B9-Prot-19",
        "question": "在雲端環境中，「Metadata Service (如 169.254.169.254)」若未受保護，常被用於哪種攻擊？",
        "options": [
            "(A) SSRF (Server-Side Request Forgery)",
            "(B) XSS",
            "(C) SQL Injection",
            "(D) DDoS"
        ],
        "answer": "A",
        "note": "攻擊者透過 SSRF 存取 Metadata Service，竊取 IAM 憑證以接管雲端資源。"
    },
    {
        "id": "B9-Prot-20",
        "question": "關於 IaC (Infrastructure as Code) 的安全性掃描，主要目的是？",
        "options": [
            "(A) 檢查程式碼語法錯誤",
            "(B) 在部署前偵測雲端資源的錯誤配置 (如 S3 公開、未加密)",
            "(C) 壓縮程式碼",
            "(D) 備份設定檔"
        ],
        "answer": "B",
        "note": "IaC 掃描 (如 Checkov, Tfsec) 是雲端安全左移 (Shift Left) 的重要實踐。"
    },
    // --- 綜合技術 ---
    {
        "id": "B9-Prot-21",
        "question": "下列何種生物特徵認證技術，其「錯誤拒絕率 (FRR)」通常最高（最不穩定）？",
        "options": [
            "(A) 指紋",
            "(B) 虹膜",
            "(C) 聲紋 (Voice Recognition)",
            "(D) 靜脈"
        ],
        "answer": "C",
        "note": "114-1 管理試題。聲紋易受環境噪音、感冒、年齡影響，變異性最大。"
    },
    {
        "id": "B9-Prot-22",
        "question": "關於「數位鑑識」中的 Hash 值比對，若兩個檔案的 Hash 值不同，代表？",
        "options": [
            "(A) 檔案名稱不同",
            "(B) 檔案內容已經被修改，非原始檔案",
            "(C) 檔案建立時間不同",
            "(D) 檔案擁有者不同"
        ],
        "answer": "B",
        "note": "Hash 值是檔案內容的數位指紋，內容哪怕只差 1 bit，Hash 也會完全不同。"
    },
    {
        "id": "B9-Prot-23",
        "question": "在密碼學中，「Nonce (Number used once)」的主要用途是？",
        "options": [
            "(A) 增加加密強度",
            "(B) 防止重送攻擊 (Replay Attack) 與確保加密唯一性",
            "(C) 作為私鑰",
            "(D) 壓縮資料"
        ],
        "answer": "B",
        "note": "Nonce 保證即使相同訊息被加密兩次，其密文也會不同，且舊的訊息無法被重送驗證。"
    },
    {
        "id": "B9-Prot-24",
        "question": "關於 WPA2 的 KRACK (Key Reinstallation Attack) 攻擊，其針對的是？",
        "options": [
            "(A) 密碼複雜度",
            "(B) 四向交握 (4-way Handshake) 過程中的金鑰重裝漏洞",
            "(C) 路由器硬體",
            "(D) WPS 功能"
        ],
        "answer": "B",
        "note": "KRACK 迫使客戶端重置 Nonce，導致加密金鑰流重複使用，進而解密流量。"
    },
    {
        "id": "B9-Prot-25",
        "question": "下列何者是主動防禦技術 (Active Defense) 的例子？",
        "options": [
            "(A) 定期備份",
            "(B) 蜜罐 (Honeypot) 與蜜標 (Honeytoken)",
            "(C) 防火牆",
            "(D) 防毒軟體"
        ],
        "answer": "B",
        "note": "主動防禦透過欺敵技術 (Deception) 誘捕攻擊者，增加其攻擊成本。"
    },
    {
        "id": "B9-Prot-26",
        "question": "關於 LDAP Injection，攻擊者試圖操控的是？",
        "options": [
            "(A) 網頁顯示內容",
            "(B) 對目錄服務 (Directory Service) 的查詢語句",
            "(C) 資料庫 SQL 語句",
            "(D) 作業系統指令"
        ],
        "answer": "B",
        "note": "針對 LDAP (如 AD) 的查詢語法進行注入，可能繞過認證或竊取目錄資訊。"
    },
    {
        "id": "B9-Prot-27",
        "question": "在電子郵件安全中，DKIM (DomainKeys Identified Mail) 的功能是？",
        "options": [
            "(A) 加密郵件內容",
            "(B) 透過數位簽章驗證郵件在傳輸過程中未被竄改，並確認發信網域",
            "(C) 掃描病毒",
            "(D) 備份郵件"
        ],
        "answer": "B",
        "note": "DKIM 在郵件標頭加入簽章，接收端透過 DNS 查詢公鑰驗證。"
    },
    {
        "id": "B9-Prot-28",
        "question": "關於「撞庫攻擊 (Credential Stuffing)」，其成功的前提是？",
        "options": [
            "(A) 攻擊者擁有超級電腦",
            "(B) 使用者在不同網站使用相同的帳號密碼",
            "(C) 目標網站沒有防火牆",
            "(D) 目標網站使用 HTTPS"
        ],
        "answer": "B",
        "note": "撞庫利用使用者「密碼重複使用」的習慣，拿 A 站洩漏的帳密去試 B 站。"
    },
    {
        "id": "B9-Prot-29",
        "question": "下列哪種 VPN 協定通常被防火牆阻擋的機率最低？",
        "options": [
            "(A) PPTP (TCP 1723)",
            "(B) IPsec (UDP 500/4500)",
            "(C) SSL VPN (TCP 443)",
            "(D) L2TP (UDP 1701)"
        ],
        "answer": "C",
        "note": "SSL VPN 使用 HTTPS (443) 埠口，與一般網頁流量難以區分，穿透性最好。"
    },
    {
        "id": "B9-Prot-30",
        "question": "關於「藍牙安全」，Bluejacking 是指？",
        "options": [
            "(A) 竊取手機資料",
            "(B) 透過藍牙發送未經請求的訊息 (騷擾)",
            "(C) 控制手機撥號",
            "(D) 監聽通話"
        ],
        "answer": "B",
        "note": "Bluejacking 僅是發送訊息騷擾；Bluesnarfing 才是竊取資料。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch9 = [
    // --- 政策與法規 ---
    {
        "id": "B9-Plan-01",
        "question": "在資安政策中，針對「不可否認性 (Non-repudiation)」的需求，通常透過什麼技術實現？",
        "options": [
            "(A) 數位簽章 (Digital Signature) 與日誌紀錄",
            "(B) 資料加密",
            "(C) 防火牆",
            "(D) 備份"
        ],
        "answer": "A",
        "note": "數位簽章能證明「是誰做的」且「內容未改」，防止當事人抵賴。"
    },
    {
        "id": "B9-Plan-02",
        "question": "關於「需知原則 (Need-to-Know)」，其含義為？",
        "options": [
            "(A) 員工有權知道公司所有秘密",
            "(B) 員工僅能存取其執行工作所「必需」的資訊",
            "(C) 主管必須知道員工的所有私事",
            "(D) 客戶必須知道公司的技術細節"
        ],
        "answer": "B",
        "note": "需知原則是存取控制的基石，防止資訊過度授權。"
    },
    {
        "id": "B9-Plan-03",
        "question": "依據《資通安全管理法》，公務機關應定期進行「資通安全健診」，其中「網路架構檢視」的目的為何？",
        "options": [
            "(A) 檢查網速",
            "(B) 檢視網路設備設定、拓撲結構是否存在單點失效或安全漏洞",
            "(C) 計算設備折舊",
            "(D) 整理網路線"
        ],
        "answer": "B",
        "note": "架構檢視旨在發現設計層面的弱點，如缺乏隔離、HA 不足等。"
    },
    {
        "id": "B9-Plan-04",
        "question": "關於 ISO 27001 的「有效性量測 (Measurement of Effectiveness)」，下列指標何者較佳？",
        "options": [
            "(A) 資安政策的頁數",
            "(B) 員工完成資安教育訓練的百分比與測驗合格率",
            "(C) 購買防毒軟體的金額",
            "(D) 開會次數"
        ],
        "answer": "B",
        "note": "好的 KPI 應是 SMART (具體、可量測、可達成、相關、有時效) 的結果指標。"
    },
    {
        "id": "B9-Plan-05",
        "question": "在個資法中，若委外廠商發生個資外洩，委託機關（公務機關）是否需要負責？",
        "options": [
            "(A) 完全不用負責",
            "(B) 視為委託機關自己的故意或過失，需負損害賠償責任",
            "(C) 只有廠商要負責",
            "(D) 由保險公司全權負責"
        ],
        "answer": "B",
        "note": "依個資法第 29 條及施行細則，委託機關有監督之責，受託者之過失視同委託者之過失。"
    },
    // --- 風險管理 ---
    {
        "id": "B9-Plan-06",
        "question": "關於「供應鏈風險」，若供應商使用含有漏洞的開源組件開發軟體交付給公司，這屬於？",
        "options": [
            "(A) 實體安全風險",
            "(B) 軟體供應鏈安全風險",
            "(C) 網路傳輸風險",
            "(D) 人員管理風險"
        ],
        "answer": "B",
        "note": "這是 SBOM (軟體物料清單) 要解決的核心問題。"
    },
    {
        "id": "B9-Plan-07",
        "question": "在風險評鑑中，將風險分為「策略、營運、財務、合規」四大類，這通常參考自哪個框架？",
        "options": [
            "(A) COSO ERM",
            "(B) OWASP",
            "(C) ITIL",
            "(D) Agile"
        ],
        "answer": "A",
        "note": "COSO 企業風險管理框架 (ERM) 是廣泛使用的企業層級風險架構。"
    },
    {
        "id": "B9-Plan-08",
        "question": "關於「定性風險分析」的優點，下列何者正確？",
        "options": [
            "(A) 計算精確的財務損失",
            "(B) 快速、簡單，易於溝通風險優先順序",
            "(C) 需要大量的歷史數據",
            "(D) 消除所有主觀判斷"
        ],
        "answer": "B",
        "note": "定性分析 (高/中/低) 適合快速篩選風險，但不夠精確。"
    },
    {
        "id": "B9-Plan-09",
        "question": "在風險矩陣中，位於「高衝擊、高可能性」區域的風險，應採取的策略通常是？",
        "options": [
            "(A) 接受",
            "(B) 立即處理 (降低或規避)",
            "(C) 忽略",
            "(D) 觀察"
        ],
        "answer": "B",
        "note": "這是不可容忍的風險 (Intolerable Risk)，必須優先處理。"
    },
    {
        "id": "B9-Plan-10",
        "question": "關於「固有風險 (Inherent Risk)」與「殘餘風險 (Residual Risk)」的關係，下列公式何者正確？",
        "options": [
            "(A) 殘餘風險 = 固有風險 + 控制措施",
            "(B) 殘餘風險 = 固有風險 - 控制措施的效果",
            "(C) 固有風險 = 殘餘風險 - 控制措施",
            "(D) 兩者相等"
        ],
        "answer": "B",
        "note": "固有風險是未經處理的原始風險；實施控制後剩下的就是殘餘風險。"
    },
    // --- 營運持續 (BCP) ---
    {
        "id": "B9-Plan-11",
        "question": "在 BCP 中，決定「啟動備援中心」的權限通常屬於？",
        "options": [
            "(A) 值班工程師",
            "(B) 災害復原小組指揮官 (通常為高階主管)",
            "(C) 廠商業務",
            "(D) 保全人員"
        ],
        "answer": "B",
        "note": "啟動備援涉及重大成本與營運變更，需由授權的高階主管決策。"
    },
    {
        "id": "B9-Plan-12",
        "question": "關於「備份資料的驗證」，下列做法何者最佳？",
        "options": [
            "(A) 只要備份軟體顯示成功即可",
            "(B) 定期執行還原測試 (Restore Test)，確認資料可讀且完整",
            "(C) 用肉眼檢查檔案大小",
            "(D) 從不驗證"
        ],
        "answer": "B",
        "note": "未經還原測試的備份，不能視為有效備份。"
    },
    {
        "id": "B9-Plan-13",
        "question": "關於「紙本資料」的備援，下列何者是 BCP 的考量點？",
        "options": [
            "(A) 紙本資料不重要",
            "(B) 重要合約、法律文件應數位化並異地備份",
            "(C) 影印多份放在辦公桌上",
            "(D) 燒毀以免外洩"
        ],
        "answer": "B",
        "note": "關鍵紙本資產 (Vital Records) 亦須納入備份計畫 (如數位化存檔)。"
    },
    {
        "id": "B9-Plan-14",
        "question": "在災難發生時，BCP 團隊的首要任務是？",
        "options": [
            "(A) 通知媒體",
            "(B) 確保員工與客戶的人身安全",
            "(C) 搶救電腦",
            "(D) 計算損失"
        ],
        "answer": "B",
        "note": "生命安全 (Life Safety) 永遠是第一優先。"
    },
    {
        "id": "B9-Plan-15",
        "question": "關於「單點失效 (Single Point of Failure, SPoF)」，下列何者是消除 SPoF 的方法？",
        "options": [
            "(A) 使用單一 ISP 線路",
            "(B) 建立冗餘機制 (Redundancy)，如 HA 架構、雙電源、雙線路",
            "(C) 購買最貴的設備",
            "(D) 減少設備數量"
        ],
        "answer": "B",
        "note": "冗餘 (Redundancy) 是消除單點失效、提升可用性的核心技術。"
    },
    // --- 稽核與合規 ---
    {
        "id": "B9-Plan-16",
        "question": "在資安稽核中，「抽樣 (Sampling)」的風險是？",
        "options": [
            "(A) 樣本太少，無法代表母體，導致未能發現重大缺失",
            "(B) 樣本太多，浪費時間",
            "(C) 稽核員太累",
            "(D) 沒有風險"
        ],
        "answer": "A",
        "note": "抽樣風險 (Sampling Risk) 指樣本結果與母體實際狀況不一致的風險。"
    },
    {
        "id": "B9-Plan-17",
        "question": "關於 ISO 27001 稽核，若發現輕微不符合 (Minor Nonconformity)，通常稽核員會？",
        "options": [
            "(A) 立即撤銷證書",
            "(B) 要求受稽方提出矯正措施計畫，並在下次稽核時確認",
            "(C) 當作沒看到",
            "(D) 罰款"
        ],
        "answer": "B",
        "note": "Minor 缺失需提矯正計畫；Major 缺失可能導致證書保留或無法通過。"
    },
    {
        "id": "B9-Plan-18",
        "question": "下列何者是 PCI DSS (支付卡產業資料安全標準) 的核心要求？",
        "options": [
            "(A) 保護持卡人資料",
            "(B) 增加刷卡手續費",
            "(C) 推廣行動支付",
            "(D) 收集客戶個資"
        ],
        "answer": "A",
        "note": "PCI DSS 旨在保護信用卡交易安全與持卡人資料 (CHD)。"
    },
    {
        "id": "B9-Plan-19",
        "question": "關於「法規遵循 (Compliance)」，組織應建立什麼清單以確保合規？",
        "options": [
            "(A) 員工生日清單",
            "(B) 適用法律法規與契約要求清單 (Legal Register)",
            "(C) 採購清單",
            "(D) 軟體清單"
        ],
        "answer": "B",
        "note": "識別並維護適用的法律法規清單是合規管理的基礎。"
    },
    {
        "id": "B9-Plan-20",
        "question": "在資安治理中，董事會 (Board of Directors) 的責任是？",
        "options": [
            "(A) 設定防火牆",
            "(B) 監督資安策略、風險胃納與資源分配",
            "(C) 執行滲透測試",
            "(D) 安裝防毒軟體"
        ],
        "answer": "B",
        "note": "董事會負有監督 (Oversight) 與治理責任，而非執行細節。"
    },
    // --- 技術管理 ---
    {
        "id": "B9-Plan-21",
        "question": "關於「變更管理委員會 (CAB, Change Advisory Board)」的功能，下列何者正確？",
        "options": [
            "(A) 負責寫程式",
            "(B) 評估變更請求 (RFC) 的風險、衝擊與優先順序，並決定是否核准",
            "(C) 負責修電腦",
            "(D) 負責教育訓練"
        ],
        "answer": "B",
        "note": "CAB 是變更管理流程中的決策組織，確保變更不會造成負面影響。"
    },
    {
        "id": "B9-Plan-22",
        "question": "關於「組態管理 (Configuration Management)」，基準線 (Baseline) 的用途是？",
        "options": [
            "(A) 畫圖用的線",
            "(B) 作為系統標準安全設定的參考點，用於偵測未經授權的變更",
            "(C) 網路線的長度",
            "(D) 預算的底線"
        ],
        "answer": "B",
        "note": "Baseline (如 GCB) 是確保系統安全設定一致性的標準。"
    },
    {
        "id": "B9-Plan-23",
        "question": "在 SSDLC 中，對於「外包開發」的專案，最重要的資安管控是？",
        "options": [
            "(A) 壓低價格",
            "(B) 在合約中明訂資安需求 (如弱點掃描、原始碼檢測) 與驗收標準",
            "(C) 要求廠商加班",
            "(D) 不需管控"
        ],
        "answer": "B",
        "note": "合約是約束外包商履行資安義務的法律依據。"
    },
    {
        "id": "B9-Plan-24",
        "question": "關於「容量管理 (Capacity Management)」的資安意涵，下列何者正確？",
        "options": [
            "(A) 預測硬碟何時會滿，避免因資源耗盡導致服務中斷 (DoS)",
            "(B) 計算辦公室容量",
            "(C) 增加電池容量",
            "(D) 與資安無關"
        ],
        "answer": "A",
        "note": "資源耗盡是可用性 (Availability) 的重大威脅。"
    },
    {
        "id": "B9-Plan-25",
        "question": "關於「網路存取控制 (NAC)」系統，其主要功能是？",
        "options": [
            "(A) 加速網路",
            "(B) 在設備連入網路前，檢查其身分與健康狀態 (如是否安裝防毒)，符合政策才允許連線",
            "(C) 備份網路設定",
            "(D) 監控員工上網行為"
        ],
        "answer": "B",
        "note": "NAC 是實施端點安全合規檢查與存取控制的閘門。"
    },
    // --- 綜合情境 ---
    {
        "id": "B9-Plan-26",
        "question": "某員工收到釣魚郵件並回報給資安團隊，資安團隊確認為惡意郵件後，下一步應採取的最佳行動是？",
        "options": [
            "(A) 刪除該員工電腦",
            "(B) 全面搜尋並刪除組織內其他員工信箱中的相同郵件，並發布警訊",
            "(C) 嘲笑該員工",
            "(D) 不做任何事"
        ],
        "answer": "B",
        "note": "這屬於圍堵 (Containment) 措施，防止其他員工受害。"
    },
    {
        "id": "B9-Plan-27",
        "question": "關於「資料保存 (Data Retention)」政策，下列何者正確？",
        "options": [
            "(A) 所有資料都要永久保存",
            "(B) 依據法律法規與業務需求設定保存期限，期限屆滿應安全銷毀",
            "(C) 硬碟滿了再刪",
            "(D) 由員工自行決定"
        ],
        "answer": "B",
        "note": "過度保存資料會增加外洩風險與合規成本 (如個資法刪除權)。"
    },
    {
        "id": "B9-Plan-28",
        "question": "在資安事故處理中，若涉及刑事案件，應優先考慮？",
        "options": [
            "(A) 立即重灌系統",
            "(B) 保護現場與證據，避免破壞鑑識跡證，並聯繫檢警單位",
            "(C) 私下和解",
            "(D) 公布駭客資料"
        ],
        "answer": "B",
        "note": "涉及犯罪時，證據保全 (Forensics) 優先於快速復原。"
    },
    {
        "id": "B9-Plan-29",
        "question": "關於「漏洞揭露 (Vulnerability Disclosure)」政策，負責任的揭露 (Responsible Disclosure) 是指？",
        "options": [
            "(A) 發現漏洞直接貼在臉書",
            "(B) 私下通知廠商，給予修補時間後再公開",
            "(C) 販賣漏洞給黑市",
            "(D) 威脅廠商付錢"
        ],
        "answer": "B",
        "note": "負責任揭露給予廠商修補機會，保護大眾安全。"
    },
    {
        "id": "B9-Plan-30",
        "question": "關於「資安意識 (Security Awareness)」的成效評估，除了測驗成績外，還可以觀察？",
        "options": [
            "(A) 員工的身高",
            "(B) 員工主動回報可疑事件的數量與品質",
            "(C) 電腦開機速度",
            "(D) 網路流量大小"
        ],
        "answer": "B",
        "note": "主動回報率是衡量資安文化 (Security Culture) 建立與否的重要指標。"
    }
];

// 將 Batch 9 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch9);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch9);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第十批次 (Batch 10)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：行動安全、工控協定、系統強化、績效指標
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch10 = [
    // --- 行動裝置與無線安全 ---
    {
        "id": "B10-Prot-01",
        "question": "Android 應用程式中，為了防止敏感資料被備份到雲端或其他裝置，應在 `AndroidManifest.xml` 設定什麼屬性？",
        "options": [
            "(A) android:debuggable=\"false\"",
            "(B) android:allowBackup=\"false\"",
            "(C) android:exported=\"false\"",
            "(D) android:permission=\"false\""
        ],
        "answer": "B",
        "note": "若未關閉備份功能，攻擊者可透過 ADB 備份匯出 App 資料並還原分析。"
    },
    {
        "id": "B10-Prot-02",
        "question": "iOS 系統的「Secure Enclave」主要用途為何？",
        "options": [
            "(A) 加速圖形運算",
            "(B) 一個獨立的硬體安全處理器，專門處理 TouchID/FaceID 生物特徵與加密金鑰，主處理器無法直接讀取",
            "(C) 儲存照片",
            "(D) 管理電池壽命"
        ],
        "answer": "B",
        "note": "Secure Enclave 提供了硬體級別的金鑰保護，即使 iOS 核心被駭也無法直接讀取生物特徵。"
    },
    {
        "id": "B10-Prot-03",
        "question": "關於 Zigbee 無線協定的安全性，下列敘述何者正確？",
        "options": [
            "(A) 預設完全不加密",
            "(B) 使用 AES-128 加密，但若使用預設的 Trust Center Link Key (如 'ZigBeeAlliance09') 則易被嗅探破解",
            "(C) 傳輸距離比 Wi-Fi 遠",
            "(D) 使用 5GHz 頻段"
        ],
        "answer": "B",
        "note": "IoT 設備若使用 Zigbee 預設金鑰，攻擊者可在配對過程中攔截並解密網路金鑰。"
    },
    {
        "id": "B10-Prot-04",
        "question": "在行動 App 安全檢測中，檢測「URL Scheme」漏洞的主要目的是防止？",
        "options": [
            "(A) SQL Injection",
            "(B) 惡意 App 透過特定的 URL Scheme 喚起受測 App 並傳入惡意參數，導致功能濫用或資料外洩",
            "(C) 耗電量增加",
            "(D) 螢幕截圖"
        ],
        "answer": "B",
        "note": "Custom URL Scheme 若未驗證來源或參數，可能成為攻擊入口 (Deep Link 攻擊)。"
    },
    {
        "id": "B10-Prot-05",
        "question": "關於 Bluetooth Low Energy (BLE) 的安全風險，下列何者正確？",
        "options": [
            "(A) BLE 訊號無法被側錄",
            "(B) 在配對 (Pairing) 過程中，若使用 Just Works 模式，容易受到中間人攻擊 (MITM)",
            "(C) BLE 不支援加密",
            "(D) 只能連線 1 公尺"
        ],
        "answer": "B",
        "note": "Just Works 模式不進行身分驗證，攻擊者可輕易攔截並偽造連線。"
    },
    // --- 系統強化與防禦 ---
    {
        "id": "B10-Prot-06",
        "question": "在 Linux 系統中，SELinux (Security-Enhanced Linux) 的 `Enforcing` 模式代表？",
        "options": [
            "(A) 僅記錄違規行為但不阻擋",
            "(B) 強制執行安全性原則，阻擋違反策略的行為",
            "(C) 關閉 SELinux",
            "(D) 允許所有行為"
        ],
        "answer": "B",
        "note": "Enforcing 是強制模式；Permissive 是寬容模式 (僅紀錄)；Disabled 是關閉。"
    },
    {
        "id": "B10-Prot-07",
        "question": "Windows 的 AppLocker 主要功能為何？",
        "options": [
            "(A) 加密應用程式",
            "(B) 限制哪些使用者或群組可以執行哪些應用程式 (白名單機制)",
            "(C) 備份應用程式",
            "(D) 監控 CPU 使用率"
        ],
        "answer": "B",
        "note": "AppLocker 是比傳統軟體限制原則 (SRP) 更進階的應用程式控制工具。"
    },
    {
        "id": "B10-Prot-08",
        "question": "關於「ASLR (Address Space Layout Randomization)」保護機制，其作用是？",
        "options": [
            "(A) 加密記憶體內容",
            "(B) 隨機配置程式執行時的記憶體位址 (如 Stack, Heap, Libs)，增加緩衝區溢位攻擊的難度",
            "(C) 隨機產生密碼",
            "(D) 隨機更換 IP"
        ],
        "answer": "B",
        "note": "ASLR 讓攻擊者難以預測記憶體位址，導致 Shellcode 無法準確跳轉。"
    },
    {
        "id": "B10-Prot-09",
        "question": "在網頁伺服器設定中，隱藏版本號 (如 Server: Apache/2.4.41 -> Server: Apache) 的目的是？",
        "options": [
            "(A) 節省頻寬",
            "(B) 防止攻擊者利用特定版本的已知漏洞進行精確攻擊 (Security through Obscurity)",
            "(C) 增加相容性",
            "(D) 提升 SEO"
        ],
        "answer": "B",
        "note": "雖然不能修補漏洞，但可增加攻擊者資訊蒐集的成本 (Banner Grabbing)。"
    },
    {
        "id": "B10-Prot-10",
        "question": "Windows Defender Credential Guard 利用什麼技術來保護 LSASS 記憶體中的憑證？",
        "options": [
            "(A) 防火牆",
            "(B) 虛擬化型安全性 (VBS - Virtualization-based Security)",
            "(C) 檔案權限",
            "(D) 網路隔離"
        ],
        "answer": "B",
        "note": "Credential Guard 將機敏資訊隔離在獨立的虛擬容器中，即使管理者權限也無法直接讀取。"
    },
    // --- 網路協定與工控安全 ---
    {
        "id": "B10-Prot-11",
        "question": "Modbus TCP 協定在設計上的主要資安缺陷為何？",
        "options": [
            "(A) 傳輸速度太慢",
            "(B) 缺乏身分驗證與加密機制，攻擊者可輕易注入惡意指令",
            "(C) 只能在 Windows 執行",
            "(D) 不支援乙太網路"
        ],
        "answer": "B",
        "note": "傳統工控協定 (Modbus, DNP3) 多無資安設計，需依賴網路隔離或封包檢查。"
    },
    {
        "id": "B10-Prot-12",
        "question": "在 OSI 模型中，WAF (Web Application Firewall) 主要運作於哪一層？",
        "options": [
            "(A) Layer 3 (Network)",
            "(B) Layer 4 (Transport)",
            "(C) Layer 7 (Application)",
            "(D) Layer 2 (Data Link)"
        ],
        "answer": "C",
        "note": "WAF 解析 HTTP/HTTPS 內容，屬於應用層防護。"
    },
    {
        "id": "B10-Prot-13",
        "question": "關於 SNMPv3 的 `AuthPriv` 安全層級，代表什麼意思？",
        "options": [
            "(A) 不認證、不加密",
            "(B) 有認證、不加密",
            "(C) 有認證 (Authentication) 且有加密 (Privacy)",
            "(D) 只有加密"
        ],
        "answer": "C",
        "note": "AuthPriv 是 SNMPv3 最安全的模式 (AuthNoPriv=認證無加密, NoAuthNoPriv=無認證無加密)。"
    },
    {
        "id": "B10-Prot-14",
        "question": "攻擊者使用 `hping3 -S -p 80 --flood` 指令，是在發動什麼攻擊？",
        "options": [
            "(A) Ping of Death",
            "(B) SYN Flood DDoS",
            "(C) UDP Flood",
            "(D) HTTP Get Flood"
        ],
        "answer": "B",
        "note": "`-S` 代表 SYN 旗標，`--flood` 代表盡快發送，這是典型的 SYN Flood。"
    },
    {
        "id": "B10-Prot-15",
        "question": "關於 CoAP (Constrained Application Protocol) 協定，主要用於哪種環境？",
        "options": [
            "(A) 高頻寬影音串流",
            "(B) 資源受限的 IoT 設備 (基於 UDP)",
            "(C) 大型資料庫同步",
            "(D) 網頁瀏覽"
        ],
        "answer": "B",
        "note": "CoAP 是輕量級 IoT 協定，類似 HTTP 但基於 UDP，需透過 DTLS 加密。"
    },
    // --- 密碼學與鑑識應用 ---
    {
        "id": "B10-Prot-16",
        "question": "在密碼學中，「生日攻擊 (Birthday Attack)」主要用來尋找什麼？",
        "options": [
            "(A) 私鑰",
            "(B) 雜湊碰撞 (Hash Collision)",
            "(C) 對稱金鑰",
            "(D) 隨機數種子"
        ],
        "answer": "B",
        "note": "生日悖論指出，在較小的群體中，兩人機率生日相同的機率比直覺高，用於尋找雜湊碰撞。"
    },
    {
        "id": "B10-Prot-17",
        "question": "數位鑑識中，若要復原已刪除的檔案，主要依賴什麼技術？",
        "options": [
            "(A) File Carving (檔案雕刻)",
            "(B) Port Scanning",
            "(C) Packet Sniffing",
            "(D) Log Analysis"
        ],
        "answer": "A",
        "note": "File Carving 透過搜尋檔案標頭 (Header) 與結尾 (Footer) 標記，從未分配磁區還原資料。"
    },
    {
        "id": "B10-Prot-18",
        "question": "關於 TLS 憑證中的 SAN (Subject Alternative Name) 欄位，其功能為？",
        "options": [
            "(A) 記錄 CA 的名字",
            "(B) 允許單一憑證保護多個不同的網域名稱",
            "(C) 記錄憑證過期日",
            "(D) 儲存私鑰"
        ],
        "answer": "B",
        "note": "SAN 擴充了憑證的適用範圍，比傳統 CN (Common Name) 更靈活。"
    },
    {
        "id": "B10-Prot-19",
        "question": "下列哪一種加密演算法是「串流加密 (Stream Cipher)」？",
        "options": [
            "(A) AES",
            "(B) RC4",
            "(C) RSA",
            "(D) DES"
        ],
        "answer": "B",
        "note": "RC4 是串流加密 (逐位元加密)，AES/DES 是區塊加密 (Block Cipher)。RC4 因弱點已不建議使用。"
    },
    {
        "id": "B10-Prot-20",
        "question": "在 JWT (JSON Web Token) 中，簽章 (Signature) 的主要目的是？",
        "options": [
            "(A) 加密 Payload 內容",
            "(B) 確保 Token 在傳輸過程中未被竄改 (Integrity)",
            "(C) 壓縮資料",
            "(D) 隱藏使用者身分"
        ],
        "answer": "B",
        "note": "JWT 的 Payload 只是 Base64Url 編碼 (可解碼讀取)，簽章才是防止竄改的關鍵。"
    },
    // --- 進階攻防 ---
    {
        "id": "B10-Prot-21",
        "question": "攻擊者利用「Blind SQL Injection」時，因為無法直接看到資料庫回傳的錯誤訊息或資料，通常會利用什麼方式判斷？",
        "options": [
            "(A) 觀察網頁回應時間 (Time-based) 或回應內容的真偽差異 (Boolean-based)",
            "(B) 直接讀取原始碼",
            "(C) 攔截封包",
            "(D) 查看 HTML 註解"
        ],
        "answer": "A",
        "note": "盲注 (Blind Injection) 透過問系統 True/False 問題或延遲時間來逐步推導資料。"
    },
    {
        "id": "B10-Prot-22",
        "question": "關於「勒索軟體即服務 (RaaS)」的運作模式，下列何者正確？",
        "options": [
            "(A) 駭客免費幫企業解密",
            "(B) 開發者提供惡意軟體平台，附屬攻擊者 (Affiliates) 負責入侵，贖金拆帳",
            "(C) 是一種防毒軟體服務",
            "(D) 是一種雲端備份服務"
        ],
        "answer": "B",
        "note": "RaaS 降低了網路犯罪的門檻，導致勒索攻擊氾濫。"
    },
    {
        "id": "B10-Prot-23",
        "question": "在 Web 安全中，CORS (Cross-Origin Resource Sharing) 機制是透過哪個 HTTP Header 來放行跨域請求？",
        "options": [
            "(A) X-Frame-Options",
            "(B) Access-Control-Allow-Origin",
            "(C) Content-Security-Policy",
            "(D) Set-Cookie"
        ],
        "answer": "B",
        "note": "瀏覽器預設同源政策 (SOP)，CORS Header 允許伺服器放寬限制。"
    },
    {
        "id": "B10-Prot-24",
        "question": "下列何者是「主動式內容 (Active Content)」帶來的風險？",
        "options": [
            "(A) 純文字檔佔用空間",
            "(B) Office 文件中的巨集 (Macro) 或 PDF 中的 JavaScript 自動執行惡意代碼",
            "(C) 圖片解析度太低",
            "(D) 影片無法播放"
        ],
        "answer": "B",
        "note": "許多惡意軟體透過含巨集的 Word/Excel 檔進行傳播。"
    },
    {
        "id": "B10-Prot-25",
        "question": "關於「字典攻擊 (Dictionary Attack)」與「暴力破解 (Brute Force)」的差異？",
        "options": [
            "(A) 兩者完全相同",
            "(B) 字典攻擊嘗試常用字詞列表；暴力破解嘗試所有可能的字元組合",
            "(C) 暴力破解比較快",
            "(D) 字典攻擊一定能成功"
        ],
        "answer": "B",
        "note": "字典攻擊效率較高但範圍有限；暴力破解覆蓋率 100% 但耗時極長。"
    },
    {
        "id": "B10-Prot-26",
        "question": "在資安事件中，若發現系統日誌被清除 (Event ID 1102)，最可能的意圖是？",
        "options": [
            "(A) 節省硬碟空間",
            "(B) 攻擊者試圖湮滅證據 (Anti-forensics)",
            "(C) 系統自動維護",
            "(D) 更新失敗"
        ],
        "answer": "B",
        "note": "日誌清除是攻擊者在 Post-exploitation 階段常見的行為。"
    },
    {
        "id": "B10-Prot-27",
        "question": "關於「中間人攻擊 (MITM)」，下列何者是 ARP Spoofing 造成的結果？",
        "options": [
            "(A) 伺服器當機",
            "(B) 流量被導向攻擊者的機器，攻擊者可竊聽或竄改後再轉送",
            "(C) 網路速度變快",
            "(D) 防火牆失效"
        ],
        "answer": "B",
        "note": "ARP Spoofing 欺騙受害者與閘道，使其誤認攻擊者為對方。"
    },
    {
        "id": "B10-Prot-28",
        "question": "下列哪種工具主要用於自動化 SQL Injection 檢測與利用？",
        "options": [
            "(A) Nmap",
            "(B) SQLMap",
            "(C) Wireshark",
            "(D) John the Ripper"
        ],
        "answer": "B",
        "note": "SQLMap 是開源且強大的 SQL 注入工具。"
    },
    {
        "id": "B10-Prot-29",
        "question": "在實體安全中，防止「尾隨 (Tailgating)」的最佳設施是？",
        "options": [
            "(A) 監視器",
            "(B) 警示標語",
            "(C) 曼通門 / 雙重互鎖門 (Mantrap)",
            "(D) 一般刷卡機"
        ],
        "answer": "C",
        "note": "Mantrap 一次僅允許一人通過，有效防止尾隨。"
    },
    {
        "id": "B10-Prot-30",
        "question": "關於 EDR 的「隔離主機 (Network Isolation)」功能，通常會保留與哪裡的連線？",
        "options": [
            "(A) 網際網路",
            "(B) 內部檔案伺服器",
            "(C) 僅保留與 EDR 管理伺服器的連線，以利進行遠端調查",
            "(D) 切斷所有連線"
        ],
        "answer": "C",
        "note": "完全斷網會導致無法遠端調查，故需保留管理通道。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch10 = [
    // --- 治理與法規 (進階) ---
    {
        "id": "B10-Plan-01",
        "question": "在風險管理指標中，KRI (Key Risk Indicator) 與 KPI (Key Performance Indicator) 的區別為何？",
        "options": [
            "(A) 兩者相同",
            "(B) KPI 衡量績效目標達成率（回顧）；KRI 預警潛在風險發生的可能性（前瞻）",
            "(C) KPI 是負面的，KRI 是正面的",
            "(D) KRI 只能用於財務"
        ],
        "answer": "B",
        "note": "KRI 是早期預警指標，用來預測風險是否即將超過胃納。"
    },
    {
        "id": "B10-Plan-02",
        "question": "ISAE 3402 (或 SSAE 18) 報告主要用於評估什麼？",
        "options": [
            "(A) 產品的安全性",
            "(B) 服務組織 (Service Organization) 的內部控制有效性，常被客戶的稽核員使用",
            "(C) 程式碼品質",
            "(D) 網站流量"
        ],
        "answer": "B",
        "note": "委外服務商常用 SOC 1/SOC 2 (基於 ISAE 3402) 報告來證明其內控健全。"
    },
    {
        "id": "B10-Plan-03",
        "question": "依據資通安全責任等級分級辦法，A 級機關的核心資通系統，應多久進行一次弱點掃描？",
        "options": [
            "(A) 每月",
            "(B) 每季",
            "(C) 每半年 (每年 2 次)",
            "(D) 每年 1 次"
        ],
        "answer": "C",
        "note": "114 概論教材。A 級機關弱掃頻率為每年 2 次；B 級為每年 1 次。"
    },
    {
        "id": "B10-Plan-04",
        "question": "關於「隱私衝擊評估 (PIA)」的時機，下列何者最佳？",
        "options": [
            "(A) 發生個資外洩後",
            "(B) 在開發新系統或變更個資處理流程「之前」",
            "(C) 收到法院傳票時",
            "(D) 每年年底"
        ],
        "answer": "B",
        "note": "Privacy by Design 要求在設計階段即進行 PIA/DPIA。"
    },
    {
        "id": "B10-Plan-05",
        "question": "在資安險中，「第一方損失 (First-party Loss)」通常包含？",
        "options": [
            "(A) 客戶對公司的求償",
            "(B) 監管機構的罰款",
            "(C) 公司本身的資料救援費用、營運中斷損失、鑑識費用",
            "(D) 律師費"
        ],
        "answer": "C",
        "note": "第一方是保險人自己的損失；第三方是他人對保險人的求償。"
    },
    // --- 風險管理與 BCP ---
    {
        "id": "B10-Plan-06",
        "question": "關於「單一損失預期值 (SLE)」的計算，公式為？",
        "options": [
            "(A) SLE = 資產價值 x ARO",
            "(B) SLE = 資產價值 x 暴露因素 (EF)",
            "(C) SLE = ALE / ARO",
            "(D) SLE = 風險 x 衝擊"
        ],
        "answer": "B",
        "note": "SLE 代表單次事件造成的金錢損失。EF 是損失的百分比。"
    },
    {
        "id": "B10-Plan-07",
        "question": "在 BCP 中，決定 RTO 的主要依據是？",
        "options": [
            "(A) IT 人員的能力",
            "(B) BIA (營運衝擊分析) 中評估的業務中斷損失隨時間的變化",
            "(C) 備份軟體的速度",
            "(D) 老闆的直覺"
        ],
        "answer": "B",
        "note": "RTO 應基於業務需求 (損失容忍度) 設定，而非 IT 技術限制。"
    },
    {
        "id": "B10-Plan-08",
        "question": "關於「供應鏈資安」，若供應商無法提供 SBOM，企業應採取何種緩解措施？",
        "options": [
            "(A) 拒絕交易",
            "(B) 自行進行軟體組成分析 (SCA) 或要求加強弱點掃描與滲透測試",
            "(C) 忽略風險",
            "(D) 簽署免責聲明"
        ],
        "answer": "B",
        "note": "SCA 工具可協助識別軟體中的開源組件風險。"
    },
    {
        "id": "B10-Plan-09",
        "question": "風險矩陣中，將風險分為「極高、高、中、低」是為了？",
        "options": [
            "(A) 計算精確損失",
            "(B) 決定風險處理的優先順序 (Prioritization)",
            "(C) 應付稽核",
            "(D) 畫圖好看"
        ],
        "answer": "B",
        "note": "資源有限，必須優先處理高等級風險。"
    },
    {
        "id": "B10-Plan-10",
        "question": "關於「風險擁有者 (Risk Owner)」的職責，下列何者錯誤？",
        "options": [
            "(A) 必須是該資產或流程的負責人",
            "(B) 負責核准風險處理計畫",
            "(C) 負責承擔殘餘風險",
            "(D) 必須親自執行修補技術工作"
        ],
        "answer": "D",
        "note": "Risk Owner 負責決策與當責，執行面通常由 IT 或資安人員負責。"
    },
    // --- 稽核與管理實務 ---
    {
        "id": "B10-Plan-11",
        "question": "在 ISO 27001 稽核中，若發現「未執行管理審查」，這通常被判定為？",
        "options": [
            "(A) 觀察事項 (Observation)",
            "(B) 輕微不符合 (Minor Nonconformity)",
            "(C) 嚴重不符合 (Major Nonconformity)",
            "(D) 改進機會"
        ],
        "answer": "C",
        "note": "管理審查是 ISMS PDCA 的核心要求，完全未執行屬系統性失效，為嚴重缺失。"
    },
    {
        "id": "B10-Plan-12",
        "question": "關於「屬性抽樣 (Attribute Sampling)」在稽核中的應用，通常用於測試？",
        "options": [
            "(A) 金額大小",
            "(B) 控制措施的遵循性 (遵行/未遵行，Yes/No)",
            "(C) 系統效能",
            "(D) 員工人數"
        ],
        "answer": "B",
        "note": "屬性抽樣用於符合性測試 (如：申請單是否有簽名)；變量抽樣用於實質性測試。"
    },
    {
        "id": "B10-Plan-13",
        "question": "下列何者是 ISO 27002:2022 新增的控制措施？",
        "options": [
            "(A) 存取控制",
            "(B) 威脅情資 (Threat Intelligence) 與雲端服務使用安全",
            "(C) 密碼管理",
            "(D) 實體安全"
        ],
        "answer": "B",
        "note": "2022 版新增了威脅情資、雲端安全、資料遮罩等現代化控制措施。"
    },
    {
        "id": "B10-Plan-14",
        "question": "關於「資產盤點」的範圍，除了硬體與軟體，還應包含？",
        "options": [
            "(A) 資訊資產 (資料)、人員、服務與實體環境",
            "(B) 只有電腦",
            "(C) 只有伺服器",
            "(D) 只有網路設備"
        ],
        "answer": "A",
        "note": "資產 (Asset) 定義為「對組織有價值的任何事物」。"
    },
    {
        "id": "B10-Plan-15",
        "question": "在變更管理中，「緊急變更 (Emergency Change)」的流程特性是？",
        "options": [
            "(A) 不需要核准",
            "(B) 不需要測試",
            "(C) 可先取得口頭或簡化授權後實施，但事後必須補辦完整程序與文件",
            "(D) 隨時可以做"
        ],
        "answer": "C",
        "note": "緊急變更仍需受控，只是授權流程加速，事後需補齊紀錄以維護可歸責性。"
    },
    // --- 雲端與新興科技管理 ---
    {
        "id": "B10-Plan-16",
        "question": "關於雲端安全的「可攜性 (Portability)」要求，主要是為了解決什麼風險？",
        "options": [
            "(A) 駭客攻擊",
            "(B) 廠商鎖定 (Vendor Lock-in)",
            "(C) 資料遺失",
            "(D) 效能不足"
        ],
        "answer": "B",
        "note": "確保能將資料與服務遷移至其他供應商，是雲端退場策略的關鍵。"
    },
    {
        "id": "B10-Plan-17",
        "question": "在 DevOps 中，CI (Continuous Integration) 階段適合引入哪種資安檢測？",
        "options": [
            "(A) 滲透測試",
            "(B) SAST (靜態應用程式安全測試) 與 SCA (軟體組成分析)",
            "(C) 實體稽核",
            "(D) 社交工程演練"
        ],
        "answer": "B",
        "note": "在程式碼合併與建置階段進行 SAST/SCA，可及早發現漏洞 (Shift Left)。"
    },
    {
        "id": "B10-Plan-18",
        "question": "關於「影子 IT (Shadow IT)」的管理策略，下列何者較務實？",
        "options": [
            "(A) 絕對禁止並開除違規者",
            "(B) 透過 CASB (雲端存取安全代理) 監控與發現，評估風險後納管或封鎖",
            "(C) 假裝沒看到",
            "(D) 斷網"
        ],
        "answer": "B",
        "note": "Shadow IT 源於業務需求，應以「監控、評估、引導」取代單純禁止。"
    },
    {
        "id": "B10-Plan-19",
        "question": "在 AI 資安中，針對「資料毒化 (Data Poisoning)」的防範，重點在於？",
        "options": [
            "(A) 加密模型",
            "(B) 確保訓練資料的完整性與來源可信度 (Data Provenance)",
            "(C) 增加算力",
            "(D) 使用更複雜的模型"
        ],
        "answer": "B",
        "note": "保護訓練資料集 (Training Data) 的供應鏈安全是防範毒化的核心。"
    },
    {
        "id": "B10-Plan-20",
        "question": "關於容器安全，應避免在容器內使用哪種使用者權限執行應用程式？",
        "options": [
            "(A) 一般使用者",
            "(B) Root (特權使用者)",
            "(C) 服務帳號",
            "(D) 訪客"
        ],
        "answer": "B",
        "note": "容器內的 Root 若發生逃逸，可能取得宿主機的高權限，應遵循最小權限原則。"
    },
    // --- 綜合情境 ---
    {
        "id": "B10-Plan-21",
        "question": "某員工電腦感染勒索軟體，資安人員第一時間「拔除網路線」的目的是？",
        "options": [
            "(A) 根除病毒",
            "(B) 圍堵 (Containment) - 防止疫情擴散至內網其他主機",
            "(C) 復原資料",
            "(D) 處罰員工"
        ],
        "answer": "B",
        "note": "實體斷網是阻斷橫向移動最直接有效的圍堵手段。"
    },
    {
        "id": "B10-Plan-22",
        "question": "在資安鑑識中，若要證明某員工在特定時間存取了特定檔案，需要依賴？",
        "options": [
            "(A) 員工的自白",
            "(B) 系統日誌 (System/Security Logs) 與檔案存取時間戳記 (MAC Times)",
            "(C) 監視器畫面",
            "(D) 同事證詞"
        ],
        "answer": "B",
        "note": "數位跡證 (Logs & Metadata) 是最具客觀性的技術證據。"
    },
    {
        "id": "B10-Plan-23",
        "question": "關於「社交工程」的防範，除了教育訓練，技術上可透過什麼強化？",
        "options": [
            "(A) SPF/DKIM/DMARC (郵件驗證) 與 郵件沙箱",
            "(B) 防火牆",
            "(C) 資料庫加密",
            "(D) WAF"
        ],
        "answer": "A",
        "note": "這些技術可大幅降低偽冒郵件與惡意附件進入員工信箱的機率。"
    },
    {
        "id": "B10-Plan-24",
        "question": "資安長 (CISO) 在向董事會報告時，應著重於？",
        "options": [
            "(A) 詳細的技術細節與攻擊語法",
            "(B) 資安風險對業務目標的影響 (Business Impact) 與投資效益 (ROI)",
            "(C) 購買了多少設備",
            "(D) 防火牆阻擋了多少次掃描"
        ],
        "answer": "B",
        "note": "高層關注的是風險與業務，而非技術細節。"
    },
    {
        "id": "B10-Plan-25",
        "question": "關於「縱深防禦」，若防火牆失效，下一道防線可能是？",
        "options": [
            "(A) 沒有防線了",
            "(B) IPS (入侵防禦系統) 或 端點防護 (EDR)",
            "(C) 備份",
            "(D) 政策文件"
        ],
        "answer": "B",
        "note": "縱深防禦強調多層次技術堆疊 (網路 -> 主機 -> 應用 -> 資料)。"
    },
    {
        "id": "B10-Plan-26",
        "question": "在個資法中，關於「告知義務」，在蒐集個資時應明確告知當事人？",
        "options": [
            "(A) 公司的股價",
            "(B) 蒐集目的、類別、利用期間/地區/對象/方式、當事人權利",
            "(C) 負責人的生日",
            "(D) 公司的資本額"
        ],
        "answer": "B",
        "note": "這是個資法第 8 條規定的必要告知事項。"
    },
    {
        "id": "B10-Plan-27",
        "question": "關於 BCP 測試，下列何者最能發現計畫中的邏輯錯誤與資源缺口？",
        "options": [
            "(A) 文件審查",
            "(B) 演練 (Exercise/Testing)",
            "(C) 更新通訊錄",
            "(D) 購買設備"
        ],
        "answer": "B",
        "note": "只有透過實際或模擬演練，才能驗證計畫在真實情境下的可行性。"
    },
    {
        "id": "B10-Plan-28",
        "question": "資安政策的審查 (Review) 應至少多久進行一次？",
        "options": [
            "(A) 每月",
            "(B) 每年 (或發生重大變更時)",
            "(C) 每五年",
            "(D) 都不用"
        ],
        "answer": "B",
        "note": "定期 (通常每年) 審查是 ISO 27001 的要求，確保政策持續適用。"
    },
    {
        "id": "B10-Plan-29",
        "question": "下列何者是「特權帳號」的最佳管理方式？",
        "options": [
            "(A) 寫在便利貼上",
            "(B) 導入 PAM (Privileged Access Management) 系統，實施密碼保管與連線側錄",
            "(C) 使用 Excel 管理",
            "(D) 告訴所有 IT 人員"
        ],
        "answer": "B",
        "note": "PAM 系統提供特權帳號的自動化管理、輪換與稽核功能。"
    },
    {
        "id": "B10-Plan-30",
        "question": "在資安治理中，「當責 (Accountability)」與「負責 (Responsibility)」的區別？",
        "options": [
            "(A) 沒區別",
            "(B) 當責者 (如 CISO/高層) 對結果負最終責任；負責者 (如 IT) 執行具體任務",
            "(C) 負責者權力較大",
            "(D) 當責者負責寫程式"
        ],
        "answer": "B",
        "note": "Accountability (當責) 只有一人，Responsibility (負責) 可多人分擔 (RACI 模型)。"
    }
];

// 將 Batch 10 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch10);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch10);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第十一批次 (Batch 11)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：雲端原生安全、Web 進階攻擊、稽核風險、資安韌性
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch11 = [
    // --- Web 與應用程式安全 (進階) ---
    {
        "id": "B11-Prot-01",
        "question": "關於「HTTP Request Smuggling (HTTP 請求走私)」攻擊，其成因主要是？",
        "options": [
            "(A) 前端伺服器 (如 CDN/WAF) 與後端伺服器對 Content-Length 與 Transfer-Encoding 標頭的解析方式不一致",
            "(B) 未使用 HTTPS 加密",
            "(C) Cookie 設定錯誤",
            "(D) 資料庫權限過大"
        ],
        "answer": "A",
        "note": "利用前後端對 HTTP 請求邊界認知的差異，導致後端將攻擊者的請求誤認為下一個合法請求的一部分。"
    },
    {
        "id": "B11-Prot-02",
        "question": "在 JavaScript 應用程式中，「Prototype Pollution (原型汙染)」漏洞允許攻擊者做什麼？",
        "options": [
            "(A) 直接刪除伺服器檔案",
            "(B) 修改 Object.prototype 基礎物件，導致所有物件都繼承惡意屬性，可能引發 DoS 或 RCE",
            "(C) 竊取資料庫密碼",
            "(D) 修改 CSS 樣式"
        ],
        "answer": "B",
        "note": "這是在 Node.js 或前端 JS 框架中常見的嚴重漏洞，常發生在遞迴合併物件 (Merge) 的功能中。"
    },
    {
        "id": "B11-Prot-03",
        "question": "關於 OAuth 2.0 的 PKCE (Proof Key for Code Exchange) 機制，主要用來防禦什麼攻擊？",
        "options": [
            "(A) SQL Injection",
            "(B) Authorization Code Interception Attack (授權碼攔截攻擊)",
            "(C) Brute Force",
            "(D) Phishing"
        ],
        "answer": "B",
        "note": "PKCE 強制客戶端在換取 Token 時出示原始的隨機驗證碼，防止授權碼在回傳過程中被惡意 App 攔截。"
    },
    {
        "id": "B11-Prot-04",
        "question": "在 API 安全中，使用 UUID (Universally Unique Identifier) 取代循序 ID (Sequential ID) 的主要好處是？",
        "options": [
            "(A) 節省資料庫空間",
            "(B) 防止攻擊者透過枚舉 (Enumeration) ID 來爬取資料或猜測業務量",
            "(C) 加快查詢速度",
            "(D) 方便記憶"
        ],
        "answer": "B",
        "note": "循序 ID (如 user/100, user/101) 容易被遍歷攻擊 (Insecure Direct Object Reference)。"
    },
    {
        "id": "B11-Prot-05",
        "question": "關於 SSRF (Server-Side Request Forgery) 的防禦，下列何者是「最無效」的作法？",
        "options": [
            "(A) 使用白名單限制可存取的網域",
            "(B) 僅在應用層過濾 '127.0.0.1' 或 'localhost' 字串 (容易被繞過，如使用 0x7f000001 或 DNS Rebinding)",
            "(C) 網路層防火牆限制伺服器對外連線",
            "(D) 停用不必要的 URL Scheme (如 file://, gopher://)"
        ],
        "answer": "B",
        "note": "黑名單過濾極易被各種編碼或 DNS 重綁定技術繞過，應採白名單或網路層隔離。"
    },
    // --- 雲端原生與容器安全 ---
    {
        "id": "B11-Prot-06",
        "question": "在 Kubernetes (K8s) 中，為了限制受駭 Pod 對 API Server 的存取權限，應設定？",
        "options": [
            "(A) RBAC (Role-Based Access Control) 與 Service Account 權限最小化",
            "(B) 關閉 API Server",
            "(C) 使用更強的 CPU",
            "(D) 設定 Pod 為 Privileged"
        ],
        "answer": "A",
        "note": "預設 Service Account 可能權限過大，應依據最小權限原則設定 Role 與 RoleBinding。"
    },
    {
        "id": "B11-Prot-07",
        "question": "關於「微服務 (Microservices)」架構中的資安挑戰，下列何者正確？",
        "options": [
            "(A) 服務間通訊 (East-West Traffic) 變多，需實施 mTLS (雙向 TLS) 確保內部通訊安全",
            "(B) 只有一個入口需要防護，內部絕對安全",
            "(C) 不需要身分驗證",
            "(D) 只要防火牆夠強就好"
        ],
        "answer": "A",
        "note": "微服務架構下，內部服務間的呼叫頻繁，零信任原則要求內部流量也必須加密與驗證 (通常透過 Service Mesh 實作)。"
    },
    {
        "id": "B11-Prot-08",
        "question": "在 Docker 安全中，使用 `Distroless` 映像檔 (Image) 的主要資安優勢是？",
        "options": [
            "(A) 映像檔體積變大",
            "(B) 移除了 Shell、Package Manager 等不必要的工具，減少攻擊面 (Attack Surface)",
            "(C) 自動修補漏洞",
            "(D) 支援所有程式語言"
        ],
        "answer": "B",
        "note": "Distroless 映像檔只包含應用程式及其依賴，沒有 /bin/bash，讓攻擊者即使入侵也難以執行指令。"
    },
    {
        "id": "B11-Prot-09",
        "question": "關於 CI/CD Pipeline 的安全 (Supply Chain Security)，「簽署 (Signing) 映像檔」的主要目的是？",
        "options": [
            "(A) 加密映像檔內容",
            "(B) 確保映像檔在建置後未被竄改，且來源可信 (Provenance)",
            "(C) 壓縮映像檔",
            "(D) 加速部署"
        ],
        "answer": "B",
        "note": "使用工具如 Cosign 對映像檔簽章，並在部署時透過 Admission Controller 驗證，可防止惡意映像檔被執行。"
    },
    {
        "id": "B11-Prot-10",
        "question": "在雲端環境中，IAM (Identity and Access Management) 的「角色 (Role)」與「使用者 (User)」的主要區別是？",
        "options": [
            "(A) Role 有長期的密碼，User 沒有",
            "(B) User 代表具體的人或服務；Role 是臨時權限的集合，可被 User 或服務暫時扮演 (Assume)",
            "(C) Role 只能給管理員用",
            "(D) 兩者完全相同"
        ],
        "answer": "B",
        "note": "Role 使用臨時憑證 (STS)，比長期金鑰更安全，適合 EC2/Lambda 或跨帳號存取。"
    },
    // --- 數位鑑識與系統深層 ---
    {
        "id": "B11-Prot-11",
        "question": "在 Windows 鑑識中，`NTFS Alternate Data Streams (ADS)` 常被攻擊者用來？",
        "options": [
            "(A) 加速檔案讀取",
            "(B) 將惡意檔案隱藏在合法檔案的背後，而在檔案總管中看不出來",
            "(C) 壓縮檔案",
            "(D) 修復壞軌"
        ],
        "answer": "B",
        "note": "ADS 允許一個檔案擁有多個資料流，攻擊者可將 payload 藏在 `file.txt:evil.exe` 中。"
    },
    {
        "id": "B11-Prot-12",
        "question": "關於 `ShimCache` (或 AppCompatCache) 在鑑識中的價值，下列何者正確？",
        "options": [
            "(A) 記錄了瀏覽器歷史",
            "(B) 記錄了系統中曾經執行過的程式路徑、修改時間與執行旗標，即使檔案已刪除仍可能留存紀錄",
            "(C) 記錄了網路連線",
            "(D) 記錄了開機密碼"
        ],
        "answer": "B",
        "note": "ShimCache 是追蹤惡意程式執行歷史 (Execution Artifacts) 的重要機碼。"
    },
    {
        "id": "B11-Prot-13",
        "question": "在 Linux 鑑識中，若發現 `/proc/[pid]/exe` 的連結指向 `(deleted)`，這通常意味著？",
        "options": [
            "(A) 系統正常",
            "(B) 該行程 (Process) 的執行檔在執行後已被刪除，這是惡意程式隱藏蹤跡的常見手法",
            "(C) 硬碟滿了",
            "(D) 記憶體不足"
        ],
        "answer": "B",
        "note": "攻擊者常在執行惡意程式後立即刪除檔案以躲避掃描，但 Process 仍在記憶體中運作。"
    },
    {
        "id": "B11-Prot-14",
        "question": "關於「勒索軟體」的加密行為偵測，下列何種特徵是 EDR 常用的判斷依據？",
        "options": [
            "(A) 讀取大量檔案",
            "(B) 在短時間內大量修改檔案內容 (高熵值寫入) 並更改副檔名",
            "(C) 網路連線變慢",
            "(D) 螢幕變黑"
        ],
        "answer": "B",
        "note": "勒索軟體的行為特徵是大規模的檔案寫入與高熵值 (Encryption) 操作。"
    },
    {
        "id": "B11-Prot-15",
        "question": "攻擊者使用 `PowerShell -nop -w hidden -c ...` 指令，其意圖為何？",
        "options": [
            "(A) 優化系統效能",
            "(B) 隱藏 PowerShell 視窗並執行惡意指令，避免使用者察覺",
            "(C) 更新 Windows",
            "(D) 備份檔案"
        ],
        "answer": "B",
        "note": "`-w hidden` (WindowStyle Hidden) 是惡意腳本標準的隱匿執行參數。"
    },
    // --- 網路攻防 (進階) ---
    {
        "id": "B11-Prot-16",
        "question": "關於「BGP Hijacking (BGP 劫持)」的防禦機制，RPKI (Resource Public Key Infrastructure) 的作用是？",
        "options": [
            "(A) 加密 BGP 封包",
            "(B) 透過數位簽章驗證 AS (自治系統) 是否有權宣告特定的 IP 前綴 (ROA)",
            "(C) 阻擋所有國外流量",
            "(D) 加速路由收斂"
        ],
        "answer": "B",
        "note": "RPKI 透過 ROA (Route Origin Authorization) 驗證路由宣告的合法性，防止前綴劫持。"
    },
    {
        "id": "B11-Prot-17",
        "question": "在 Wi-Fi 安全中，攻擊者架設「Rogue AP」並使用強訊號覆蓋合法 AP，這是為了執行什麼攻擊？",
        "options": [
            "(A) DoS",
            "(B) Evil Twin (邪惡雙子星) 攻擊，誘使受害者連線後進行中間人攻擊",
            "(C) 破解 WPA3",
            "(D) 增加網速"
        ],
        "answer": "B",
        "note": "Evil Twin 模仿合法 AP 的 SSID 與 MAC，利用訊號強度誘騙裝置自動連線。"
    },
    {
        "id": "B11-Prot-18",
        "question": "關於 TLS 憑證的「OCSP Stapling」技術，其資安與隱私優勢為何？",
        "options": [
            "(A) 加密更強",
            "(B) 由 Web Server 代替瀏覽器向 CA 查詢憑證狀態並「釘選」在握手過程中，保護使用者隱私並提升效能",
            "(C) 不需要憑證",
            "(D) 讓憑證永不過期"
        ],
        "answer": "B",
        "note": "傳統 OCSP 讓 CA 知道使用者造訪了哪些網站 (隱私問題) 且有延遲，Stapling 解決了此問題。"
    },
    {
        "id": "B11-Prot-19",
        "question": "下列哪種 DDoS 攻擊是利用協定的「無狀態 (Stateless)」特性進行反射放大？",
        "options": [
            "(A) HTTP Flood",
            "(B) DNS / NTP Amplification Attack",
            "(C) SYN Flood",
            "(D) Slowloris"
        ],
        "answer": "B",
        "note": "UDP 是無狀態協定，攻擊者可偽造來源 IP，請求 DNS/NTP 伺服器回傳大量回應給受害者。"
    },
    {
        "id": "B11-Prot-20",
        "question": "在防火牆管理中，「Egress Filtering (出口過濾)」的主要資安目的是？",
        "options": [
            "(A) 防止外部攻擊進入",
            "(B) 防止內部受駭主機對外連線 C2 伺服器或發動攻擊 (如偽造來源 IP)",
            "(C) 加速下載",
            "(D) 節省頻寬"
        ],
        "answer": "B",
        "note": "限制內部對外的連線 (Egress) 可阻斷惡意軟體回報或資料外洩的通道。"
    },
    // --- 密碼學與新興技術 ---
    {
        "id": "B11-Prot-21",
        "question": "關於「量子金鑰分發 (QKD)」的特性，下列何者正確？",
        "options": [
            "(A) 可以破解所有密碼",
            "(B) 利用量子力學原理 (如測不準原理)，若通訊被竊聽會干擾量子態，雙方可立即察覺",
            "(C) 不需要光纖",
            "(D) 是一種雜湊函數"
        ],
        "answer": "B",
        "note": "QKD 提供理論上絕對安全的金鑰交換方式，能偵測任何竊聽行為。"
    },
    {
        "id": "B11-Prot-22",
        "question": "在比特幣等區塊鏈中，私鑰遺失意味著什麼？",
        "options": [
            "(A) 可以透過身分證找回",
            "(B) 資產永久遺失，因為沒有中央機構可以重置私鑰",
            "(C) 可以請礦工幫忙",
            "(D) 只要有助記詞就可以重設私鑰"
        ],
        "answer": "B",
        "note": "區塊鏈是去中心化的，私鑰 (或助記詞) 是資產控制的唯一憑證，無法掛失。"
    },
    {
        "id": "B11-Prot-23",
        "question": "關於「零知識證明 (Zero-Knowledge Proof)」的應用，下列何者正確？",
        "options": [
            "(A) 公開所有資料",
            "(B) 在不洩露秘密內容的情況下，向驗證者證明自己知道該秘密 (如證明年滿 18 歲而不透露生日)",
            "(C) 不需要任何證明",
            "(D) 加密所有硬碟"
        ],
        "answer": "B",
        "note": "ZKP 是隱私保護技術的重要突破，常用於身份認證與區塊鏈隱私交易。"
    },
    {
        "id": "B11-Prot-24",
        "question": "下列何者是「同態加密 (Homomorphic Encryption)」在雲端運算中的應用場景？",
        "options": [
            "(A) 加速傳輸",
            "(B) 允許雲端服務商在「加密狀態下」對資料進行搜尋或統計分析，而無需解密看到原始資料",
            "(C) 備份資料",
            "(D) 壓縮影片"
        ],
        "answer": "B",
        "note": "這解決了資料上雲的隱私疑慮，資料在處理過程中全程保持加密。"
    },
    {
        "id": "B11-Prot-25",
        "question": "FIDO2 協定中的 WebAuthn 標準，允許使用者使用什麼進行登入？",
        "options": [
            "(A) 複雜的密碼",
            "(B) 瀏覽器內建的生物辨識或硬體金鑰，無需輸入密碼 (Passwordless)",
            "(C) 電子郵件連結",
            "(D) 簡訊驗證碼"
        ],
        "answer": "B",
        "note": "WebAuthn 是 FIDO2 的核心，推動無密碼登入的普及。"
    },
    // --- 綜合防護 ---
    {
        "id": "B11-Prot-26",
        "question": "針對「供應鏈軟體更新」的安全性，TUF (The Update Framework) 提供了什麼保護？",
        "options": [
            "(A) 加速下載",
            "(B) 防止更新檔被竄改、過期或回滾 (Rollback) 攻擊",
            "(C) 免費更新",
            "(D) 自動安裝"
        ],
        "answer": "B",
        "note": "TUF 是保護軟體更新系統 (如 Docker Content Trust) 的安全框架。"
    },
    {
        "id": "B11-Prot-27",
        "question": "在 Windows AD 安全中，Tier Model (分層模型) 的主要目的是？",
        "options": [
            "(A) 區分部門",
            "(B) 防止高權限帳號 (Tier 0, 如 Domain Admin) 登入低安全性的電腦 (Tier 2)，避免憑證被竊",
            "(C) 節省授權費",
            "(D) 方便備份"
        ],
        "answer": "B",
        "note": "防止 Pass-the-Hash 等橫向移動攻擊，確保高權限帳號只在安全環境使用。"
    },
    {
        "id": "B11-Prot-28",
        "question": "關於「WAF (網頁應用程式防火牆)」與「IPS (入侵防禦系統)」的部署順序，一般建議為何？",
        "options": [
            "(A) IPS 在前 (過濾網路層攻擊)，WAF 在後 (過濾應用層攻擊)",
            "(B) WAF 在前，IPS 在後",
            "(C) 兩者平行部署",
            "(D) 隨便部署"
        ],
        "answer": "A",
        "note": "IPS 先過濾掉大量的網路層攻擊與已知漏洞攻擊，減輕 WAF 負擔，WAF 再專注處理複雜的 Web 邏輯攻擊。"
    },
    {
        "id": "B11-Prot-29",
        "question": "下列哪一種日誌對於偵測「資料外洩 (Data Exfiltration)」最為關鍵？",
        "options": [
            "(A) DHCP 日誌",
            "(B) 防火牆與 Proxy 的流量日誌 (分析大流量傳輸或連線至可疑 IP)",
            "(C) 應用程式錯誤日誌",
            "(D) 開機日誌"
        ],
        "answer": "B",
        "note": "外洩通常伴隨著異常的對外流量，流量日誌是偵測 Exfiltration 的核心。"
    },
    {
        "id": "B11-Prot-30",
        "question": "在實體安全中，針對「USB 隨身碟攻擊 (如 BadUSB)」的有效技術防護是？",
        "options": [
            "(A) 貼上封條",
            "(B) 實施周邊裝置控管 (Device Control)，限制僅允許註冊的 USB 裝置或完全禁用",
            "(C) 規定員工不能用",
            "(D) 格式化所有 USB"
        ],
        "answer": "B",
        "note": "技術性強制控管 (DLP/Endpoint Security) 比行政規範更有效。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch11 = [
    // --- 稽核與風險 (進階) ---
    {
        "id": "B11-Plan-01",
        "question": "在稽核風險模型中，「固有風險 (Inherent Risk)」是指？",
        "options": [
            "(A) 稽核員抽樣錯誤的風險",
            "(B) 在未考量內部控制情況下，業務本身發生重大錯誤的風險",
            "(C) 控制措施失效的風險",
            "(D) 稽核員未發現錯誤的風險"
        ],
        "answer": "B",
        "note": "例如：現金交易本身就比支票交易有更高的被竊固有風險。"
    },
    {
        "id": "B11-Plan-02",
        "question": "關於「控制風險 (Control Risk)」，下列敘述何者正確？",
        "options": [
            "(A) 組織的內部控制未能及時預防或偵測出重大錯誤的風險",
            "(B) 稽核員的風險",
            "(C) 外部環境的風險",
            "(D) 法律風險"
        ],
        "answer": "A",
        "note": "控制風險高代表內部控制設計不良或執行無效。"
    },
    {
        "id": "B11-Plan-03",
        "question": "稽核員可以控制的風險是哪一種？",
        "options": [
            "(A) 固有風險",
            "(B) 控制風險",
            "(C) 偵查風險 (Detection Risk)",
            "(D) 經營風險"
        ],
        "answer": "C",
        "note": "稽核員透過調整查核程序的性質、時間與範圍 (NET) 來降低偵查風險。"
    },
    {
        "id": "B11-Plan-04",
        "question": "在 ISO 27001 中，關於「不符合事項 (Nonconformity)」的矯正，第一步應該是？",
        "options": [
            "(A) 修改政策",
            "(B) 立即採取行動以控制並矯正它 (Correction)，並處理後果",
            "(C) 處罰員工",
            "(D) 忽略它"
        ],
        "answer": "B",
        "note": "先止血 (Correction)，再分析根因並採取矯正措施 (Corrective Action) 防止再發。"
    },
    {
        "id": "B11-Plan-05",
        "question": "關於「風險擁有者 (Risk Owner)」與「資產擁有者 (Asset Owner)」的關係，下列何者正確？",
        "options": [
            "(A) 一定要是不同人",
            "(B) 通常是同一人或由資產擁有者擔任，因為他們最了解資產價值與業務衝擊",
            "(C) 風險擁有者必須是資安長",
            "(D) 資產擁有者只需負責購買資產"
        ],
        "answer": "B",
        "note": "權責相符原則：誰享受資產帶來的利益，誰就該負責相關的風險。"
    },
    // --- 法規與標準 (深入) ---
    {
        "id": "B11-Plan-06",
        "question": "ISO 27001:2022 新增的控制措施中，「資料遮罩 (Data Masking)」的主要目的是？",
        "options": [
            "(A) 壓縮資料",
            "(B) 限制敏感資料的暴露，以符合法令 (如個資法) 或業務需求",
            "(C) 備份資料",
            "(D) 加速查詢"
        ],
        "answer": "B",
        "note": "這是一種存取控制技術，確保使用者只能看到其權限範圍內的資料 (如遮蔽身分證號)。"
    },
    {
        "id": "B11-Plan-07",
        "question": "關於 GDPR 的「隱私預設 (Privacy by Default)」原則，意指？",
        "options": [
            "(A) 產品出廠時，預設設定應提供最高程度的隱私保護 (如不公開個人檔案)",
            "(B) 使用者必須手動開啟隱私功能",
            "(C) 隱私政策可以隨便寫",
            "(D) 預設收集所有資料"
        ],
        "answer": "A",
        "note": "使用者不需做任何設定，隱私就應受到保護。"
    },
    {
        "id": "B11-Plan-08",
        "question": "在資通安全責任等級分級辦法中，機關若將核心資通系統委外，其資安責任？",
        "options": [
            "(A) 完全轉移給廠商",
            "(B) 仍由機關承擔，機關應負監督管理之責",
            "(C) 雙方各半",
            "(D) 由主管機關承擔"
        ],
        "answer": "B",
        "note": "委外僅是委託執行，法定責任無法轉移 (Accountability remains)。"
    },
    {
        "id": "B11-Plan-09",
        "question": "關於 NIST SP 800-171 標準，主要是規範保護哪一類資訊？",
        "options": [
            "(A) 國家機密 (Classified)",
            "(B) 受控非機密資訊 (CUI - Controlled Unclassified Information)",
            "(C) 公開資訊",
            "(D) 個人日記"
        ],
        "answer": "B",
        "note": "這是美國國防供應鏈廠商必須遵守的資安標準 (非機密但敏感的政府資訊)。"
    },
    {
        "id": "B11-Plan-10",
        "question": "ISO 22301 (營運持續管理) 中，關於「演練 (Exercise)」與「測試 (Testing)」的細微差別？",
        "options": [
            "(A) 沒差別",
            "(B) 演練著重於「人員」的訓練與應變能力；測試著重於「系統」或「計畫」的有效性驗證",
            "(C) 演練是假的，測試是真的",
            "(D) 演練由 HR 負責，測試由 IT 負責"
        ],
        "answer": "B",
        "note": "Exercise (People focus) vs Testing (System/Plan focus)。"
    },
    // --- 供應鏈與合規 ---
    {
        "id": "B11-Plan-11",
        "question": "在 CMMC (網路安全成熟度模型驗證) 中，Level 2 (Advanced) 要求符合哪個標準的所有控制措施？",
        "options": [
            "(A) ISO 27001",
            "(B) NIST SP 800-171 (110 項要求)",
            "(C) NIST SP 800-53",
            "(D) CIS Controls"
        ],
        "answer": "B",
        "note": "CMMC Level 2 直接對齊 NIST SP 800-171。"
    },
    {
        "id": "B11-Plan-12",
        "question": "關於「軟體供應鏈安全」，美國行政命令 EO 14028 強調了什麼的重要性？",
        "options": [
            "(A) 購買最貴的軟體",
            "(B) 軟體物料清單 (SBOM) 與開發環境的安全性",
            "(C) 禁止使用開源軟體",
            "(D) 延長軟體開發時間"
        ],
        "answer": "B",
        "note": "SBOM 是提升供應鏈透明度與應變能力的核心要求。"
    },
    {
        "id": "B11-Plan-13",
        "question": "機關在採購資通訊產品時，應優先選擇？",
        "options": [
            "(A) 價格最低的產品",
            "(B) 通過共同準則 (Common Criteria, ISO 15408) 驗證或取得資安標章的產品",
            "(C) 功能最多的產品",
            "(D) 廣告最大的產品"
        ],
        "answer": "B",
        "note": "採購經認證的產品可降低產品本身含有漏洞或後門的風險。"
    },
    {
        "id": "B11-Plan-14",
        "question": "關於「第四方風險 (Fourth-party Risk)」，是指？",
        "options": [
            "(A) 客戶的風險",
            "(B) 供應商的供應商 (Sub-contractors) 所帶來的風險",
            "(C) 駭客的風險",
            "(D) 內部的風險"
        ],
        "answer": "B",
        "note": "供應鏈是層層相扣的，主要供應商若依賴不安全的下游廠商，風險會傳遞回來。"
    },
    {
        "id": "B11-Plan-15",
        "question": "在合約中加入「稽核權 (Right to Audit)」條款的主要目的是？",
        "options": [
            "(A) 刁難廠商",
            "(B) 確保機關有權在必要時，對廠商的資安控制進行實地查核，驗證其合規性",
            "(C) 增加合約頁數",
            "(D) 降低採購金額"
        ],
        "answer": "B",
        "note": "稽核權是落實供應商監督管理的重要法律依據。"
    },
    // --- 營運持續與韌性 ---
    {
        "id": "B11-Plan-16",
        "question": "關於「業務持續計畫 (BCP)」與「災難復原計畫 (DRP)」的關係，下列何者正確？",
        "options": [
            "(A) DRP 是 BCP 的一部分，專注於 IT 系統與資料的恢復",
            "(B) BCP 是 DRP 的一部分",
            "(C) 兩者互不相關",
            "(D) BCP 只管人，DRP 只管機器"
        ],
        "answer": "A",
        "note": "BCP 涵蓋業務流程、人員、場所等整體營運；DRP 聚焦於支持業務的 IT 技術恢復。"
    },
    {
        "id": "B11-Plan-17",
        "question": "在 BIA 中，識別「相依性 (Dependencies)」的重要性在於？",
        "options": [
            "(A) 沒什麼重要",
            "(B) 了解恢復某個系統前，必須先恢復哪些基礎設施 (如 AD, DNS, Network)，以決定正確的復原順序",
            "(C) 增加報告篇幅",
            "(D) 計算資產價格"
        ],
        "answer": "B",
        "note": "正確的復原順序 (Recovery Sequence) 取決於系統間的相依關係。"
    },
    {
        "id": "B11-Plan-18",
        "question": "關於「韌性 (Resilience)」與「防護 (Protection)」的觀念差異？",
        "options": [
            "(A) 防護強調不被攻破；韌性強調被攻破後能維持運作並快速恢復 (Absorb and Recover)",
            "(B) 兩者相同",
            "(C) 韌性只適用於硬體",
            "(D) 防護不需要成本"
        ],
        "answer": "A",
        "note": "現代資安強調「數位韌性」，承認攻擊不可避免，重點在於生存與恢復。"
    },
    {
        "id": "B11-Plan-19",
        "question": "在 BCP 中，「緊急應變中心 (EOC)」的功能是？",
        "options": [
            "(A) 員工休息室",
            "(B) 災難發生時的指揮調度、決策與溝通中樞",
            "(C) 備援機房",
            "(D) 媒體採訪區"
        ],
        "answer": "B",
        "note": "EOC (Emergency Operations Center) 是危機管理的核心大腦。"
    },
    {
        "id": "B11-Plan-20",
        "question": "關於「備份加密」的管理，最關鍵的是？",
        "options": [
            "(A) 加密演算法要自己發明",
            "(B) 金鑰管理 (Key Management)，確保金鑰與備份分開存放且妥善備份",
            "(C) 不需加密",
            "(D) 使用簡易密碼"
        ],
        "answer": "B",
        "note": "若備份加密了但金鑰遺失或被鎖在受災機房內，備份將無法還原。"
    },
    // --- 綜合情境 ---
    {
        "id": "B11-Plan-21",
        "question": "某機關發現資安事件，經評估為「核心業務系統受駭，但未涉及關鍵基礎設施，且能在 RTO 內恢復」，這可能屬於哪一級事件？",
        "options": [
            "(A) 1 級",
            "(B) 2 級",
            "(C) 3 級",
            "(D) 4 級"
        ],
        "answer": "C",
        "note": "核心業務系統受駭通常起跳為 3 級，若涉及關鍵基礎設施或無法於限時內恢復可能升為 4 級。但依據最新分級辦法，核心業務受影響屬 3 級。"
    },
    {
        "id": "B11-Plan-22",
        "question": "關於「資安健診」報告中的「待改善事項」，機關應如何處理？",
        "options": [
            "(A) 存查即可",
            "(B) 擬定改善計畫，列管追蹤直至完成修補 (Remediation)",
            "(C) 刪除報告",
            "(D) 否認缺失"
        ],
        "answer": "B",
        "note": "健診的價值在於後續的改善行動，而非報告本身。"
    },
    {
        "id": "B11-Plan-23",
        "question": "在開發 App 時，遵循「Privacy by Design」原則，若 App 需要定位權限，應如何設計？",
        "options": [
            "(A) 一安裝就強制開啟",
            "(B) 預設關閉，僅在使用者使用地圖功能時詢問授權，並說明目的",
            "(C) 偷偷開啟",
            "(D) 收集所有位置資料並販售"
        ],
        "answer": "B",
        "note": "最小權限、主動告知、即時授權 (Just-in-Time) 是隱私設計的原則。"
    },
    {
        "id": "B11-Plan-24",
        "question": "關於「資安通報」的機密性，下列何者正確？",
        "options": [
            "(A) 應公開所有細節",
            "(B) 通報內容涉及漏洞細節或機敏資訊，應透過加密管道傳輸並限制知悉人員 (Need-to-know)",
            "(C) 可以貼在佈告欄",
            "(D) 通報單不需要保護"
        ],
        "answer": "B",
        "note": "通報內容本身可能包含敏感資訊，需防止在通報過程中外洩 (TLP 燈號管理)。"
    },
    {
        "id": "B11-Plan-25",
        "question": "對於「過時/老舊系統 (Legacy System)」的資安管理，若無法更新或汰換，應採取的補償性控制 (Compensating Control) 是？",
        "options": [
            "(A) 忽視它",
            "(B) 將其隔離在獨立網段，限制存取，並加強監控 (Virtual Patching)",
            "(C) 開放對外連線",
            "(D) 移除防毒軟體"
        ],
        "answer": "B",
        "note": "無法修補的系統必須透過隔離 (Isolation) 與限制接觸面來降低風險。"
    },
    {
        "id": "B11-Plan-26",
        "question": "關於「社交工程演練」的誘餌郵件設計，下列何者較具教育意義？",
        "options": [
            "(A) 極度誇張明顯的詐騙信",
            "(B) 模擬真實業務場景 (如薪資單、會議通知)，難度適中，能反映員工真實警覺性",
            "(C) 空白信件",
            "(D) 針對特定個人的羞辱信"
        ],
        "answer": "B",
        "note": "演練應貼近真實威脅場景，才能有效測試並提升員工辨識能力。"
    },
    {
        "id": "B11-Plan-27",
        "question": "在資安治理中，關於「利益衝突 (Conflict of Interest)」的避免，下列何者正確？",
        "options": [
            "(A) 開發人員兼任稽核人員",
            "(B) 系統管理員兼任資安稽核人員",
            "(C) 稽核人員應獨立於受稽單位之外，不應稽核自己的工作",
            "(D) 球員兼裁判是最好的"
        ],
        "answer": "C",
        "note": "獨立性是確保稽核客觀公正的前提。"
    },
    {
        "id": "B11-Plan-28",
        "question": "關於「遠端辦公」的資安政策，下列何者應被禁止？",
        "options": [
            "(A) 使用公司配發的 VPN",
            "(B) 全家共用公司配發的電腦進行遊戲或私人用途",
            "(C) 更新作業系統",
            "(D) 鎖定螢幕"
        ],
        "answer": "B",
        "note": "公務設備僅限公務使用，家人共用會大幅增加感染惡意軟體或資料外洩風險。"
    },
    {
        "id": "B11-Plan-29",
        "question": "依據 ISO 27001，當發現資安政策不再適用時 (如新技術導入)，應？",
        "options": [
            "(A) 繼續使用舊政策",
            "(B) 進行管理審查，修訂並發布新政策，且公告周知",
            "(C) 口頭更改",
            "(D) 刪除政策"
        ],
        "answer": "B",
        "note": "文件化資訊的審查與更新是 PDCA 的重要環節。"
    },
    {
        "id": "B11-Plan-30",
        "question": "資安長 (CISO) 的績效衡量，不應僅看？",
        "options": [
            "(A) 資安事故的處理效率",
            "(B) 合規性達成率",
            "(C) 絕對的「零事故」 (因為不可能達成，可能導致隱匿通報)",
            "(D) 風險降低的程度"
        ],
        "answer": "C",
        "note": "以「零事故」為 KPI 會造成「報喜不報憂」的負面文化；應看重偵測與回應能力 (Resilience)。"
    }
];

// 將 Batch 11 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch11);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch11);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第十二批次 (Batch 12)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：IoT 架構安全、雲端責任共擔、BCM 管理流程、資安治理成熟度
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch12 = [
    // --- IoT 與工控安全 (進階) ---
    {
        "id": "B12-Prot-01",
        "question": "在物聯網 (IoT) 架構中，負責「資料傳輸、裝置連網、協定路由」的是哪一層？",
        "options": [
            "(A) 感知層 (Perception Layer)",
            "(B) 網路層 (Network Layer)",
            "(C) 應用層 (Application Layer)",
            "(D) 業務層 (Business Layer)"
        ],
        "answer": "B",
        "note": "114 概論教材。網路層 (如 Wi-Fi, 4G/5G, NB-IoT) 負責資料的傳輸與路由。"
    },
    {
        "id": "B12-Prot-02",
        "question": "關於 NB-IoT (Narrowband IoT) 與 LoRaWAN 的比較，下列何者正確？",
        "options": [
            "(A) NB-IoT 使用非授權頻段，LoRaWAN 使用授權頻段",
            "(B) NB-IoT 由電信業者部署 (授權頻段)，LoRaWAN 可由企業自建 (非授權頻段)",
            "(C) LoRaWAN 傳輸速率比 NB-IoT 快",
            "(D) 兩者都不適合低功耗應用"
        ],
        "answer": "B",
        "note": "114 概論教材。NB-IoT 依賴電信基站，安全性較高；LoRaWAN 彈性高但需自建 Gateway。"
    },
    {
        "id": "B12-Prot-03",
        "question": "在物聯網安全中，下列哪一種機制是用來確保「裝置只能啟動可信韌體」？",
        "options": [
            "(A) Secure Boot (安全開機)",
            "(B) Firewall (防火牆)",
            "(C) VPN",
            "(D) WPA3"
        ],
        "answer": "A",
        "note": "114 概論教材。Secure Boot 利用數位簽章驗證 Bootloader 與 OS，防止未授權的韌體被載入。"
    },
    {
        "id": "B12-Prot-04",
        "question": "關於 ZigBee 協定的安全性，其使用的加密演算法為何？",
        "options": [
            "(A) AES-128",
            "(B) DES",
            "(C) RSA-2048",
            "(D) 不支援加密"
        ],
        "answer": "A",
        "note": "114 概論教材。ZigBee 使用 AES-128 進行加密，但若使用預設 Link Key 仍有風險。"
    },
    {
        "id": "B12-Prot-05",
        "question": "在工控系統 (ICS) 中，為了防止惡意軟體透過 USB 傳播，下列何種措施最為有效且常見？",
        "options": [
            "(A) 封死所有 USB 埠口 (物理或邏輯封鎖)",
            "(B) 安裝一般商用防毒軟體",
            "(C) 每天重灌系統",
            "(D) 使用雲端掃毒"
        ],
        "answer": "A",
        "note": "工控環境通常封閉且不便更新，封鎖 USB 埠口是阻斷物理入侵的關鍵措施。"
    },
    // --- 雲端安全 (進階) ---
    {
        "id": "B12-Prot-06",
        "question": "在 AWS 雲端環境中，若要對 S3 Bucket 中的資料進行加密，且希望「自行管理金鑰」，應使用哪種服務？",
        "options": [
            "(A) SSE-S3 (S3-Managed Keys)",
            "(B) SSE-KMS (KMS-Managed Keys) with CMK (Customer Master Key)",
            "(C) HTTP",
            "(D) SSH"
        ],
        "answer": "B",
        "note": "SSE-KMS 允許用戶使用自定義的主金鑰 (CMK) 進行加密管理，並具備稽核紀錄。"
    },
    {
        "id": "B12-Prot-07",
        "question": "關於「雲端原生應用程式保護平台 (CNAPP)」的定義，它通常整合了哪些功能？",
        "options": [
            "(A) 僅包含防毒軟體",
            "(B) 整合了 CSPM (組態管理)、CWPP (工作負載保護) 與 CI/CD 安全掃描",
            "(C) 僅包含防火牆",
            "(D) 用來備份資料"
        ],
        "answer": "B",
        "note": "CNAPP 是新一代雲端安全解決方案，強調從開發到執行的全生命週期保護。"
    },
    {
        "id": "B12-Prot-08",
        "question": "在雲端身分管理中，為了避免長期憑證洩漏的風險，應優先使用？",
        "options": [
            "(A) IAM User 的長期 Access Key",
            "(B) IAM Role (角色) 搭配臨時憑證 (Temporary Credentials)",
            "(C) 將帳號密碼寫在程式碼中",
            "(D) 使用 Root 帳號"
        ],
        "answer": "B",
        "note": "IAM Role 提供短時效的臨時憑證，大幅降低金鑰洩漏後的風險。"
    },
    {
        "id": "B12-Prot-09",
        "question": "關於 Kubernetes 的 `NetworkPolicy`，其預設行為通常是？",
        "options": [
            "(A) 阻擋所有流量 (Default Deny)",
            "(B) 允許所有 Pod 之間的流量 (Default Allow)",
            "(C) 只允許 HTTP",
            "(D) 只允許 SSH"
        ],
        "answer": "B",
        "note": "K8s 預設允許所有 Pod 互通，必須主動設定 NetworkPolicy 才能實施隔離 (微分割)。"
    },
    {
        "id": "B12-Prot-10",
        "question": "在 Serverless 架構 (如 AWS Lambda) 中，最常見的資安攻擊面是？",
        "options": [
            "(A) 作業系統漏洞",
            "(B) 函數 (Function) 的輸入驗證不足 (如 Injection) 與權限過大 (Over-privileged)",
            "(C) 實體機房入侵",
            "(D) SSH 暴力破解"
        ],
        "answer": "B",
        "note": "Serverless 雖無伺服器管理問題，但應用層漏洞與 IAM 權限設定仍是攻擊重點。"
    },
    // --- 網路與通訊 (進階) ---
    {
        "id": "B12-Prot-11",
        "question": "關於 5G 網路的「SUCI (Subscription Concealed Identifier)」機制，其主要目的是？",
        "options": [
            "(A) 加速上網",
            "(B) 加密用戶的 IMSI (國際行動用戶識別碼)，防止偽基地台 (IMSI Catcher) 竊取身分",
            "(C) 降低延遲",
            "(D) 節省電量"
        ],
        "answer": "B",
        "note": "114 概論教材。SUCI 解決了 4G 時代 IMSI 明文傳輸導致的身分洩漏問題。"
    },
    {
        "id": "B12-Prot-12",
        "question": "在 Wi-Fi 安全中，WPA3-Enterprise 模式通常要求使用多少位元的加密強度？",
        "options": [
            "(A) 64-bit",
            "(B) 128-bit",
            "(C) 192-bit (CNSA Suite)",
            "(D) 256-bit"
        ],
        "answer": "C",
        "note": "114 概論教材。WPA3-Enterprise 提供 192-bit 安全套件，符合高機密環境需求。"
    },
    {
        "id": "B12-Prot-13",
        "question": "關於 BLE (Bluetooth Low Energy) 的「LE Encryption」，其主要功能是？",
        "options": [
            "(A) 增加傳輸距離",
            "(B) 保護資料在無線傳輸中不被竊聽或竄改",
            "(C) 降低功耗",
            "(D) 自動配對"
        ],
        "answer": "B",
        "note": "114 概論教材。LE Encryption 是 BLE 的加密層，保障傳輸安全。"
    },
    {
        "id": "B12-Prot-14",
        "question": "下列哪一種 VPN 協定，常被用於繞過防火牆封鎖，因為它使用標準的 HTTPS (443) 埠口？",
        "options": [
            "(A) IPsec (IKEv2)",
            "(B) L2TP",
            "(C) SSL VPN (如 OpenVPN, SSTP)",
            "(D) PPTP"
        ],
        "answer": "C",
        "note": "SSL VPN 偽裝成網頁流量，穿透性最佳。"
    },
    {
        "id": "B12-Prot-15",
        "question": "在 Zero Trust Network Access (ZTNA) 架構中，使用者存取應用程式時，是否直接連接到內部網路？",
        "options": [
            "(A) 是，ZTNA 就是 VPN",
            "(B) 否，透過中間的代理 (Broker/Gateway) 進行連線，使用者無法接觸到底層網路",
            "(C) 是，但需要密碼",
            "(D) 否，使用者不能存取任何應用"
        ],
        "answer": "B",
        "note": "ZTNA 將應用程式從網路中隱藏 (Dark Cloud)，使用者僅能透過代理存取特定應用，而非整個網路。"
    },
    // --- 系統與端點 (進階) ---
    {
        "id": "B12-Prot-16",
        "question": "在 Windows 系統中，攻擊者利用 `certutil.exe` 下載惡意檔案，這屬於哪種攻擊技術？",
        "options": [
            "(A) Buffer Overflow",
            "(B) LOLBins (Living off the Land Binaries)",
            "(C) SQL Injection",
            "(D) Zero-day"
        ],
        "answer": "B",
        "note": "利用系統內建合法工具進行惡意行為，是 LOLBins 的典型特徵。"
    },
    {
        "id": "B12-Prot-17",
        "question": "關於 Linux 的 `sudo` 指令，若配置不當 (如 `ALL=(ALL) NOPASSWD: ALL`)，主要風險為何？",
        "options": [
            "(A) 系統變慢",
            "(B) 任何取得該帳號權限的攻擊者，無需密碼即可提升為 root 權限",
            "(C) 無法連網",
            "(D) 硬碟損壞"
        ],
        "answer": "B",
        "note": "sudo 配置錯誤是 Linux 提權 (Privilege Escalation) 的常見漏洞。"
    },
    {
        "id": "B12-Prot-18",
        "question": "在端點防護中，HIPS (Host-based IPS) 與 NIPS (Network-based IPS) 的主要差異是？",
        "options": [
            "(A) HIPS 安裝在主機上，可監控系統呼叫與檔案存取；NIPS 安裝在網路上，監控封包",
            "(B) HIPS 只能防毒，NIPS 只能防火牆",
            "(C) HIPS 比較便宜",
            "(D) NIPS 會拖慢主機效能"
        ],
        "answer": "A",
        "note": "HIPS 能看到加密後的解密內容 (在主機端)，NIPS 只能看到加密流量 (除非有解密機制)。"
    },
    {
        "id": "B12-Prot-19",
        "question": "關於「應用程式白名單 (Application Whitelisting)」的防護效果，下列何者正確？",
        "options": [
            "(A) 只能防禦已知病毒",
            "(B) 能有效防禦未知惡意軟體 (Zero-day)，因為只有被允許的程式才能執行",
            "(C) 會導致系統中毒",
            "(D) 設定非常簡單，不需要維護"
        ],
        "answer": "B",
        "note": "白名單採「正面表列」，未在清單上的程式一律阻擋，對抗未知威脅極為有效。"
    },
    {
        "id": "B12-Prot-20",
        "question": "在行動裝置鑑識中，若裝置處於鎖定狀態且無法解鎖，通常能提取的資料量為？",
        "options": [
            "(A) 完整檔案系統 (Full File System)",
            "(B) 實體映像 (Physical Extraction)",
            "(C) 極少或無法提取 (視加密狀態與漏洞而定)",
            "(D) 所有資料"
        ],
        "answer": "C",
        "note": "現代手機 (FBE/FDE) 在鎖定狀態下資料是加密的，若無密碼或漏洞，幾乎無法提取有效資料。"
    },
    // --- 攻防實務 ---
    {
        "id": "B12-Prot-21",
        "question": "攻擊者使用 `nmap -sV` 指令，其目的是？",
        "options": [
            "(A) 進行 Ping 掃描",
            "(B) 偵測服務版本資訊 (Service Version Detection)",
            "(C) 進行 UDP 掃描",
            "(D) 繞過防火牆"
        ],
        "answer": "B",
        "note": "`-sV` 會嘗試與開放埠口進行互動，識別服務軟體及其版本，以尋找對應漏洞。"
    },
    {
        "id": "B12-Prot-22",
        "question": "關於「Golden Ticket」攻擊，攻擊者偽造的是哪一種 Kerberos 票據？",
        "options": [
            "(A) TGS (Ticket Granting Service)",
            "(B) TGT (Ticket Granting Ticket)",
            "(C) ST (Service Ticket)",
            "(D) HTTP Ticket"
        ],
        "answer": "B",
        "note": "Golden Ticket 是偽造的 TGT，擁有它可隨意請求任何服務的 TGS，等同擁有網域最高權限。"
    },
    {
        "id": "B12-Prot-23",
        "question": "在 Web 滲透測試中，若發現輸入 `<script>alert(1)</script>` 會原樣顯示在網頁上，但未執行，可能原因為何？",
        "options": [
            "(A) 瀏覽器壞了",
            "(B) 網站有做 HTML Entity Encoding (將 < 轉為 &lt;)",
            "(C) 這是 SQL Injection",
            "(D) 攻擊語法錯誤"
        ],
        "answer": "B",
        "note": "輸出編碼 (Output Encoding) 是防禦 XSS 的最有效手段，將特殊字元轉為無害的 HTML 實體。"
    },
    {
        "id": "B12-Prot-24",
        "question": "關於「撞庫攻擊 (Credential Stuffing)」的防禦，下列何者最有效？",
        "options": [
            "(A) 限制密碼長度",
            "(B) 導入 MFA (多因子認證) 或 CAPTCHA",
            "(C) 隱藏登入頁面",
            "(D) 定期重啟伺服器"
        ],
        "answer": "B",
        "note": "撞庫利用的是「正確的帳號密碼」，唯有 MFA 能在密碼正確的情況下阻擋非本人登入。"
    },
    {
        "id": "B12-Prot-25",
        "question": "下列哪一種工具是用來進行「密碼雜湊破解」的？",
        "options": [
            "(A) Wireshark",
            "(B) Hashcat 或 John the Ripper",
            "(C) Metasploit",
            "(D) Nessus"
        ],
        "answer": "B",
        "note": "Hashcat 利用 GPU 加速，是目前最強大的密碼破解工具之一。"
    },
    {
        "id": "B12-Prot-26",
        "question": "在紅隊演練中，「C2 (Command and Control)」通道常使用 HTTPS 協定的原因是？",
        "options": [
            "(A) 速度最快",
            "(B) 流量加密且常見，易於混入正常流量 (Blending in) 躲避偵測",
            "(C) 設定最簡單",
            "(D) 為了保護駭客隱私"
        ],
        "answer": "B",
        "note": "使用常見的加密協定 (HTTPS) 可以讓惡意流量在防火牆日誌中看起來像正常的網頁瀏覽。"
    },
    {
        "id": "B12-Prot-27",
        "question": "關於「供應鏈攻擊」的防範，在開發階段引入 SCA (Software Composition Analysis) 工具的目的是？",
        "options": [
            "(A) 掃描原始碼邏輯漏洞",
            "(B) 盤點並檢測第三方開源套件的已知漏洞 (如 CVE)",
            "(C) 進行滲透測試",
            "(D) 加密程式碼"
        ],
        "answer": "B",
        "note": "SCA 專注於檢查專案中引用的「第三方元件 (Libraries/Dependencies)」是否安全。"
    },
    {
        "id": "B12-Prot-28",
        "question": "在資安事件中，若發現大量外對內的 RDP (3389) 連線失敗紀錄，最可能是遭受什麼攻擊？",
        "options": [
            "(A) DDoS",
            "(B) 暴力破解 (Brute Force) 或 密碼潑灑 (Password Spraying)",
            "(C) SQL Injection",
            "(D) XSS"
        ],
        "answer": "B",
        "note": "RDP 是勒索軟體駭客最愛的進入點，大量失敗紀錄通常代表正在嘗試猜測密碼。"
    },
    {
        "id": "B12-Prot-29",
        "question": "關於「蜜罐 (Honeypot)」的日誌分析，若發現有連線紀錄，通常代表？",
        "options": [
            "(A) 正常使用者誤觸",
            "(B) 極高機率是惡意掃描或攻擊 (因為蜜罐不對外提供正常服務)",
            "(C) 系統故障",
            "(D) 網路延遲"
        ],
        "answer": "B",
        "note": "蜜罐沒有正常業務流量，任何連線都應視為可疑，這也是其低誤報率的原因。"
    },
    {
        "id": "B12-Prot-30",
        "question": "在 Web 安全中，設定 `Secure` 屬性的 Cookie，其效果是？",
        "options": [
            "(A) 禁止 JavaScript 讀取",
            "(B) 僅在 HTTPS 加密連線中傳輸，防止在 HTTP 明文中被竊聽",
            "(C) 防止 CSRF",
            "(D) 延長 Cookie 效期"
        ],
        "answer": "B",
        "note": "Secure 屬性確保 Cookie 不會隨 HTTP 請求發送，避免被中間人側錄。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch12 = [
    // --- 業務持續運作管理 (BCM) ---
    {
        "id": "B12-Plan-01",
        "question": "在 ISO 22301 (BCMS) 中，關於「業務持續運作計畫 (BCP)」的定義，下列何者正確？",
        "options": [
            "(A) 指導組織因應業務運作中斷、反應、重啟及恢復業務持續運作目標之文件化資訊",
            "(B) 僅包含 IT 系統還原步驟",
            "(C) 是一份保險合約",
            "(D) 是行銷計畫"
        ],
        "answer": "A",
        "note": "114 概論教材。BCP 涵蓋了從中斷發生到完全恢復正常運作的所有指引。"
    },
    {
        "id": "B12-Plan-02",
        "question": "進行 BIA (營運衝擊分析) 時，首先要識別的是？",
        "options": [
            "(A) 公司的核心業務功能 (Critical Business Functions)",
            "(B) 伺服器的 IP",
            "(C) 員工的生日",
            "(D) 供應商的電話"
        ],
        "answer": "A",
        "note": "BIA 的起點是識別哪些業務最重要，才能決定資源分配與復原優先順序。"
    },
    {
        "id": "B12-Plan-03",
        "question": "關於 RTO 與 RPO 的關係，下列敘述何者正確？",
        "options": [
            "(A) RTO 決定備援設備的等級 (多快恢復)，RPO 決定備份頻率 (資料多新)",
            "(B) 兩者意義相同",
            "(C) RTO 決定備份，RPO 決定備援",
            "(D) 兩者都由 IT 部門決定，與業務無關"
        ],
        "answer": "A",
        "note": "114 概論教材。RTO = 時間 (Time) = 速度；RPO = 點 (Point) = 資料量。"
    },
    {
        "id": "B12-Plan-04",
        "question": "在 BCP 演練中，「複合式演練情境」是指？",
        "options": [
            "(A) 只演練單一系統故障",
            "(B) 模擬多種災害同時發生 (如地震導致停電且網路中斷)，以測試組織的綜合應變能力",
            "(C) 大家一起吃便當",
            "(D) 書面檢查"
        ],
        "answer": "B",
        "note": "114 概論教材。真實災害往往是連鎖發生的，複合式演練更貼近現實。"
    },
    {
        "id": "B12-Plan-05",
        "question": "關於 BCP 的維護，下列何者是觸發計畫更新的時機？",
        "options": [
            "(A) 人員異動、系統變更、業務流程改變或演練後發現缺失",
            "(B) 只有每年固定時間",
            "(C) 只有發生災害時",
            "(D) 永遠不需要更新"
        ],
        "answer": "A",
        "note": "BCP 是活的文件 (Living Document)，需隨組織變動而持續更新。"
    },
    // --- 資安治理與成熟度 ---
    {
        "id": "B12-Plan-06",
        "question": "依據 NIST CSF 2.0，資安治理 (Govern) 的核心目標包含？",
        "options": [
            "(A) 建立並溝通資通安全策略、角色、責任及監督",
            "(B) 購買防火牆",
            "(C) 修補漏洞",
            "(D) 備份資料"
        ],
        "answer": "A",
        "note": "114 概論教材。Govern 強調資安策略與組織目標的對齊，以及高層的監督責任。"
    },
    {
        "id": "B12-Plan-07",
        "question": "在資安治理成熟度評估中 (ISO/IEC 33004)，Level 3 (制度化型) 的特徵是？",
        "options": [
            "(A) 流程未定義",
            "(B) 有效定義與部署標準化流程，使其成為常規作業",
            "(C) 流程可量化預測",
            "(D) 持續創新優化"
        ],
        "answer": "B",
        "note": "114 概論教材。Level 3 的關鍵是「標準化 (Standardized)」與「制度化」。"
    },
    {
        "id": "B12-Plan-08",
        "question": "關於資安績效評估，下列何者屬於「結果導向 (Outcome-based)」的指標？",
        "options": [
            "(A) 舉辦了幾場教育訓練",
            "(B) 員工釣魚演練的點擊率下降幅度",
            "(C) 購買了幾套軟體",
            "(D) 寫了幾頁報告"
        ],
        "answer": "B",
        "note": "結果導向關注的是「成效」而非「產出」。點擊率下降代表資安意識真實提升。"
    },
    {
        "id": "B12-Plan-09",
        "question": "資安長 (CISO) 定期向董事會報告資安狀況，這屬於資安治理架構中的哪一個面向？",
        "options": [
            "(A) 監督 (Oversight) 與溝通",
            "(B) 技術實作",
            "(C) 事件應變",
            "(D) 採購流程"
        ],
        "answer": "A",
        "note": "向治理層 (董事會) 報告是確保高層掌握風險並履行監督責任的關鍵機制。"
    },
    {
        "id": "B12-Plan-10",
        "question": "在資安治理中，採用「三道防線」模型時，第二道防線 (風險管理/法規遵循) 的職責是？",
        "options": [
            "(A) 直接操作系統",
            "(B) 制定風險管理框架，協助並監控第一道防線 (營運單位) 的風險管理活動",
            "(C) 進行獨立稽核",
            "(D) 負責修電腦"
        ],
        "answer": "B",
        "note": "第二道防線負責制定規則與監控；第一道防線負責執行；第三道防線負責獨立查核。"
    },
    // --- 雲端安全管理 ---
    {
        "id": "B12-Plan-11",
        "question": "在雲端責任共擔模型中，若使用 PaaS (平台即服務)，客戶「不需要」負責管理什麼？",
        "options": [
            "(A) 應用程式",
            "(B) 資料",
            "(C) 作業系統 (OS) 與中介軟體 (Middleware) 的修補",
            "(D) 使用者權限"
        ],
        "answer": "C",
        "note": "114 概論教材。PaaS 模式下，OS 與中介軟體由雲端供應商負責維護。"
    },
    {
        "id": "B12-Plan-12",
        "question": "關於雲端服務的「資料主權 (Data Sovereignty)」，其主要考量為何？",
        "options": [
            "(A) 資料的備份速度",
            "(B) 資料儲存所在的地理位置，需符合當地的法律法規 (如 GDPR)",
            "(C) 資料的加密演算法",
            "(D) 資料的壓縮比率"
        ],
        "answer": "B",
        "note": "資料存在哪個國家，就受該國法律管轄，是跨國雲端服務的合規重點。"
    },
    {
        "id": "B12-Plan-13",
        "question": "企業導入 SaaS 服務 (如 Microsoft 365) 時，最重要的資安設定通常是？",
        "options": [
            "(A) 調整防火牆規則",
            "(B) 啟用 MFA (多因子認證) 與正確的存取權限設定",
            "(C) 安裝防毒軟體",
            "(D) 備份硬碟"
        ],
        "answer": "B",
        "note": "SaaS 的安全性主要取決於身分識別與存取管理 (IAM) 的設定。"
    },
    {
        "id": "B12-Plan-14",
        "question": "關於 ISO 27017 (雲端資安) 標準，它主要補充了 ISO 27002 的什麼不足？",
        "options": [
            "(A) 實體安全",
            "(B) 針對雲端服務提供者與客戶的特定資安控制措施 (如虛擬化安全、多租戶隔離)",
            "(C) 程式碼開發",
            "(D) 稽核流程"
        ],
        "answer": "B",
        "note": "ISO 27017 提供了雲端特有的控制指引。"
    },
    {
        "id": "B12-Plan-15",
        "question": "在使用公有雲時，若發生資安事件，第一步應參考什麼文件來釐清責任與通報流程？",
        "options": [
            "(A) 報紙新聞",
            "(B) SLA (服務水準協議) 與責任共擔模型說明",
            "(C) 員工手冊",
            "(D) 技術論壇"
        ],
        "answer": "B",
        "note": "SLA 與合約定義了雙方的責任邊界與應變義務。"
    },
    // --- 供應鏈與採購 ---
    {
        "id": "B12-Plan-16",
        "question": "機關辦理資通系統委外時，應在「招標階段」做什麼？",
        "options": [
            "(A) 決定廠商",
            "(B) 將資安需求 (如 SSDLC、檢測項目) 納入 RFP (徵求建議書) 與契約草案",
            "(C) 驗收系統",
            "(D) 支付款項"
        ],
        "answer": "B",
        "note": "114 概論教材。招標階段需將資安規格明確化，作為後續履約與驗收的依據。"
    },
    {
        "id": "B12-Plan-17",
        "question": "關於軟體供應鏈安全，要求廠商提供 SBOM (軟體物料清單) 的好處是？",
        "options": [
            "(A) 可以殺價",
            "(B) 當開源元件 (如 Log4j) 爆發漏洞時，能快速清查受影響的系統",
            "(C) 增加軟體效能",
            "(D) 減少硬碟空間"
        ],
        "answer": "B",
        "note": "SBOM 提供了軟體成分的透明度，是供應鏈風險管理的關鍵工具。"
    },
    {
        "id": "B12-Plan-18",
        "question": "對於委外廠商的駐點人員，應採取何種管理措施？",
        "options": [
            "(A) 完全信任",
            "(B) 簽署保密協議 (NDA)，並限制其僅能存取業務所需的系統與資料 (最小權限)",
            "(C) 給予最高管理員權限方便做事",
            "(D) 不需要管理"
        ],
        "answer": "B",
        "note": "駐點人員視同內部人員管理，但需更嚴格的權限控管與保密要求。"
    },
    {
        "id": "B12-Plan-19",
        "question": "在驗收委外開發的系統時，除了功能測試外，還應要求廠商提供什麼？",
        "options": [
            "(A) 發票",
            "(B) 安全性檢測報告 (如源碼掃描、弱點掃描、滲透測試)",
            "(C) 員工名單",
            "(D) 廣告文宣"
        ],
        "answer": "B",
        "note": "114 概論教材。資安檢測報告是確認系統符合資安需求的重要驗收文件。"
    },
    {
        "id": "B12-Plan-20",
        "question": "若委外廠商需要遠端維護系統，應採取什麼原則？",
        "options": [
            "(A) 開放 Any-to-Any",
            "(B) 原則禁止、例外允許，並採短天期開放、限制來源 IP、啟用 MFA 與全程側錄",
            "(C) 使用 TeamViewer 並共用密碼",
            "(D) 給予永久 VPN 權限"
        ],
        "answer": "B",
        "note": "114 概論教材。嚴格管控遠端維護通道是防止供應鏈攻擊的重要措施。"
    },
    // --- 其他法規與標準 ---
    {
        "id": "B12-Plan-21",
        "question": "依據《資通安全事件通報及應變辦法》，第 3 級資安事件的審核時限為？",
        "options": [
            "(A) 1 小時",
            "(B) 2 小時",
            "(C) 8 小時",
            "(D) 24 小時"
        ],
        "answer": "B",
        "note": "114 概論教材。第 3、4 級事件較嚴重，上級機關需在 2 小時內完成審核。"
    },
    {
        "id": "B12-Plan-22",
        "question": "關於《個人資料保護法》，公務機關保有個資檔案，應由誰核定資通安全責任等級？",
        "options": [
            "(A) 總統",
            "(B) 主管機關 (數位部) 核定或備查",
            "(C) 自己決定就好",
            "(D) 民眾投票"
        ],
        "answer": "B",
        "note": "資通安全責任等級需報請主管機關核定或備查。"
    },
    {
        "id": "B12-Plan-23",
        "question": "ISO 27001:2022 的控制措施 5.23「使用雲端服務之資訊安全」，要求組織？",
        "options": [
            "(A) 禁止使用雲端",
            "(B) 應訂定使用雲端服務的獲取、使用、管理與退場之安全程序",
            "(C) 只能使用私有雲",
            "(D) 雲端廠商負責所有安全"
        ],
        "answer": "B",
        "note": "組織需建立雲端服務的治理與管理流程，而非放任使用。"
    },
    {
        "id": "B12-Plan-24",
        "question": "關於「資安情資分享 (ISAC)」，其主要效益為？",
        "options": [
            "(A) 洩漏公司機密",
            "(B) 透過聯防機制，及早獲取威脅預警，提升整體防禦能力",
            "(C) 增加工作負擔",
            "(D) 為了社交"
        ],
        "answer": "B",
        "note": "ISAC (Information Sharing and Analysis Center) 促進情資交流，實現資安聯防。"
    },
    {
        "id": "B12-Plan-25",
        "question": "依據 NIST SP 800-53，資安控制措施分為 Low, Moderate, High 三個基準 (Baseline)，其選擇依據為？",
        "options": [
            "(A) 預算多寡",
            "(B) FIPS 199 的安全分類 (系統對 CIA 的衝擊程度)",
            "(C) 系統管理員的喜好",
            "(D) 廠商建議"
        ],
        "answer": "B",
        "note": "系統的安全分類 (Impact Level) 決定了需實施的控制措施基準。"
    },
    // --- 綜合題 ---
    {
        "id": "B12-Plan-26",
        "question": "在資安事故後，進行「根因分析 (Root Cause Analysis)」的主要工具或方法不包括？",
        "options": [
            "(A) 5 Whys (五個為什麼)",
            "(B) 魚骨圖 (Fishbone Diagram)",
            "(C) 責怪員工 (Blame Game)",
            "(D) 時間軸分析"
        ],
        "answer": "C",
        "note": "根因分析旨在找出流程或系統的缺陷，而非單純責怪個人。"
    },
    {
        "id": "B12-Plan-27",
        "question": "關於「行動應用程式安全」，開發者應避免？",
        "options": [
            "(A) 使用 HTTPS",
            "(B) 在程式碼中 Hard-code 金鑰或密碼",
            "(C) 進行混淆 (Obfuscation)",
            "(D) 檢查 Root/Jailbreak"
        ],
        "answer": "B",
        "note": "Hard-code 金鑰極易透過逆向工程被提取，造成嚴重風險。"
    },
    {
        "id": "B12-Plan-28",
        "question": "關於「社交工程演練」的信件內容，下列何者最容易誘騙成功？",
        "options": [
            "(A) 全英文的廣告信",
            "(B) 結合時事 (如疫情補助、退稅) 或公司內部流程 (如薪資單、考績) 的偽造信件",
            "(C) 亂碼信",
            "(D) 空白信"
        ],
        "answer": "B",
        "note": "針對性高、結合時事或利益相關的內容，最能降低受害者的戒心。"
    },
    {
        "id": "B12-Plan-29",
        "question": "在資安險中，若因駭客入侵導致公司無法營運而造成的收入損失，通常由哪種條款理賠？",
        "options": [
            "(A) 資料外洩責任",
            "(B) 營業中斷損失 (Business Interruption Loss)",
            "(C) 勒索贖金",
            "(D) 硬體損壞"
        ],
        "answer": "B",
        "note": "營業中斷險賠償因資安事件停業期間的毛利損失與額外費用。"
    },
    {
        "id": "B12-Plan-30",
        "question": "關於資安長的資格，通常要求？",
        "options": [
            "(A) 只要會寫程式",
            "(B) 具備資安管理、風險評估、溝通協調能力，並持有相關證照 (如 CISSP, CISM)",
            "(C) 只要是 IT 主管",
            "(D) 只要年資夠久"
        ],
        "answer": "B",
        "note": "資安長需具備全方位的管理與技術視野。"
    }
];

// 將 Batch 12 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch12);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch12);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第十三批次 (Batch 13)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：VANS/GCB 實務、進階 Web 漏洞、資安治理指標、三道防線
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch13 = [
    // --- 政府資安規範技術實務 (VANS/GCB) ---
    {
        "id": "B13-Prot-01",
        "question": "關於「政府機關資安弱點通報機制 (VANS)」的運作方式，下列何者正確？",
        "options": [
            "(A) 機關需手動上傳每一個漏洞的修補截圖",
            "(B) 機關導入資產弱點管理系統，將資產盤點資訊 (CPE) 上傳至 VANS 平台，由平台自動比對 CVE 弱點",
            "(C) VANS 會自動修補機關的所有漏洞",
            "(D) 僅針對網頁應用程式進行掃描"
        ],
        "answer": "B",
        "note": "114 概論教材。VANS 的核心是標準化資產資訊 (CPE) 與弱點資料庫 (CVE) 的自動比對。"
    },
    {
        "id": "B13-Prot-02",
        "question": "在 GCB (政府組態基準) 中，針對「瀏覽器」的安全設定，下列何者通常是被要求的項目？",
        "options": [
            "(A) 啟用所有 ActiveX 控制項",
            "(B) 關閉「智慧篩選 (SmartScreen)」功能",
            "(C) 禁止儲存密碼、啟用快顯封鎖程式、強制檢查憑證吊銷狀態",
            "(D) 允許執行所有 Java Applet"
        ],
        "answer": "C",
        "note": "114 概論教材。GCB 旨在透過「最小權限」與「關閉不必要功能」來強化終端安全。"
    },
    // --- Web 與應用程式安全 (高階) ---
    {
        "id": "B13-Prot-03",
        "question": "攻擊者利用 XML 解析器的設定漏洞，在 XML 文件中引用外部實體 (如 `<!ENTITY xxe SYSTEM \"file:///etc/passwd\" >`)，這屬於？",
        "options": [
            "(A) XSS",
            "(B) XXE (XML External Entity) Injection",
            "(C) SQL Injection",
            "(D) LDAP Injection"
        ],
        "answer": "B",
        "note": "XXE 可導致讀取本機檔案、SSRF 或阻斷服務。防禦方式是停用 XML 解析器的 DTD/Entity 功能。"
    },
    {
        "id": "B13-Prot-04",
        "question": "關於「不安全的反序列化 (Insecure Deserialization)」漏洞，其根本原因為何？",
        "options": [
            "(A) 密碼太短",
            "(B) 應用程式在還原物件 (Deserialize) 時，未驗證資料來源或內容，導致執行了惡意物件中的代碼",
            "(C) 資料庫欄位太小",
            "(D) 網路頻寬不足"
        ],
        "answer": "B",
        "note": "這是 OWASP Top 10 的常客，攻擊者可藉此達成 RCE (遠端代碼執行)。"
    },
    {
        "id": "B13-Prot-05",
        "question": "在 OAuth 2.0 中，若 `redirect_uri` 驗證不嚴謹，可能導致什麼攻擊？",
        "options": [
            "(A) SQL Injection",
            "(B) Authorization Code 洩漏，攻擊者可攔截 Code 並換取 Access Token",
            "(C) 伺服器當機",
            "(D) 資料庫被刪除"
        ],
        "answer": "B",
        "note": "攻擊者可將 redirect_uri 指向自己的伺服器，誘使受害者登入後將授權碼傳送給攻擊者。"
    },
    // --- 網路與雲端安全 ---
    {
        "id": "B13-Prot-06",
        "question": "關於 TLS 1.3 的「0-RTT (Zero Round Trip Time) Resumption」功能，其潛在的資安風險是？",
        "options": [
            "(A) 加密強度不足",
            "(B) 重送攻擊 (Replay Attack)，攻擊者可擷取並重送 0-RTT 請求 (如重複轉帳)",
            "(C) 憑證過期",
            "(D) 無法使用 ECC"
        ],
        "answer": "B",
        "note": "雖然 0-RTT 加速了連線，但應用層需處理 Replay 風險 (如只允許 GET 請求使用 0-RTT)。"
    },
    {
        "id": "B13-Prot-07",
        "question": "在雲端環境 (如 AWS/GCP) 中，攻擊者透過 SSRF 存取 `http://169.254.169.254/latest/meta-data/`，其目的是？",
        "options": [
            "(A) 下載網頁原始碼",
            "(B) 獲取實例 (Instance) 的 IAM 角色憑證 (Credentials)，以接管雲端帳號",
            "(C) 測試網路連線",
            "(D) 更新系統時間"
        ],
        "answer": "B",
        "note": "114 概論教材。這是雲端環境中最經典的 SSRF 攻擊利用方式。"
    },
    {
        "id": "B13-Prot-08",
        "question": "關於 DNS over HTTPS (DoH) 對企業資安監控的影響，下列何者正確？",
        "options": [
            "(A) 讓監控更容易",
            "(B) 因 DNS 流量被加密隱藏在 HTTPS 中，傳統防火牆無法過濾惡意網域 (DNS Filtering 失效)",
            "(C) 降低網路延遲",
            "(D) 增加頻寬"
        ],
        "answer": "B",
        "note": "DoH 保護了隱私，但也讓企業難以阻擋員工連線至惡意網站，需改用端點防護或支援 DoH 解析的防火牆。"
    },
    // --- 系統與端點防護 ---
    {
        "id": "B13-Prot-09",
        "question": "在 Linux 系統中，`/etc/shadow` 檔案的權限應設定為？",
        "options": [
            "(A) 777 (所有人可讀寫)",
            "(B) 644 (所有人可讀)",
            "(C) 000 (所有人不可讀寫，僅 Root 可強制讀取)",
            "(D) 400 或 600 (僅 Root 可讀/讀寫)",
        ],
        "answer": "D",
        "note": "`shadow` 存放密碼雜湊，必須嚴格限制僅 root 可讀 (400/600)，一般使用者不應有權限。"
    },
    {
        "id": "B13-Prot-10",
        "question": "Windows 系統中，攻擊者利用 `SAM` 檔案是為了獲取什麼？",
        "options": [
            "(A) 瀏覽器紀錄",
            "(B) 本機使用者帳號的 NTLM Hash (如 Administrator)",
            "(C) 網路設定",
            "(D) 系統日誌"
        ],
        "answer": "B",
        "note": "SAM (Security Account Manager) 資料庫儲存本機帳號密碼雜湊。"
    },
    {
        "id": "B13-Prot-11",
        "question": "關於 AES 加密演算法的「GCM (Galois/Counter Mode)」模式，其優點為？",
        "options": [
            "(A) 速度最慢",
            "(B) 同時提供資料加密 (Confidentiality) 與完整性驗證 (Integrity)，屬於 AEAD",
            "(C) 不需要 IV",
            "(D) 只能用於無線網路"
        ],
        "answer": "B",
        "note": "GCM 效率高且內建驗證，是目前 TLS 1.3 與 VPN 推薦使用的模式。"
    },
    {
        "id": "B13-Prot-12",
        "question": "在端點防護中，針對「無檔案 (Fileless) 惡意軟體」的最佳偵測方式是？",
        "options": [
            "(A) 掃描硬碟檔案",
            "(B) 監控記憶體中的行為 (如 PowerShell 執行字串、WMI 呼叫)",
            "(C) 檢查檔案雜湊值",
            "(D) 檢查檔案建立日期"
        ],
        "answer": "B",
        "note": "Fileless 不落地，傳統防毒掃描硬碟無效，需依賴 EDR 的行為監控。"
    },
    // --- 攻防技術與鑑識 ---
    {
        "id": "B13-Prot-13",
        "question": "攻擊者利用「Typosquatting (域名搶註/錯字)」攻擊供應鏈 (如 npm, pip)，其手法是？",
        "options": [
            "(A) 攻擊官方伺服器",
            "(B) 上傳一個名稱與熱門套件極為相似的惡意套件 (如 `requests` vs `requsets`)，誘使開發者打錯字安裝",
            "(C) 修改開發者電腦",
            "(D) 猜測管理員密碼"
        ],
        "answer": "B",
        "note": "這是軟體供應鏈攻擊的常見手法，針對開發者的輸入錯誤。"
    },
    {
        "id": "B13-Prot-14",
        "question": "在網路封包中，若發現 TTL (Time To Live) 值異常變動，可能代表？",
        "options": [
            "(A) 網路速度變快",
            "(B) 存在中間人攻擊、作業系統指紋 (OS Fingerprinting) 或路由路徑改變",
            "(C) 硬碟故障",
            "(D) 應用程式錯誤"
        ],
        "answer": "B",
        "note": "不同 OS 的預設 TTL 不同 (Win=128, Linux=64)，可用於識別 OS 或偵測異常路由。"
    },
    {
        "id": "B13-Prot-15",
        "question": "關於圖片中的「EXIF Metadata」，在資安上的隱私風險是？",
        "options": [
            "(A) 檔案太大",
            "(B) 可能包含拍攝地點的 GPS 座標、設備型號與拍攝時間，導致位置隱私外洩",
            "(C) 圖片畫質降低",
            "(D) 容易中毒"
        ],
        "answer": "B",
        "note": "上傳圖片前應清除 EXIF 資訊，避免洩漏物理位置。"
    },
    {
        "id": "B13-Prot-16",
        "question": "關於「多型病毒 (Polymorphic Virus)」的特徵，下列何者正確？",
        "options": [
            "(A) 每次感染時會改變自己的程式碼 (加密/解密迴圈)，但功能不變，以躲避特徵碼偵測",
            "(B) 同時感染 Windows 和 Linux",
            "(C) 檔案非常大",
            "(D) 不會破壞資料"
        ],
        "answer": "A",
        "note": "多型病毒透過變換特徵碼 (Signature) 來對抗傳統防毒軟體。"
    },
    {
        "id": "B13-Prot-17",
        "question": "攻擊者使用 `Man-in-the-Browser (MitB)` 攻擊，通常是透過什麼方式？",
        "options": [
            "(A) 綁架 DNS",
            "(B) 植入瀏覽器擴充套件 (Extension) 或木馬，在使用者看到網頁前即時修改內容 (如竄改轉帳帳號)",
            "(C) 破壞海底電纜",
            "(D) 關閉螢幕"
        ],
        "answer": "B",
        "note": "MitB 發生在端點瀏覽器內，HTTPS 無法防禦 (因為在加密前/解密後就被修改了)。"
    },
    {
        "id": "B13-Prot-18",
        "question": "無線網路攻擊「Evil Twin」的主要目的是？",
        "options": [
            "(A) 破解 Wi-Fi 密碼",
            "(B) 偽裝成合法 AP，誘騙使用者連線後，進行釣魚或中間人攻擊",
            "(C) 增加訊號覆蓋率",
            "(D) 測試網路速度"
        ],
        "answer": "B",
        "note": "利用使用者裝置會自動連線到「名稱相同 (SSID)」且「訊號較強」AP 的特性。"
    },
    {
        "id": "B13-Prot-19",
        "question": "關於 Android App 的 `APK Signature Scheme`，其作用是？",
        "options": [
            "(A) 加密 App",
            "(B) 確保 APK 檔案在發布後未被竄改，並驗證開發者身分",
            "(C) 壓縮 APK",
            "(D) 提高執行速度"
        ],
        "answer": "B",
        "note": "Android 系統在安裝 App 時會驗證簽章，若簽章不符或檔案被改，將拒絕安裝。"
    },
    {
        "id": "B13-Prot-20",
        "question": "在雲端 Serverless 架構中，若函數 (Function) 存在「Cold Start (冷啟動)」特性，攻擊者可能利用此特性進行什麼攻擊？",
        "options": [
            "(A) 竊取資料",
            "(B) 資源耗盡 (Denial of Wallet) 攻擊，透過大量請求迫使系統不斷啟動新實例，消耗預算",
            "(C) 提權",
            "(D) 關閉帳號"
        ],
        "answer": "B",
        "note": "這是一種針對雲端計費模式的攻擊，旨在造成財務損失。"
    },
    // --- 綜合技術應用 ---
    {
        "id": "B13-Prot-21",
        "question": "Kubernetes 的 `Pod Security Standards (PSS)` 中，限制最嚴格的策略是？",
        "options": [
            "(A) Privileged",
            "(B) Baseline",
            "(C) Restricted",
            "(D) Open"
        ],
        "answer": "C",
        "note": "Restricted 策略強烈限制 Pod 的權限 (如禁止 Root, 限制 Volume 類型)，適用於高安全需求。"
    },
    {
        "id": "B13-Prot-22",
        "question": "在供應鏈攻擊中，攻擊者入侵 CI/CD 伺服器 (如 Jenkins) 的主要目的是？",
        "options": [
            "(A) 用來挖礦",
            "(B) 在軟體建置 (Build) 過程中注入惡意程式碼，汙染下游所有使用者",
            "(C) 練習打字",
            "(D) 測試伺服器效能"
        ],
        "answer": "B",
        "note": "SolarWinds 事件即為典型案例，攻擊者在 Build 階段植入後門。"
    },
    {
        "id": "B13-Prot-23",
        "question": "關於身分認證攻擊，「Credential Stuffing (撞庫)」與「Brute Force (暴力破解)」的主要差異？",
        "options": [
            "(A) 沒差異",
            "(B) 撞庫使用「已洩漏的真實帳密」列表嘗試登入；暴力破解則是嘗試「所有可能的字元組合」",
            "(C) 撞庫比較慢",
            "(D) 暴力破解只能用在 SSH"
        ],
        "answer": "B",
        "note": "撞庫成功率通常較高，因為使用者常在不同網站使用相同密碼。"
    },
    {
        "id": "B13-Prot-24",
        "question": "社交工程中的「Pretexting (假託/藉口)」是指？",
        "options": [
            "(A) 寄送大量垃圾信",
            "(B) 攻擊者編造一個虛構的情境或身分 (如 IT 支援人員)，以騙取受害者信任並提供資訊",
            "(C) 撿垃圾桶",
            "(D) 尾隨進入公司"
        ],
        "answer": "B",
        "note": "Pretexting 是社交工程的前置作業，旨在建立信任基礎。"
    },
    {
        "id": "B13-Prot-25",
        "question": "實體安全中，RFID 門禁卡最常見的攻擊風險是？",
        "options": [
            "(A) 卡片折斷",
            "(B) 側錄與複製 (Cloning)",
            "(C) 沒電",
            "(D) 消磁"
        ],
        "answer": "B",
        "note": "舊式低頻 RFID 卡無加密，極易被側錄器複製。"
    },
    {
        "id": "B13-Prot-26",
        "question": "關於蜜罐 (Honeypot) 的類型，`Low-interaction` (低互動) 與 `High-interaction` (高互動) 的差異？",
        "options": [
            "(A) 低互動模擬服務回應，風險低；高互動提供真實作業系統，風險高但能收集詳細攻擊行為",
            "(B) 低互動比較貴",
            "(C) 高互動不能聯網",
            "(D) 兩者都無風險"
        ],
        "answer": "A",
        "note": "高互動蜜罐 (如真實 VM) 若被攻破，可能成為攻擊者的跳板，需嚴格隔離。"
    },
    {
        "id": "B13-Prot-27",
        "question": "使用 Nmap 進行作業系統偵測的參數是？",
        "options": [
            "(A) -sS",
            "(B) -O (OS Detection)",
            "(C) -sV",
            "(D) -A"
        ],
        "answer": "B",
        "note": "`-O` 會分析 TCP/IP 堆疊特徵來猜測作業系統；`-sV` 是服務版本；`-A` 是綜合掃描。"
    },
    {
        "id": "B13-Prot-28",
        "question": "SNMPv3 相較於 v1/v2c，增加的最重要安全功能是？",
        "options": [
            "(A) 速度更快",
            "(B) 訊息完整性、驗證與加密 (Authentication and Encryption)",
            "(C) 支援更多設備",
            "(D) 介面更漂亮"
        ],
        "answer": "B",
        "note": "v1/v2c 使用明文 Community String，v3 提供了 USM (User-based Security Model)。"
    },
    {
        "id": "B13-Prot-29",
        "question": "關於「Security through Obscurity (隱匿式安全)」的觀念，資安界的看法是？",
        "options": [
            "(A) 是最佳的防禦策略",
            "(B) 不應作為唯一的防禦手段，因為秘密一旦被發現，系統就無防護能力",
            "(C) 只要藏得好就沒問題",
            "(D) 是 ISO 27001 的要求"
        ],
        "answer": "B",
        "note": "真正的安全應基於設計與數學強度，而非依賴「沒人知道」。"
    },
    {
        "id": "B13-Prot-30",
        "question": "在資安防護中，「縱深防禦 (Defense in Depth)」與「單點防禦」的最大差別是？",
        "options": [
            "(A) 預算不同",
            "(B) 縱深防禦建立多層次防線，單一防線失效不代表整體崩潰",
            "(C) 單點防禦比較強",
            "(D) 縱深防禦只用防火牆"
        ],
        "answer": "B",
        "note": "縱深防禦 (DiD) 是現代資安架構的核心原則。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch13 = [
    // --- 法規與合規 (進階) ---
    {
        "id": "B13-Plan-01",
        "question": "依據《資通安全責任等級分級辦法》，特定非公務機關 (如關鍵基礎設施提供者) 若被核定為 A 級，其應辦事項要求與公務機關相比？",
        "options": [
            "(A) 完全不同",
            "(B) 大致相同，皆需導入 ISMS、配置專職人員、定期檢測與演練",
            "(C) 較寬鬆",
            "(D) 不需要做資安"
        ],
        "answer": "B",
        "note": "114 概論教材。CI 提供者 (A級) 的要求比照 A 級公務機關，甚至在某些監管上更嚴格。"
    },
    {
        "id": "B13-Plan-02",
        "question": "在資安治理中，「三道防線」模型的第一道防線 (First Line of Defense) 是指？",
        "options": [
            "(A) 內部稽核",
            "(B) 風險管理部門",
            "(C) 營運管理單位 (Business Operations) 與 IT 單位 (直接面對風險者)",
            "(D) 外部顧問"
        ],
        "answer": "C",
        "note": "第一道防線是直接擁有和管理風險的單位 (如 IT、業務)。"
    },
    {
        "id": "B13-Plan-03",
        "question": "關於 ISO 27001:2022 的「Themes (主題)」分類，將 93 項控制措施分為哪 4 類？",
        "options": [
            "(A) 組織、人員、實體、技術 (Organizational, People, Physical, Technological)",
            "(B) 預防、偵測、回應、復原",
            "(C) 紅隊、藍隊、紫隊、白隊",
            "(D) 規劃、執行、查核、行動"
        ],
        "answer": "A",
        "note": "這是 2022 版最顯著的結構改變，取代了舊版的 14 個領域。"
    },
    {
        "id": "B13-Plan-04",
        "question": "NIST CSF 2.0 的「Govern (治理)」功能，主要強調？",
        "options": [
            "(A) 購買設備",
            "(B) 組織的資安策略應與業務使命及風險管理策略一致，並建立監督機制",
            "(C) 修補漏洞",
            "(D) 備份資料"
        ],
        "answer": "B",
        "note": "Govern 確保資安不再只是 IT 的事，而是組織整體的戰略議題。"
    },
    // --- 風險管理與指標 ---
    {
        "id": "B13-Plan-05",
        "question": "關於資安績效指標，「領先指標 (Leading Indicator)」與「落後指標 (Lagging Indicator)」的區別？",
        "options": [
            "(A) 沒區別",
            "(B) 落後指標看過去 (如發生多少事故)；領先指標看未來 (如漏洞修補率、演練合格率)，具預警作用",
            "(C) 領先指標比較貴",
            "(D) 落後指標比較準"
        ],
        "answer": "B",
        "note": "好的儀表板應包含這兩種指標，以兼顧績效檢討與風險預警。"
    },
    {
        "id": "B13-Plan-06",
        "question": "在風險評估中，Quantitative (定量) 與 Qualitative (定性) 的主要優缺點比較？",
        "options": [
            "(A) 定量較主觀，定性較客觀",
            "(B) 定量提供具體財務數據 (ROI)，但耗時且數據難取得；定性快速易懂，但較主觀",
            "(C) 定性一定要用計算機",
            "(D) 兩者都不能用"
        ],
        "answer": "B",
        "note": "管理層通常偏好定量 (錢)，但實務上常因數據不足而採用定性 (高/中/低)。"
    },
    // --- 營運持續與隱私 ---
    {
        "id": "B13-Plan-07",
        "question": "在 BCP 測試中，「桌面演練 (Tabletop Exercise)」的主要進行方式是？",
        "options": [
            "(A) 關閉電源",
            "(B) 團隊成員圍坐討論，針對特定情境 (Scenario) 逐步檢視計畫流程是否合理",
            "(C) 實際切換機房",
            "(D) 重新安裝系統"
        ],
        "answer": "B",
        "note": "桌面演練成本低、干擾小，是驗證邏輯與溝通流程的首選方式。"
    },
    {
        "id": "B13-Plan-08",
        "question": "關於「隱私衝擊評估 (PIA / DPIA)」的觸發時機，下列何者最恰當？",
        "options": [
            "(A) 專案結束後",
            "(B) 在專案啟動初期或變更設計時，尤其是涉及大量敏感個資處理",
            "(C) 發生洩漏後",
            "(D) 年度聚餐時"
        ],
        "answer": "B",
        "note": "Privacy by Design 要求在設計階段即識別並緩解隱私風險。"
    },
    {
        "id": "B13-Plan-09",
        "question": "在雲端服務合約中，Exit Strategy (退場策略) 的重要性在於？",
        "options": [
            "(A) 確保可以隨時更換供應商，並能完整取回資料，避免 Vendor Lock-in",
            "(B) 為了殺價",
            "(C) 為了購買更多服務",
            "(D) 為了減少備份"
        ],
        "answer": "A",
        "note": "缺乏退場策略可能導致被供應商綁架，或在終止服務時遺失關鍵資料。"
    },
    {
        "id": "B13-Plan-10",
        "question": "關於供應鏈合約中的「Right to Audit (稽核權)」，其目的為？",
        "options": [
            "(A) 增加廠商成本",
            "(B) 確保機關有權力對廠商的資安落實狀況進行實地或書面查核",
            "(C) 取得廠商原始碼",
            "(D) 延後付款"
        ],
        "answer": "B",
        "note": "稽核權是確保供應商合規性的最終手段。"
    },
    // --- 實務管理細節 ---
    {
        "id": "B13-Plan-11",
        "question": "在人員安全管理中，「背景查核 (Background Check)」通常在何時進行？",
        "options": [
            "(A) 離職時",
            "(B) 聘用前 (Pre-employment)，尤其是針對接觸敏感資訊的職位",
            "(C) 每年一次",
            "(D) 發生事故後"
        ],
        "answer": "B",
        "note": "事前過濾是降低內部威脅 (Insider Threat) 的第一道關卡。"
    },
    {
        "id": "B13-Plan-12",
        "question": "關於資產歸還 (Return of Assets) 的程序，應在何時啟動？",
        "options": [
            "(A) 員工聘用終止或合約結束時",
            "(B) 員工生日時",
            "(C) 每年盤點時",
            "(D) 設備故障時"
        ],
        "answer": "A",
        "note": "離職程序 (Offboarding) 必須包含實體資產與邏輯權限的回收。"
    },
    {
        "id": "B13-Plan-13",
        "question": "在權限管理中，「使用者存取權限審查 (User Access Review)」建議多久進行一次？",
        "options": [
            "(A) 10 年",
            "(B) 定期 (如每半年或一年)，且在職務異動時立即進行",
            "(C) 系統上線時做一次就好",
            "(D) 從不"
        ],
        "answer": "B",
        "note": "定期審查可防止「權限蔓延 (Privilege Creep)」，確保權限符合現況。"
    },
    {
        "id": "B13-Plan-14",
        "question": "關於實體安全中的「安全區域 (Secure Areas)」，進出管制應採取什麼原則？",
        "options": [
            "(A) 歡迎光臨",
            "(B) 需知原則 (Need-to-Know) 與 最小權限，僅授權必要人員進入",
            "(C) 只要是主管都可進入",
            "(D) 方便就好"
        ],
        "answer": "B",
        "note": "機房等安全區域應嚴格限制進出，並留存進出紀錄。"
    },
    {
        "id": "B13-Plan-15",
        "question": "在容量管理 (Capacity Management) 中，除了硬碟空間外，還需監控？",
        "options": [
            "(A) CPU、記憶體、網路頻寬等資源的使用趨勢",
            "(B) 員工體重",
            "(C) 辦公室座位",
            "(D) 印表機紙張"
        ],
        "answer": "A",
        "note": "預測資源需求可防止因資源耗盡導致的可用性問題 (Availability)。"
    },
    {
        "id": "B13-Plan-16",
        "question": "關於保密協議 (NDA) 的簽署對象，應包含？",
        "options": [
            "(A) 只有正職員工",
            "(B) 員工、承包商、供應商及任何可能接觸機密資訊的第三方",
            "(C) 只有工讀生",
            "(D) 只有高階主管"
        ],
        "answer": "B",
        "note": "NDA 是法律上的保護傘，應覆蓋所有接觸敏感資訊的人員。"
    },
    {
        "id": "B13-Plan-17",
        "question": "在軟體開發環境中，為什麼需要「開發、測試、正式環境分離」？",
        "options": [
            "(A) 為了多買伺服器",
            "(B) 防止開發測試過程影響正式營運，並避免正式資料外洩到低安全性的開發環境",
            "(C) 為了讓開發人員更忙",
            "(D) 沒有原因"
        ],
        "answer": "B",
        "note": "環境隔離是 ISO 27001 的基本要求，防止誤操作與資料外洩。"
    },
    {
        "id": "B13-Plan-18",
        "question": "資安事故發生後，「經驗學習 (Lessons Learned)」階段的主要產出是？",
        "options": [
            "(A) 找戰犯",
            "(B) 改善行動計畫 (Improvement Plan)，修正流程與控制措施，防止再發",
            "(C) 刪除日誌",
            "(D) 隱瞞事實"
        ],
        "answer": "B",
        "note": "將事故轉化為組織免疫力，是應變流程最有價值的一環。"
    },
    {
        "id": "B13-Plan-19",
        "question": "在軟體授權合規 (License Compliance) 中，企業應避免什麼？",
        "options": [
            "(A) 使用正版軟體",
            "(B) 使用盜版軟體或違反開源授權 (如將 GPL 程式碼閉源商用)",
            "(C) 購買授權",
            "(D) 盤點軟體資產"
        ],
        "answer": "B",
        "note": "違反授權可能導致法律訴訟與商譽損失。"
    },
    {
        "id": "B13-Plan-20",
        "question": "關於「稽核軌跡 (Audit Trail)」的保護，下列何者正確？",
        "options": [
            "(A) 允許管理員隨意修改",
            "(B) 應唯讀儲存，並受到嚴格存取控制，防止竄改與刪除",
            "(C) 不需要備份",
            "(D) 開放給所有人看"
        ],
        "answer": "B",
        "note": "日誌是調查與究責的依據，必須確保其完整性 (如傳送到遠端 Log Server)。"
    },
    // --- CMMC 與新趨勢 ---
    {
        "id": "B13-Plan-21",
        "question": "CMMC (網路安全成熟度模型驗證) 的 Level 1 (Foundational) 主要聚焦於？",
        "options": [
            "(A) 保護國家機密",
            "(B) 保護聯邦契約資訊 (FCI)，實施基本的 17 項資安要求",
            "(C) 進階持續性威脅防禦",
            "(D) 沒有要求"
        ],
        "answer": "B",
        "note": "114 概論教材。Level 1 是基礎級，適用於所有國防供應商。"
    },
    {
        "id": "B13-Plan-22",
        "question": "在零信任架構中，PDP (Policy Decision Point) 的功能是？",
        "options": [
            "(A) 執行阻擋",
            "(B) 依據政策與情境資訊，運算並決定是否授權存取",
            "(C) 儲存資料",
            "(D) 掃描病毒"
        ],
        "answer": "B",
        "note": "PDP 是大腦 (決策)，PEP (Policy Enforcement Point) 是手腳 (執行)。"
    },
    {
        "id": "B13-Plan-23",
        "question": "工控系統 (OT) 資安的首要考量 (Priority) 通常是？",
        "options": [
            "(A) 機密性 (Confidentiality)",
            "(B) 可用性 (Availability) 與 人身安全 (Safety)",
            "(C) 完整性 (Integrity)",
            "(D) 隱私性 (Privacy)"
        ],
        "answer": "B",
        "note": "OT 環境涉及物理運作，系統停擺或誤動作可能造成人員傷亡，故 Safety/Availability 優先。"
    },
    {
        "id": "B13-Plan-24",
        "question": "面對「對抗式機器學習 (Adversarial ML)」攻擊，企業應？",
        "options": [
            "(A) 停止使用 AI",
            "(B) 了解 AI 模型的弱點，保護訓練資料與模型參數，並監控異常輸入",
            "(C) 公開所有模型細節",
            "(D) 不需理會"
        ],
        "answer": "B",
        "note": "AI 模型也是資產，需防範 Model Inversion, Evasion, Poisoning 等攻擊。"
    },
    {
        "id": "B13-Plan-25",
        "question": "在資料治理中，「資料擁有者 (Data Owner)」與「資料保管者 (Data Custodian)」的區別？",
        "options": [
            "(A) 沒區別",
            "(B) Owner 負責定義資料分類與授權；Custodian (通常是 IT) 負責執行保護措施 (如備份、權限設定)",
            "(C) Custodian 權力較大",
            "(D) Owner 負責修電腦"
        ],
        "answer": "B",
        "note": "Owner 決策，Custodian 執行。"
    },
    {
        "id": "B13-Plan-26",
        "question": "關於資安指標 (Metrics)，「落後指標 (Lagging)」如事故數量，主要用途是？",
        "options": [
            "(A) 預測未來",
            "(B) 檢討過去的績效與控制措施有效性",
            "(C) 沒用處",
            "(D) 即時阻擋攻擊"
        ],
        "answer": "B",
        "note": "落後指標反映歷史表現；領先指標 (如修補率、演練分數) 預測未來風險。"
    },
    {
        "id": "B13-Plan-27",
        "question": "文件管理中，對機密文件標示「機密等級」的主要目的是？",
        "options": [
            "(A) 裝飾",
            "(B) 指示處理人員應採取的保護措施 (如加密、存放位置、銷毀方式)",
            "(C) 增加印刷成本",
            "(D) 限制閱讀速度"
        ],
        "answer": "B",
        "note": "標示 (Labeling) 是資訊分類與分級的具體實踐。"
    },
    {
        "id": "B13-Plan-28",
        "question": "行動裝置管理 (MDM) 的「遠端抹除 (Remote Wipe)」功能，主要解決什麼風險？",
        "options": [
            "(A) 手機中毒",
            "(B) 裝置遺失或遭竊時的資料外洩風險",
            "(C) 電池爆炸",
            "(D) 訊號不良"
        ],
        "answer": "B",
        "note": "這是行動資安的最後一道防線。"
    },
    {
        "id": "B13-Plan-29",
        "question": "關於遠端工作的 VPN 政策，下列何者是最佳實務？",
        "options": [
            "(A) 允許全家共用",
            "(B) 啟用 MFA，並限制僅能存取工作所需的資源 (Split Tunneling 需謹慎評估)",
            "(C) 使用弱密碼",
            "(D) 不需紀錄日誌"
        ],
        "answer": "B",
        "note": "VPN 入口是駭客攻擊重點，MFA 是必要防護。"
    },
    {
        "id": "B13-Plan-30",
        "question": "社交工程演練的頻率，依據資安法 A 級機關要求為？",
        "options": [
            "(A) 每年 1 次",
            "(B) 每半年 1 次",
            "(C) 每季 1 次",
            "(D) 每月 1 次"
        ],
        "answer": "B",
        "note": "114 概論教材。A 級機關：每半年 1 次社交工程演練。"
    }
];

// 將 Batch 13 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch13);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch13);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第十四批次 (Batch 14)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 重點：零信任實作、後量子密碼學、AI 安全、供應鏈韌性
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch14 = [
    // --- 零信任架構 (ZTA) 實作 ---
    {
        "id": "B14-Prot-01",
        "question": "在 NIST SP 800-207 零信任架構中，負責接收存取請求並執行決策（允許/拒絕）的組件是？",
        "options": [
            "(A) 政策決策點 (PDP)",
            "(B) 政策執行點 (PEP)",
            "(C) 政策資訊點 (PIP)",
            "(D) 政策管理點 (PAP)"
        ],
        "answer": "B",
        "note": "PEP 位於資源與主體之間，負責實際攔截請求並根據 PDP 的指令執行動作。"
    },
    {
        "id": "B14-Prot-02",
        "question": "關於零信任中的「信任演算法 (Trust Algorithm)」，其主要功能為何？",
        "options": [
            "(A) 加密資料",
            "(B) 綜合評估主體、資產、環境等多維度資訊，計算出動態的信任分數",
            "(C) 備份日誌",
            "(D) 產生隨機密碼"
        ],
        "answer": "B",
        "note": "信任演算法是 PDP 的核心，決定是否授權的關鍵邏輯。"
    },
    {
        "id": "B14-Prot-03",
        "question": "在實施「微分段 (Micro-segmentation)」時，最主要的技術挑戰通常是？",
        "options": [
            "(A) 硬體成本太高",
            "(B) 難以釐清應用程式之間的相依性與通訊流 (Application Dependency Mapping)",
            "(C) 網路速度變慢",
            "(D) 無法支援 IPv6"
        ],
        "answer": "B",
        "note": "若不清楚服務間的呼叫關係，實施微分段極易導致業務中斷。"
    },
    {
        "id": "B14-Prot-04",
        "question": "關於「SDP (Software Defined Perimeter)」技術，其在零信任架構中的角色是？",
        "options": [
            "(A) 取代防火牆",
            "(B) 實現「先驗證，後連線 (Authenticate before Connect)」的黑雲 (Dark Cloud) 機制，隱藏基礎設施",
            "(C) 進行病毒掃描",
            "(D) 備份資料"
        ],
        "answer": "B",
        "note": "SDP 讓服務對未經授權的使用者「不可見」，大幅減少攻擊面。"
    },
    {
        "id": "B14-Prot-05",
        "question": "在零信任環境中，對於 BYOD (Bring Your Own Device) 設備的存取控制，應優先考量？",
        "options": [
            "(A) 禁止使用",
            "(B) 透過 UEM/MDM 檢查設備健康狀態 (Device Health) 與合規性，才允許有限度存取",
            "(C) 開放所有權限",
            "(D) 只檢查帳號密碼"
        ],
        "answer": "B",
        "note": "零信任不信任網路位置，也不完全信任設備，需持續驗證其安全狀態。"
    },
    // --- 密碼學與新興技術 (進階) ---
    {
        "id": "B14-Prot-06",
        "question": "關於「後量子密碼學 (PQC)」的遷移準備，企業目前最應優先執行的是？",
        "options": [
            "(A) 立即更換所有硬體",
            "(B) 盤點現有系統中使用的加密演算法與金鑰長度 (Crypto-agility Assessment)",
            "(C) 等待量子電腦普及再說",
            "(D) 自行發明演算法"
        ],
        "answer": "B",
        "note": "了解自身的加密資產現況 (Crypto Inventory) 是遷移至 PQC 的第一步。"
    },
    {
        "id": "B14-Prot-07",
        "question": "「同態加密 (Homomorphic Encryption)」的主要應用場景為何？",
        "options": [
            "(A) 加速傳輸",
            "(B) 允許在加密數據上直接進行運算與分析，保護資料隱私 (如醫療數據分析)",
            "(C) 防止 DDoS",
            "(D) 壓縮影片"
        ],
        "answer": "B",
        "note": "同態加密解決了「資料在使用中 (Data in Use)」的隱私保護問題。"
    },
    {
        "id": "B14-Prot-08",
        "question": "關於「多方安全計算 (Secure Multi-Party Computation, SMPC)」的特性，下列何者正確？",
        "options": [
            "(A) 需要第三方可信機構",
            "(B) 允許多個參與者在不洩露各自私有數據的前提下，共同計算出一個結果",
            "(C) 資料必須集中儲存",
            "(D) 完全不加密"
        ],
        "answer": "B",
        "note": "SMPC 是隱私計算的重要技術，實現了「數據可用不可見」。"
    },
    {
        "id": "B14-Prot-09",
        "question": "在區塊鏈應用中，「智能合約 (Smart Contract)」最常見的安全漏洞是？",
        "options": [
            "(A) SQL Injection",
            "(B) 重入攻擊 (Reentrancy) 與整數溢位 (Integer Overflow)",
            "(C) XSS",
            "(D) CSRF"
        ],
        "answer": "B",
        "note": "智能合約一旦部署即難以修改，邏輯漏洞會造成永久性資產損失。"
    },
    {
        "id": "B14-Prot-10",
        "question": "關於 AI 對抗式攻擊中的「Evasion Attack (逃逸攻擊)」，其手法是？",
        "options": [
            "(A) 竊取模型參數",
            "(B) 在輸入數據中加入微小擾動 (Perturbation)，使 AI 模型在推論階段做出錯誤判斷",
            "(C) 破壞訓練資料",
            "(D) 關閉 AI 伺服器"
        ],
        "answer": "B",
        "note": "例如在交通號誌圖片上貼貼紙，讓自駕車 AI 誤判為其他標誌。"
    },
    // --- 雲端與容器安全 (實務) ---
    {
        "id": "B14-Prot-11",
        "question": "在 Kubernetes 中，使用 `NetworkPolicy` 實施「預設拒絕 (Default Deny)」的最佳實務是？",
        "options": [
            "(A) 不做任何設定",
            "(B) 建立一個選取所有 Pod 且不包含任何 Ingress/Egress 規則的 NetworkPolicy",
            "(C) 關閉網路介面",
            "(D) 移除 CNI 插件"
        ],
        "answer": "B",
        "note": "這是實施微分割的起點，確保只有明確允許的流量才能通過。"
    },
    {
        "id": "B14-Prot-12",
        "question": "關於容器映像檔的「最小化 (Minimization)」，使用 `Distroless` 或 `Alpine` 映像檔的主要資安效益是？",
        "options": [
            "(A) 節省硬碟空間",
            "(B) 減少攻擊面 (Attack Surface)，因為移除了不必要的 Shell 和工具",
            "(C) 加速編譯",
            "(D) 支援更多功能"
        ],
        "answer": "B",
        "note": "攻擊者即便入侵容器，若無 Shell 或工具可用，也難以進行後續攻擊。"
    },
    {
        "id": "B14-Prot-13",
        "question": "在 AWS 中，若發現 EC2 實例被入侵，進行鑑識的第一步通常是？",
        "options": [
            "(A) 立即終止 (Terminate) 實例",
            "(B) 建立實例的快照 (Snapshot) 以保全證據，並隔離該實例 (Security Group)",
            "(C) 登入該實例查看日誌",
            "(D) 重啟實例"
        ],
        "answer": "B",
        "note": "直接終止會導致記憶體與暫存資料遺失，應先快照保全。"
    },
    {
        "id": "B14-Prot-14",
        "question": "關於 IaC (Infrastructure as Code) 安全掃描工具 (如 Checkov, tfsec)，其主要偵測對象是？",
        "options": [
            "(A) 應用程式原始碼漏洞",
            "(B) 雲端資源的組態設定 (如 S3 公開、未加密、安全群組過寬)",
            "(C) 網路流量",
            "(D) 使用者密碼"
        ],
        "answer": "B",
        "note": "IaC 掃描能在部署前發現基礎設施的配置錯誤 (Misconfiguration)。"
    },
    {
        "id": "B14-Prot-15",
        "question": "CASB (Cloud Access Security Broker) 的核心功能不包含？",
        "options": [
            "(A) 發現影子 IT (Shadow IT)",
            "(B) 資料外洩防護 (DLP)",
            "(C) 修補作業系統漏洞",
            "(D) 合規性檢查"
        ],
        "answer": "C",
        "note": "修補 OS 漏洞是 CWPP 或系統管理工具的職責，CASB 專注於雲端服務的存取與資料安全。"
    },
    // --- 攻防技術 (進階) ---
    {
        "id": "B14-Prot-16",
        "question": "攻擊者利用 `LLMNR/NBT-NS Poisoning` 攻擊，其主要目的是？",
        "options": [
            "(A) 癱瘓網路",
            "(B) 在區域網路中回應名稱解析請求，竊取使用者的 NTLM Hash",
            "(C) 注入惡意代碼",
            "(D) 刪除檔案"
        ],
        "answer": "B",
        "note": "這是內網滲透中獲取憑證的經典手法，應透過 GPO 停用 LLMNR/NBT-NS。"
    },
    {
        "id": "B14-Prot-17",
        "question": "關於「ASLR (Address Space Layout Randomization)」與「DEP (Data Execution Prevention)」的關係？",
        "options": [
            "(A) 兩者功能相同",
            "(B) DEP 防止在資料區段執行代碼，ASLR 防止攻擊者預測記憶體位址，兩者互補",
            "(C) ASLR 取代了 DEP",
            "(D) DEP 取代了 ASLR"
        ],
        "answer": "B",
        "note": "現代作業系統同時啟用這兩項機制來防禦記憶體破壞漏洞 (Memory Corruption)。"
    },
    {
        "id": "B14-Prot-18",
        "question": "在 Web 安全中，`SameSite` Cookie 屬性的 `Lax` 模式與 `Strict` 模式的主要差異？",
        "options": [
            "(A) Lax 允許部分頂層導航 (Top-level Navigation) 攜帶 Cookie，平衡了安全性與使用者體驗",
            "(B) Strict 允許所有跨站請求",
            "(C) Lax 不安全",
            "(D) Strict 只能在 HTTP 使用"
        ],
        "answer": "A",
        "note": "Lax 是現代瀏覽器的預設值，能防禦大部分 CSRF，同時不影響正常連結跳轉。"
    },
    {
        "id": "B14-Prot-19",
        "question": "關於「Subdomain Takeover (子網域接管)」漏洞，其成因通常是？",
        "options": [
            "(A) DNS 設定指向了一個已經停用或刪除的雲端服務 (Dangling DNS record)",
            "(B) 網域過期",
            "(C) 密碼外洩",
            "(D) 伺服器被駭"
        ],
        "answer": "A",
        "note": "攻擊者可註冊該雲端資源，進而控制該子網域的內容與流量。"
    },
    {
        "id": "B14-Prot-20",
        "question": "在紅隊演練中，「Domain Fronting (網域前置)」技術主要用於？",
        "options": [
            "(A) 隱藏 C2 (Command and Control) 通訊，使其看起來像是與合法 CDN 或大廠網域連線",
            "(B) 加速攻擊",
            "(C) 破解密碼",
            "(D) 掃描漏洞"
        ],
        "answer": "A",
        "note": "利用 CDN 的特性，DNS 查詢合法網域，但 HTTP Host Header 指向惡意 C2。"
    },
    // --- 系統鑑識 ---
    {
        "id": "B14-Prot-21",
        "question": "在 Windows 鑑識中，`SRUM (System Resource Usage Monitor)` 資料庫可提供什麼資訊？",
        "options": [
            "(A) 瀏覽器歷史",
            "(B) 過去 30-60 天的應用程式執行紀錄、網路流量與電量消耗",
            "(C) 刪除的檔案",
            "(D) 登錄檔修改紀錄"
        ],
        "answer": "B",
        "note": "SRUM 是追溯歷史執行行為與網路活動的重要跡證。"
    },
    {
        "id": "B14-Prot-22",
        "question": "關於 Linux 的 `auditd` 系統，其主要功能是？",
        "options": [
            "(A) 掃描病毒",
            "(B) 核心層級的審計系統，可記錄詳細的系統呼叫 (Syscall)、檔案存取與執行紀錄",
            "(C) 備份檔案",
            "(D) 防火牆"
        ],
        "answer": "B",
        "note": "auditd 提供了比一般日誌更底層且難以被繞過的監控能力。"
    },
    {
        "id": "B14-Prot-23",
        "question": "攻擊者使用 `Timestomping` 技術，其目的是？",
        "options": [
            "(A) 加速系統時間",
            "(B) 修改檔案的時間戳記 ($MACE attributes)，以混淆鑑識時間軸 (Timeline)",
            "(C) 刪除檔案",
            "(D) 隱藏檔案內容"
        ],
        "answer": "B",
        "note": "鑑識人員需透過 $Standard_Information 與 $File_Name 屬性的時間差異來偵測。"
    },
    {
        "id": "B14-Prot-24",
        "question": "在記憶體鑑識中，`Process Hollowing` 是一種什麼樣的攻擊技術？",
        "options": [
            "(A) 刪除進程",
            "(B) 啟動一個合法進程 (如 svchost.exe) 並處於暫停狀態，然後替換其記憶體內容為惡意代碼",
            "(C) 隱藏進程 ID",
            "(D) 增加進程優先級"
        ],
        "answer": "B",
        "note": "這讓惡意程式在工作管理員中看起來像合法的系統程式。"
    },
    {
        "id": "B14-Prot-25",
        "question": "關於 `Prefetch` 檔案在 SSD (固態硬碟) 環境下的行為，下列何者正確？",
        "options": [
            "(A) 完全不產生",
            "(B) 預設可能被停用或行為改變 (視 Windows 版本與 SuperFetch 設定而定)，鑑識時需確認",
            "(C) 產生更多檔案",
            "(D) 與 HDD 完全相同"
        ],
        "answer": "B",
        "note": "鑑識人員需了解作業系統在不同硬體環境下的行為差異。"
    },
    // --- 綜合防護 ---
    {
        "id": "B14-Prot-26",
        "question": "在郵件安全中，`DMARC` 的 `p=reject` 政策代表？",
        "options": [
            "(A) 拒絕所有郵件",
            "(B) 若郵件未通過 SPF 或 DKIM 驗證，收件端應直接拒絕接收 (Reject)",
            "(C) 將郵件放入垃圾桶 (Quarantine)",
            "(D) 不做任何動作 (None)"
        ],
        "answer": "B",
        "note": "這是 DMARC 最嚴格的政策，能有效防止網域被偽冒。"
    },
    {
        "id": "B14-Prot-27",
        "question": "關於「DevSecOps」中的「SAST (Static Application Security Testing)」，其最佳執行時機是？",
        "options": [
            "(A) 系統上線後",
            "(B) 開發階段 (Coding) 或建置階段 (Build)，越早越好 (Shift Left)",
            "(C) 發生資安事件後",
            "(D) 廢棄系統時"
        ],
        "answer": "B",
        "note": "SAST 分析原始碼，不需要執行程式，適合在開發早期發現漏洞。"
    },
    {
        "id": "B14-Prot-28",
        "question": "在無線網路中，WPA3 的「OWE (Opportunistic Wireless Encryption)」主要解決了什麼問題？",
        "options": [
            "(A) 速度問題",
            "(B) 開放式網路 (Open Wi-Fi) 的傳輸加密問題，讓免密碼連線也能享有加密保護",
            "(C) 認證問題",
            "(D) 漫遊問題"
        ],
        "answer": "B",
        "note": "OWE 提供了無認證的加密通道，防止被動監聽。"
    },
    {
        "id": "B14-Prot-29",
        "question": "關於「Certificate Transparency (憑證透明度)」日誌，其主要用途是？",
        "options": [
            "(A) 公開私鑰",
            "(B) 讓網域擁有者能監控是否有 CA 誤發或濫發其網域的憑證",
            "(C) 加速憑證申請",
            "(D) 備份憑證"
        ],
        "answer": "B",
        "note": "CT Logs 公開透明，有助於及早發現惡意或錯誤簽發的憑證。"
    },
    {
        "id": "B14-Prot-30",
        "question": "在 Web 安全中，`HSTS (HTTP Strict Transport Security)` 的 `preload` 清單是指？",
        "options": [
            "(A) 預先載入圖片",
            "(B) 瀏覽器內建的 HSTS 網域清單，確保即使是第一次造訪也能強制使用 HTTPS",
            "(C) 預先載入惡意網站",
            "(D) 預先載入 Cookie"
        ],
        "answer": "B",
        "note": "解決了 HSTS 首次造訪 (Trust on First Use) 的安全空窗期。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch14 = [
    // --- 資安治理與策略 (進階) ---
    {
        "id": "B14-Plan-01",
        "question": "在資安治理中，「風險胃納 (Risk Appetite)」與「風險容忍度 (Risk Tolerance)」的設定權責在於？",
        "options": [
            "(A) IT 經理",
            "(B) 最高管理階層 / 董事會",
            "(C) 外部稽核員",
            "(D) 一般員工"
        ],
        "answer": "B",
        "note": "這是組織層級的戰略決策，必須由高層定調。"
    },
    {
        "id": "B14-Plan-02",
        "question": "關於「資安長 (CISO)」的報告路線 (Reporting Line)，最佳實務建議是？",
        "options": [
            "(A) 報告給 CIO (可能產生利益衝突)",
            "(B) 直接報告給 CEO 或董事會，以確保獨立性與高層支持",
            "(C) 報告給 HR",
            "(D) 報告給總務"
        ],
        "answer": "B",
        "note": "CISO 需具備獨立性，避免資安決策受制於 IT 維運壓力。"
    },
    {
        "id": "B14-Plan-03",
        "question": "在制定資安策略時，應優先考量？",
        "options": [
            "(A) 最新技術",
            "(B) 業務目標 (Business Alignment)",
            "(C) 競爭對手的作法",
            "(D) 預算多寡"
        ],
        "answer": "B",
        "note": "資安的目的是支持業務，策略必須與業務目標一致 (Alignment)。"
    },
    {
        "id": "B14-Plan-04",
        "question": "關於「資安文化 (Security Culture)」的建立，下列何者最關鍵？",
        "options": [
            "(A) 嚴厲的懲罰",
            "(B) 管理層的以身作則 (Tone from the Top) 與持續的溝通教育",
            "(C) 購買昂貴工具",
            "(D) 制定複雜的政策"
        ],
        "answer": "B",
        "note": "高層的支持與示範是塑造組織文化的關鍵力量。"
    },
    {
        "id": "B14-Plan-05",
        "question": "在 ESG (環境、社會與治理) 指標中，資安通常歸類於哪一個面向？",
        "options": [
            "(A) E (環境)",
            "(B) S (社會) 或 G (治理)",
            "(C) 都不屬於",
            "(D) 只屬於 IT"
        ],
        "answer": "B",
        "note": "資安涉及隱私保護 (S) 與風險管理 (G)，是 ESG 的重要評估項目。"
    },
    // --- 風險管理 (進階) ---
    {
        "id": "B14-Plan-06",
        "question": "關於「供應鏈風險管理 (SCRM)」，除了簽約要求外，還應建立？",
        "options": [
            "(A) 持續監控機制 (如定期稽核、評分卡)",
            "(B) 信任關係",
            "(C) 送禮文化",
            "(D) 口頭承諾"
        ],
        "answer": "A",
        "note": "供應商的資安狀態是動態的，需持續監控與評估。"
    },
    {
        "id": "B14-Plan-07",
        "question": "在風險評鑑中，對於「新興科技 (如 AI, Quantum)」帶來的風險，應採取？",
        "options": [
            "(A) 忽略",
            "(B) 納入定期風險評鑑範圍，並進行情境分析 (Scenario Analysis)",
            "(C) 禁止使用",
            "(D) 等發生事故再說"
        ],
        "answer": "B",
        "note": "風險評鑑需具備前瞻性，識別新興威脅對組織的潛在衝擊。"
    },
    {
        "id": "B14-Plan-08",
        "question": "關於「量化風險分析」中的 SLE (Single Loss Expectancy)，其計算公式為？",
        "options": [
            "(A) 資產價值 x 暴露因子 (Exposure Factor)",
            "(B) ALE x ARO",
            "(C) 風險 x 機率",
            "(D) 成本 x 效益"
        ],
        "answer": "A",
        "note": "SLE 代表單次事件造成的預期損失金額。"
    },
    {
        "id": "B14-Plan-09",
        "question": "在處理「殘餘風險 (Residual Risk)」時，若風險仍高於胃納，且無法進一步降低，組織應？",
        "options": [
            "(A) 假裝沒看到",
            "(B) 由高層簽署風險接受 (Risk Acceptance)，或選擇避免風險 (停止業務)",
            "(C) 責怪資安人員",
            "(D) 修改風險胃納"
        ],
        "answer": "B",
        "note": "風險接受必須是高層知情且同意的決策 (Sign-off)。"
    },
    {
        "id": "B14-Plan-10",
        "question": "關於 KRI (關鍵風險指標) 的設定，應具備什麼特性？",
        "options": [
            "(A) 越多越好",
            "(B) 具備預警能力 (Predictive) 且與關鍵風險相關",
            "(C) 只看過去",
            "(D) 難以量測"
        ],
        "answer": "B",
        "note": "KRI 應能在風險發生前提供預警，以便及時採取行動。"
    },
    // --- 營運持續與應變 (進階) ---
    {
        "id": "B14-Plan-11",
        "question": "在 BCP 中，關於「危機溝通 (Crisis Communication)」的原則，下列何者錯誤？",
        "options": [
            "(A) 指定單一發言人",
            "(B) 資訊透明且及時",
            "(C) 盡量隱瞞事實以維護股價",
            "(D) 照顧利害關係人感受"
        ],
        "answer": "C",
        "note": "隱瞞事實往往會造成更大的信任危機與聲譽損害。"
    },
    {
        "id": "B14-Plan-12",
        "question": "關於「資安保險」的理賠範圍，通常不包含？",
        "options": [
            "(A) 營業中斷損失",
            "(B) 鑑識與法律費用",
            "(C) 因資安事件導致的硬體升級費用 (Betterment)",
            "(D) 勒索贖金 (視保單而定)"
        ],
        "answer": "C",
        "note": "保險通常只賠償損失回復原狀，不賠償設備升級或改善 (Betterment) 的費用。"
    },
    {
        "id": "B14-Plan-13",
        "question": "在應變計畫中，「Playbook (劇本)」的作用是？",
        "options": [
            "(A) 演戲用",
            "(B) 針對特定類型的資安事件 (如勒索軟體、DDoS)，提供標準化的處置步驟指引",
            "(C) 記錄會議紀錄",
            "(D) 規劃預算"
        ],
        "answer": "B",
        "note": "Playbook 確保應變團隊在壓力下能依循標準程序，減少失誤。"
    },
    {
        "id": "B14-Plan-14",
        "question": "關於「數位韌性 (Digital Resilience)」的目標，不只是恢復，還包括？",
        "options": [
            "(A) 報復攻擊者",
            "(B) 適應 (Adapt) 與 轉型 (Transform)，從事件中學習並變得更強",
            "(C) 增加預算",
            "(D) 購買更多保險"
        ],
        "answer": "B",
        "note": "韌性強調動態適應與演進，而非僅是回復原狀 (Bounce back vs Bounce forward)。"
    },
    {
        "id": "B14-Plan-15",
        "question": "在資安演練中，紅藍對抗 (Red/Blue Teaming) 的「紫隊 (Purple Team)」角色是？",
        "options": [
            "(A) 裁判",
            "(B) 促進紅藍雙方溝通與協作，確保攻防演練能轉化為實際的防禦能力提升",
            "(C) 觀眾",
            "(D) 後勤補給"
        ],
        "answer": "B",
        "note": "紫隊的目標是最大化演練效益，消除資訊不對稱。"
    },
    // --- 法規與合規 (特定領域) ---
    {
        "id": "B14-Plan-16",
        "question": "關於歐盟「DORA (數位營運韌性法案)」的規範對象，主要是？",
        "options": [
            "(A) 醫療業",
            "(B) 金融業及其 ICT 供應商",
            "(C) 製造業",
            "(D) 教育業"
        ],
        "answer": "B",
        "note": "DORA 強化了金融體系的數位韌性，並將監管延伸至關鍵 ICT 第三方服務商。"
    },
    {
        "id": "B14-Plan-17",
        "question": "在 GDPR 中，發生重大個資外洩時，通報主管機關的時限是？",
        "options": [
            "(A) 24 小時",
            "(B) 72 小時",
            "(C) 7 天",
            "(D) 1 個月"
        ],
        "answer": "B",
        "note": "72 小時是 GDPR 的黃金通報時間。"
    },
    {
        "id": "B14-Plan-18",
        "question": "關於 PCI DSS (支付卡產業資料安全標準)，其主要保護的資料是？",
        "options": [
            "(A) 持卡人資料 (CHD) 與 敏感驗證資料 (SAD)",
            "(B) 員工個資",
            "(C) 公司財報",
            "(D) 供應商名單"
        ],
        "answer": "A",
        "note": "PCI DSS 嚴格規範信用卡號 (PAN)、磁條資料、CVV 等資料的儲存與傳輸。"
    },
    {
        "id": "B14-Plan-19",
        "question": "台灣《資通安全管理法》對於「危害國家資通安全產品」的規範是？",
        "options": [
            "(A) 鼓勵使用",
            "(B) 公務機關原則禁止使用，例外經核准方可使用",
            "(C) 沒限制",
            "(D) 只能在內網使用"
        ],
        "answer": "B",
        "note": "這是降低國家級供應鏈風險的重要管控措施。"
    },
    {
        "id": "B14-Plan-20",
        "question": "在 ISO 27001 中，關於「持續改善」的要求，主要透過？",
        "options": [
            "(A) 買新設備",
            "(B) 矯正措施、內部稽核、管理審查與績效評估",
            "(C) 換新員工",
            "(D) 增加預算"
        ],
        "answer": "B",
        "note": "PDCA 循環的 Act 與 Check 階段驅動了持續改善。"
    },
    // --- 實務管理情境 ---
    {
        "id": "B14-Plan-21",
        "question": "公司欲導入 AI 輔助程式開發 (如 Copilot)，資安部門首要的考量是？",
        "options": [
            "(A) 提升效率",
            "(B) 程式碼智慧財產權外洩風險與產出程式碼的安全性 (是否包含漏洞)",
            "(C) 降低成本",
            "(D) 開發者體驗"
        ],
        "answer": "B",
        "note": "需評估 AI 工具的隱私政策，並加強對產出程式碼的 SAST 掃描。"
    },
    {
        "id": "B14-Plan-22",
        "question": "面對員工私下使用雲端儲存服務 (Shadow IT)，資安管理的最佳策略？",
        "options": [
            "(A) 全面封鎖網路",
            "(B) 了解需求，提供合規的企業級替代方案 (如企業版雲端硬碟)，並透過 CASB 監控",
            "(C) 視而不見",
            "(D) 開除員工"
        ],
        "answer": "B",
        "note": "疏導優於圍堵，提供安全且好用的工具才能解決 Shadow IT 問題。"
    },
    {
        "id": "B14-Plan-23",
        "question": "在遠端工作環境下，對於員工家中 Wi-Fi 安全的不可控性，企業應？",
        "options": [
            "(A) 強制員工升級家中路由器",
            "(B) 實施 Always-on VPN 或 ZTNA，並強化端點防護 (EDR)，不信任底層網路",
            "(C) 禁止在家工作",
            "(D) 忽略風險"
        ],
        "answer": "B",
        "note": "零信任原則：假設網路是不安全的，防護應集中在端點與連線加密。"
    },
    {
        "id": "B14-Plan-24",
        "question": "關於「資產報廢」的資安處置，硬碟銷毀的最佳證明是？",
        "options": [
            "(A) 員工口頭保證",
            "(B) 銷毀過程的錄影、銷毀證明書 (CoD) 與資產清冊核銷紀錄",
            "(C) 丟到垃圾桶的照片",
            "(D) 格式化截圖"
        ],
        "answer": "B",
        "note": "證據保全是稽核的重點，銷毀證明需具備可追溯性。"
    },
    {
        "id": "B14-Plan-25",
        "question": "在委外開發合約中，關於「原始碼所有權」的約定，對資安的影響？",
        "options": [
            "(A) 沒影響",
            "(B) 擁有原始碼所有權才能進行獨立的資安檢測與修補，避免廠商綁架 (Vendor Lock-in)",
            "(C) 為了省錢",
            "(D) 為了轉賣"
        ],
        "answer": "B",
        "note": "若無原始碼，後續的弱點修補與維護將受制於廠商。"
    },
    {
        "id": "B14-Plan-26",
        "question": "關於「機敏資料傳輸」，下列何者符合最佳實務？",
        "options": [
            "(A) 使用一般 Email 附件",
            "(B) 使用加密的檔案傳輸服務 (SFTP, HTTPS)，並對檔案本身加密 (如 PGP, AES)",
            "(C) 使用 Line 傳送",
            "(D) 存到 USB 寄送"
        ],
        "answer": "B",
        "note": "傳輸通道加密 + 檔案內容加密 (端對端加密) 提供雙重保障。"
    },
    {
        "id": "B14-Plan-27",
        "question": "在社交工程演練中，發現某部門重複點擊率高，應採取的管理措施？",
        "options": [
            "(A) 扣績效",
            "(B) 針對該部門進行客製化的加強培訓，並了解其業務流程是否容易受騙",
            "(C) 公布名單羞辱",
            "(D) 拔除網路線"
        ],
        "answer": "B",
        "note": "針對高風險群體進行重點輔導，並優化流程 (如增加驗證步驟)。"
    },
    {
        "id": "B14-Plan-28",
        "question": "關於「特權帳號 (PAM)」的管理，下列何者是必要措施？",
        "options": [
            "(A) 密碼永不過期",
            "(B) 密碼保險箱 (Vault)、連線側錄、定期輪換密碼、MFA",
            "(C) 寫在筆記本上",
            "(D) 多人共用"
        ],
        "answer": "B",
        "note": "PAM 系統能有效管控與稽核高權限帳號的使用。"
    },
    {
        "id": "B14-Plan-29",
        "question": "在資安預算編列時，應優先投資於？",
        "options": [
            "(A) 最貴的硬體",
            "(B) 風險評鑑識別出的高風險項目與關鍵資產保護",
            "(C) 裝潢機房",
            "(D) 購買贈品"
        ],
        "answer": "B",
        "note": "資源分配應基於風險 (Risk-based)，確保投資效益最大化。"
    },
    {
        "id": "B14-Plan-30",
        "question": "關於「開源情資 (OSINT)」在資安管理中的應用，主要價值為？",
        "options": [
            "(A) 偷窺員工隱私",
            "(B) 了解組織在外部的暴露面 (Attack Surface)，如洩漏的憑證、未公開的服務",
            "(C) 增加網路流量",
            "(D) 備份資料"
        ],
        "answer": "B",
        "note": "OSINT 協助組織以駭客視角檢視自身曝險狀況。"
    }
];

// 將 Batch 14 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch14);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch14);
}
// ==========================================
// 2025 資安工程師模擬題庫 - 第十五批次 (Batch 15)
// 包含：防護實務 30 題 + 規劃實務 30 題
// 特色：包含「複選題」(Multiple Choice)，強化綜合判斷能力
// 重點：API 安全、容器調度、威脅情資標準、資安治理細節
// ==========================================

// 請將以下內容合併至原本的 protectionQuestions 陣列中
const protectionQuestions_Batch15 = [
    // --- API 與 Web 安全 (複選題) ---
    {
        "id": "B15-Prot-01",
        "question": "在 OWASP API Security Top 10 中，關於「Mass Assignment (大量賦值)」漏洞的描述與防護，下列哪些正確？(複選)",
        "options": [
            "(A) 攻擊者透過在請求中加入額外參數(如 `role=admin`)，試圖修改後端物件中不應被修改的屬性",
            "(B) 這是因為應用程式直接將客戶端輸入綁定到內部物件模型，且未做過濾",
            "(C) 防護方式是使用 `Data Transfer Objects (DTO)` 或明確定義允許輸入的白名單",
            "(D) 只要使用 HTTPS 就能完全防禦此攻擊"
        ],
        "answer": "ABC",
        "note": "Mass Assignment 利用了框架自動綁定參數的便利性；HTTPS 僅保護傳輸層，無法防禦應用層邏輯漏洞。"
    },
    {
        "id": "B15-Prot-02",
        "question": "關於 HTTP 安全標頭 (Security Headers) 的設定，下列哪些有助於防禦 XSS 或點擊劫持攻擊？(複選)",
        "options": [
            "(A) Content-Security-Policy (CSP)",
            "(B) X-Frame-Options",
            "(C) X-Content-Type-Options",
            "(D) Server"
        ],
        "answer": "ABC",
        "note": "CSP 限制資源載入防 XSS；X-Frame 防點擊劫持；X-Content-Type 防 MIME Sniffing；Server 標頭通常建議隱藏以免洩漏版本。"
    },
    {
        "id": "B15-Prot-03",
        "question": "針對 GraphQL API 的攻擊面，下列哪些是常見的資安風險？(複選)",
        "options": [
            "(A) 深度遞迴查詢導致的阻斷服務 (DoS)",
            "(B) 內省查詢 (Introspection) 洩漏完整的 Schema 資訊",
            "(C) 批量查詢 (Batching) 用於暴力破解或規避速率限制",
            "(D) SQL Injection"
        ],
        "answer": "ABCD",
        "note": "GraphQL 的彈性也帶來了特定的風險，需針對 Query Depth/Complexity 進行限制，並評估是否關閉 Introspection。"
    },
    {
        "id": "B15-Prot-04",
        "question": "在 JSON Web Token (JWT) 的使用安全上，下列哪些是必須檢查的項目？(複選)",
        "options": [
            "(A) 驗證簽章 (Signature) 是否有效",
            "(B) 檢查 `exp` (Expiration Time) 是否過期",
            "(C) 確認 `alg` (Algorithm) 標頭不是 'None'",
            "(D) 確保 Payload 中不包含敏感個資 (因 Base64 僅編碼非加密)"
        ],
        "answer": "ABCD",
        "note": "JWT 的安全性完全依賴於正確的驗證實作與 Payload 管理。"
    },
    // --- 雲端與容器安全 (複選題) ---
    {
        "id": "B15-Prot-05",
        "question": "Kubernetes (K8s) 的 `Pod Security Standards` 定義了不同層級的安全性。關於「Restricted」層級的要求，下列哪些正確？(複選)",
        "options": [
            "(A) 禁止容器以 Root 使用者身分執行 (Must run as non-root)",
            "(B) 禁止容器提升權限 (AllowPrivilegeEscalation=false)",
            "(C) 限制 Volume 的類型 (如禁止掛載 hostPath)",
            "(D) 允許容器使用主機網路 (HostNetwork=true)"
        ],
        "answer": "ABC",
        "note": "Restricted 層級旨在提供最強的隔離性；允許 HostNetwork 會破壞隔離，屬於 Privileged 行為。"
    },
    {
        "id": "B15-Prot-06",
        "question": "在雲端環境中，關於「IAM (Identity and Access Management)」的最佳實務，下列哪些正確？(複選)",
        "options": [
            "(A) 為每個 IAM User 啟用 MFA",
            "(B) 避免使用 Root 帳號進行日常操作",
            "(C) 定期輪換 Access Keys",
            "(D) 賦予所有開發者 AdministratorAccess 權限以方便做事"
        ],
        "answer": "ABC",
        "note": "D 選項違反最小權限原則 (Least Privilege)。"
    },
    {
        "id": "B15-Prot-07",
        "question": "關於 Docker 容器的網路模式，下列敘述哪些正確？(複選)",
        "options": [
            "(A) `bridge` 模式是預設模式，容器位於獨立網段，需透過 Port Mapping 對外",
            "(B) `host` 模式下，容器與宿主機共用網路堆疊，效能較好但隔離性差",
            "(C) `none` 模式下，容器沒有網路介面，最安全但無法連網",
            "(D) `container` 模式允許容器共享另一個容器的網路命名空間"
        ],
        "answer": "ABCD",
        "note": "了解不同網路模式的隔離性差異是容器資安的基礎。"
    },
    // --- 威脅情資與鑑識 (複選題) ---
    {
        "id": "B15-Prot-08",
        "question": "STIX 2.1 (Structured Threat Information Expression) 標準中，定義了多種物件。下列哪些屬於 SDO (Domain Objects)？(複選)",
        "options": [
            "(A) Indicator (指標)",
            "(B) Malware (惡意軟體)",
            "(C) Threat Actor (威脅行動者)",
            "(D) Attack Pattern (攻擊模式)"
        ],
        "answer": "ABCD",
        "note": "STIX 2.1 定義了 SDO (領域物件) 來描述威脅內容，以及 SRO (關係物件) 來描述物件間的關聯。"
    },
    {
        "id": "B15-Prot-09",
        "question": "在進行數位鑑識時，關於「揮發性資料 (Volatile Data)」的收集順序，下列哪些應優於硬碟映像檔的製作？(複選)",
        "options": [
            "(A) 記憶體 (RAM) 內容",
            "(B) 網路連線狀態 (Network Connections)",
            "(C) 執行中的程序 (Running Processes)",
            "(D) 系統已封存的日誌檔"
        ],
        "answer": "ABC",
        "note": "依據 RFC 3227，應先收集最易消失的資料。已封存日誌在硬碟中，揮發性較低。"
    },
    {
        "id": "B15-Prot-10",
        "question": "關於「網路流量分析 (Network Traffic Analysis)」，下列哪些特徵可能暗示內部主機遭受 C2 (Command & Control) 控制？(複選)",
        "options": [
            "(A) 規律的 Beaconing (信標) 行為",
            "(B) 連線至已知的惡意 IP 或網域",
            "(C) 在非上班時間出現異常的大量資料上傳",
            "(D) DNS 查詢請求異常過長 (可能為 DNS Tunneling)"
        ],
        "answer": "ABCD",
        "note": "這些都是典型的受駭指標 (IoC)。"
    },
    // --- 網路防護技術 (單選/複選混合) ---
    {
        "id": "B15-Prot-11",
        "question": "在電子郵件安全協定中，STARTTLS 的主要功能為何？(單選)",
        "options": [
            "(A) 加密郵件內容",
            "(B) 驗證寄件者身分",
            "(C) 允許將原本明文的連線 (如 SMTP) 升級為加密連線 (TLS)，而無需使用不同的連接埠",
            "(D) 阻擋垃圾郵件"
        ],
        "answer": "C",
        "note": "STARTTLS 是一種機會性加密，讓明文協定能升級加密，但若設定不當可能遭受降級攻擊。"
    },
    {
        "id": "B15-Prot-12",
        "question": "關於 VPN 的 Split Tunneling (分割通道) 設定，下列敘述何者正確？(單選)",
        "options": [
            "(A) 最安全，所有流量都回傳公司",
            "(B) 僅將存取公司內網的流量透過 VPN 傳輸，其餘上網流量直接走本地網路，可節省頻寬但可能有安全破口",
            "(C) 是一種加密技術",
            "(D) 必須使用硬體權杖"
        ],
        "answer": "B",
        "note": "Split Tunneling 雖提升效率，但若端點遭入侵，可能成為跳板攻擊內網，需搭配端點防護。"
    },
    {
        "id": "B15-Prot-13",
        "question": "在 Wi-Fi 企業級認證 (WPA2/WPA3-Enterprise) 中，通常涉及哪三個角色？(複選)",
        "options": [
            "(A) Supplicant (用戶端裝置)",
            "(B) Authenticator (無線基地台/交換器)",
            "(C) Authentication Server (如 RADIUS 伺服器)",
            "(D) CA Server"
        ],
        "answer": "ABC",
        "note": "這是 802.1X 的標準架構。CA Server 雖常用於憑證，但非架構角色名稱。"
    },
    {
        "id": "B15-Prot-14",
        "question": "關於 IPv6 的位址類型，下列配對哪些正確？(複選)",
        "options": [
            "(A) ::1 -> Loopback Address (類似 127.0.0.1)",
            "(B) fe80::/10 -> Link-Local Address (類似 169.254.x.x)",
            "(C) fc00::/7 -> Unique Local Address (類似私有 IP)",
            "(D) ff00::/8 -> Multicast Address"
        ],
        "answer": "ABCD",
        "note": "熟悉 IPv6 位址類型對於設定防火牆與分析流量至關重要。"
    },
    {
        "id": "B15-Prot-15",
        "question": "下列哪些是針對 DNS 服務的常見攻擊手法？(複選)",
        "options": [
            "(A) DNS Cache Poisoning (快取汙染)",
            "(B) DNS Amplification DDoS (放大攻擊)",
            "(C) DNS Domain Hijacking (網域劫持)",
            "(D) DNS Tunneling (穿透/隧道)"
        ],
        "answer": "ABCD",
        "note": "DNS 是網路基礎設施的關鍵，面臨多種層面的威脅。"
    },
    // --- 攻防實務 (單選) ---
    {
        "id": "B15-Prot-16",
        "question": "攻擊者使用 `Hashcat` 工具並搭配 `-m 1000` 參數，通常是為了破解哪種雜湊？",
        "options": [
            "(A) MD5",
            "(B) NTLM (Windows 密碼雜湊)",
            "(C) SHA-256",
            "(D) bcrypt"
        ],
        "answer": "B",
        "note": "NTLM 是 Windows 環境中最常被竊取並嘗試破解的目標。"
    },
    {
        "id": "B15-Prot-17",
        "question": "在滲透測試中，利用 `Burp Suite` 的 `Repeater` 功能主要是為了？",
        "options": [
            "(A) 自動掃描漏洞",
            "(B) 手動修改並重送單一 HTTP 請求，以分析伺服器回應差異，測試邏輯漏洞",
            "(C) 暴力破解密碼",
            "(D) 攔截所有流量"
        ],
        "answer": "B",
        "note": "Repeater 是測試人員手動驗證漏洞（如 SQLi, XSS, 邏輯繞過）的核心工具。"
    },
    {
        "id": "B15-Prot-18",
        "question": "關於 `Metasploit` 的 `Meterpreter` Payload，其 `migrate` 指令的作用是？",
        "options": [
            "(A) 刪除自己",
            "(B) 將惡意程序注入並遷移到另一個穩定的系統進程 (如 explorer.exe) 中，以維持連線並隱藏蹤跡",
            "(C) 加密硬碟",
            "(D) 下載檔案"
        ],
        "answer": "B",
        "note": "遷移進程 (Process Migration) 是維持權限 (Persistence) 與隱匿的重要技巧。"
    },
    {
        "id": "B15-Prot-19",
        "question": "下列何者是偵測 `Pass-the-Hash` 攻擊的有效指標？",
        "options": [
            "(A) 密碼錯誤次數過多",
            "(B) 發現大量使用 NTLM 協定進行登入，且來源非正常工作站，或在非上班時間",
            "(C) 網路斷線",
            "(D) 硬碟空間不足"
        ],
        "answer": "B",
        "note": "PtH 使用雜湊值登入，不會產生密碼錯誤紀錄，需監控異常的 NTLM 驗證流量。"
    },
    {
        "id": "B15-Prot-20",
        "question": "在 Linux 提權攻擊中，攻擊者尋找 `SUID` 檔案的指令通常是？",
        "options": [
            "(A) find / -perm -4000 -type f 2>/dev/null",
            "(B) ls -la /root",
            "(C) ps -ef",
            "(D) cat /etc/passwd"
        ],
        "answer": "A",
        "note": "這是尋找具有 SetUID 權限檔案的標準指令，這類檔案若有漏洞可被利用提升至 root 權限。"
    },
    // --- 新興技術安全 ---
    {
        "id": "B15-Prot-21",
        "question": "關於 FIDO (Fast Identity Online) 的運作原理，下列敘述何者正確？",
        "options": [
            "(A) 生物特徵會傳送到伺服器比對",
            "(B) 伺服器保存使用者的私鑰",
            "(C) 生物特徵僅在本地裝置驗證，解鎖私鑰後，透過公鑰加密機制與伺服器進行簽章驗證",
            "(D) 仍然需要使用密碼"
        ],
        "answer": "C",
        "note": "FIDO 的核心價值在於生物特徵不離身，且消除共用密碼風險。"
    },
    {
        "id": "B15-Prot-22",
        "question": "在 5G 網路切片 (Network Slicing) 安全中，最重要的考量是？",
        "options": [
            "(A) 切片間的隔離性 (Isolation)，防止攻擊者從低安全切片跨越至高安全切片",
            "(B) 切片的速度",
            "(C) 切片的數量",
            "(D) 手機的品牌"
        ],
        "answer": "A",
        "note": "不同切片承載不同業務 (如自駕車 vs 上網)，隔離失效將導致嚴重後果。"
    },
    {
        "id": "B15-Prot-23",
        "question": "關於 AI 模型的「Model Inversion Attack (模型反轉攻擊)」，其目標是？",
        "options": [
            "(A) 讓模型判斷錯誤",
            "(B) 透過分析模型輸出，逆向推導出訓練資料中的敏感個資 (如人臉影像)",
            "(C) 刪除模型",
            "(D) 加密模型"
        ],
        "answer": "B",
        "note": "這是一種針對 AI 隱私的攻擊，試圖還原訓練數據。"
    },
    {
        "id": "B15-Prot-24",
        "question": "在 IoT 安全中，MQTT 協定的安全弱點通常在於？",
        "options": [
            "(A) 預設使用明文傳輸 (Port 1883)，需改用 MQTTS (Port 8883) 並啟用身分驗證",
            "(B) 傳輸速度太慢",
            "(C) 不支援無線",
            "(D) 只能單向傳輸"
        ],
        "answer": "A",
        "note": "許多 IoT 設備為了便利，預設未啟用 MQTTS 與帳號認證，導致資料外洩。"
    },
    {
        "id": "B15-Prot-25",
        "question": "關於「零信任架構」中的「信任評估」，應考量哪些動態因素？(複選)",
        "options": [
            "(A) 使用者身分與行為模式",
            "(B) 裝置的健康狀態與合規性",
            "(C) 存取的時間與地理位置",
            "(D) 資源的敏感度"
        ],
        "answer": "ABCD",
        "note": "零信任是動態的、持續的評估，綜合考量所有上下文 (Context)。"
    },
    {
        "id": "B15-Prot-26",
        "question": "下列哪些演算法被 NIST 選為後量子密碼學 (PQC) 的標準？(複選)",
        "options": [
            "(A) CRYSTALS-Kyber (用於公鑰加密/KEM)",
            "(B) CRYSTALS-Dilithium (用於數位簽章)",
            "(C) FALCON (用於數位簽章)",
            "(D) SPHINCS+ (用於數位簽章)"
        ],
        "answer": "ABCD",
        "note": "這些是能夠抵抗量子電腦攻擊的新一代演算法。"
    },
    {
        "id": "B15-Prot-27",
        "question": "在軟體供應鏈安全中，SLSA (Supply-chain Levels for Software Artifacts) 框架關注的是？",
        "options": [
            "(A) 軟體效能",
            "(B) 從源碼到構建 (Build) 過程的完整性，防止被竄改",
            "(C) 軟體售價",
            "(D) 使用者體驗"
        ],
        "answer": "B",
        "note": "SLSA 旨在確保軟體產出物 (Artifacts) 的來源可信且構建過程安全。"
    },
    {
        "id": "B15-Prot-28",
        "question": "關於 WPA3 的「Dragonfly Handshake (SAE)」，其抗攻擊特性為何？",
        "options": [
            "(A) 抗離線字典攻擊 (Offline Dictionary Attack)",
            "(B) 抗量子攻擊",
            "(C) 抗干擾",
            "(D) 抗水災"
        ],
        "answer": "A",
        "note": "SAE 協議確保即使密碼較弱，攻擊者也無法透過抓取握手包離線破解。"
    },
    {
        "id": "B15-Prot-29",
        "question": "在端點防護中，ASR (Attack Surface Reduction) 規則可以做到？(複選)",
        "options": [
            "(A) 阻擋 Office 應用程式建立子進程",
            "(B) 阻擋從電子郵件開啟可執行內容",
            "(C) 阻擋 JavaScript 或 VBScript 啟動下載執行",
            "(D) 阻擋 USB 寫入"
        ],
        "answer": "ABC",
        "note": "ASR 是 Windows Defender 的功能，能有效限縮常見的惡意軟體利用途徑。"
    },
    {
        "id": "B15-Prot-30",
        "question": "關於 EDR 的遙測數據 (Telemetry)，通常包含哪些資訊？(複選)",
        "options": [
            "(A) Process 建立與終止紀錄",
            "(B) 網路連線 (IP/Port)",
            "(C) 檔案讀寫與登錄檔修改",
            "(D) 使用者登入登出事件"
        ],
        "answer": "ABCD",
        "note": "完整的遙測數據是 EDR 進行行為分析與威脅獵捕的基礎。"
    }
];

// 請將以下內容合併至原本的 planningQuestions 陣列中
const planningQuestions_Batch15 = [
    // --- 資安治理與合規 (複選題) ---
    {
        "id": "B15-Plan-01",
        "question": "在 ISO 27001:2022 中，關於「管理審查 (Management Review)」的輸入項目，包含下列哪些？(複選)",
        "options": [
            "(A) 內部與外部議題的變更",
            "(B) 資訊安全績效的回饋 (如不符合事項、監控量測結果)",
            "(C) 利害關係人的回饋",
            "(D) 風險評鑑結果與風險處理計畫的狀態"
        ],
        "answer": "ABCD",
        "note": "管理審查是 ISMS PDCA 循環中「Check」的關鍵，需綜合考量各面向資訊以進行決策。"
    },
    {
        "id": "B15-Plan-02",
        "question": "依據《資通安全責任等級分級辦法》，A 級機關應辦理的資安事項包含哪些？(複選)",
        "options": [
            "(A) 每年辦理 2 次弱點掃描",
            "(B) 每年辦理 1 次滲透測試",
            "(C) 每年辦理 1 次資安健診",
            "(D) 每半年辦理 1 次社交工程演練"
        ],
        "answer": "ABCD",
        "note": "A 級機關要求最嚴格，需熟記各項檢測的頻率。"
    },
    {
        "id": "B15-Plan-03",
        "question": "在 GDPR 中，關於「資料保護影響評估 (DPIA)」的執行時機，下列哪些情況通常需要進行？(複選)",
        "options": [
            "(A) 系統性且廣泛地評估自然人的個人面向 (如自動化決策、Profiling)",
            "(B) 大規模處理特種個資 (如健康、生物特徵)",
            "(C) 對公開區域進行大規模監控 (如 CCTV)",
            "(D) 導入新科技且對權利自由有高風險時"
        ],
        "answer": "ABCD",
        "note": "DPIA 是高風險資料處理前的必要程序，體現 Privacy by Design。"
    },
    {
        "id": "B15-Plan-04",
        "question": "關於 NIST CSF 2.0 的「治理 (Govern)」功能，其類別 (Category) 包含哪些？(複選)",
        "options": [
            "(A) 組織情境 (Organizational Context)",
            "(B) 風險管理策略 (Risk Management Strategy)",
            "(C) 角色、責任與權限 (Roles, Responsibilities, and Authorities)",
            "(D) 政策 (Policy)"
        ],
        "answer": "ABCD",
        "note": "Govern 功能確保資安策略與組織整體的使命與風險胃納一致。"
    },
    {
        "id": "B15-Plan-05",
        "question": "關於「供應鏈資安風險管理」，企業應要求供應商提供或配合哪些事項？(複選)",
        "options": [
            "(A) 簽署保密協議 (NDA) 與資安協議",
            "(B) 提供軟體物料清單 (SBOM)",
            "(C) 接受定期的資安稽核 (Right to Audit)",
            "(D) 發生資安事件時的通報義務"
        ],
        "answer": "ABCD",
        "note": "透過合約與管理機制，將供應商納入企業的資安防護圈。"
    },
    // --- 風險管理與 BCM (複選題) ---
    {
        "id": "B15-Plan-06",
        "question": "在進行「營運衝擊分析 (BIA)」時，應評估哪些類型的衝擊？(複選)",
        "options": [
            "(A) 財務損失 (營收減少、罰款)",
            "(B) 營運衝擊 (服務中斷、生產停滯)",
            "(C) 聲譽損害 (客戶信任喪失)",
            "(D) 法律與合規影響 (違約、違法)"
        ],
        "answer": "ABCD",
        "note": "BIA 需全面評估有形與無形的損失，以決定 RTO 與 RPO。"
    },
    {
        "id": "B15-Plan-07",
        "question": "關於「風險處理 (Risk Treatment)」的選項，下列配對哪些正確？(複選)",
        "options": [
            "(A) 安裝防火牆 -> 風險降低 (Modification)",
            "(B) 購買資安保險 -> 風險移轉 (Sharing)",
            "(C) 停止高風險業務 -> 風險避免 (Avoidance)",
            "(D) 管理層簽署接受殘餘風險 -> 風險保留 (Retention)"
        ],
        "answer": "ABCD",
        "note": "正確理解四種風險處理策略及其應用場景。"
    },
    {
        "id": "B15-Plan-08",
        "question": "在 BCP 演練中，關於「驗證目標」的設定，應包含哪些？(複選)",
        "options": [
            "(A) RTO 是否達成",
            "(B) RPO 是否達成 (資料回復完整性)",
            "(C) 人員是否熟悉應變程序",
            "(D) 通訊管道是否暢通"
        ],
        "answer": "ABCD",
        "note": "演練不只是走流程，更要驗證關鍵指標是否符合預期。"
    },
    // --- 實務管理 (單選) ---
    {
        "id": "B15-Plan-09",
        "question": "關於「社交工程演練」的結果分析，若發現某員工連續多次點擊釣魚信，最佳的管理處置是？",
        "options": [
            "(A) 直接開除",
            "(B) 深入了解原因 (是否業務流程使其難以辨識)，並提供針對性的輔導與訓練",
            "(C) 公開羞辱",
            "(D) 禁止使用電腦"
        ],
        "answer": "B",
        "note": "懲罰往往造成反效果 (隱匿通報)，教育與流程優化才是正途。"
    },
    {
        "id": "B15-Plan-10",
        "question": "在「變更管理」中，對於「緊急變更 (Emergency Change)」的程序，下列敘述何者正確？",
        "options": [
            "(A) 完全不需要審核",
            "(B) 可事後補單，但事前仍需獲得授權 (如口頭)，且事後需補齊完整紀錄與測試驗證",
            "(C) 只有主管可以做",
            "(D) 隨時都可以做"
        ],
        "answer": "B",
        "note": "緊急變更仍需受控 (Controlled)，只是流程加速，事後必須補正以維持可歸責性。"
    },
    {
        "id": "B15-Plan-11",
        "question": "關於「資安長 (CISO)」的角色職責，下列何者最不適當？",
        "options": [
            "(A) 制定資安策略",
            "(B) 監督資安合規",
            "(C) 兼任 IT 系統管理員與開發者",
            "(D) 向董事會報告風險"
        ],
        "answer": "C",
        "note": "CISO 應專注於治理與監督，兼任執行角色 (球員兼裁判) 會有利益衝突與職責不分的問題。"
    },
    {
        "id": "B15-Plan-12",
        "question": "在資安事故應變中，關於「對外發言」的原則，下列何者正確？",
        "options": [
            "(A) 每個員工都可以代表公司發言",
            "(B) 應指定單一發言人 (Single Point of Contact)，訊息發布需經核准，保持資訊一致與準確",
            "(C) 盡量說謊掩蓋",
            "(D) 拒絕回答任何問題"
        ],
        "answer": "B",
        "note": "危機溝通需統一窗口，避免錯誤資訊造成混亂或二度傷害商譽。"
    },
    {
        "id": "B15-Plan-13",
        "question": "關於 ISO 27002:2022 的控制屬性 (Attributes)，下列何者不是其中之一？",
        "options": [
            "(A) 控制類型 (Control Type) - 預防/偵測/矯正",
            "(B) 資安屬性 (InfoSec Properties) - C/I/A",
            "(C) 網路安全概念 (Cybersecurity Concepts) - 識別/保護/偵測/回應/復原",
            "(D) 產品價格 (Price)"
        ],
        "answer": "D",
        "note": "2022 版引入了屬性 (Hashtags) 概念，方便使用者從不同視角 (如 NIST CSF, CIA) 檢索控制措施。"
    },
    {
        "id": "B15-Plan-14",
        "question": "在採購資安產品時，要求廠商提供「Common Criteria (ISO 15408)」證書的主要目的是？",
        "options": [
            "(A) 確保產品功能與安全性經過第三方實驗室的標準化評估與驗證",
            "(B) 確保產品最便宜",
            "(C) 確保產品是國產的",
            "(D) 確保廠商規模夠大"
        ],
        "answer": "A",
        "note": "Common Criteria 是國際通用的資安產品評估準則，EAL 等級代表驗證的嚴謹度。"
    },
    {
        "id": "B15-Plan-15",
        "question": "關於「特權存取管理 (PAM)」的導入效益，下列何者錯誤？",
        "options": [
            "(A) 降低特權帳號被竊取的風險",
            "(B) 提供特權連線的側錄與稽核",
            "(C) 自動輪換特權密碼",
            "(D) 讓所有人都能擁有特權"
        ],
        "answer": "D",
        "note": "PAM 的目的是「限制」與「監控」特權，而非擴大特權。"
    },
    // --- 雲端與新技術管理 (單選) ---
    {
        "id": "B15-Plan-16",
        "question": "企業導入 BYOD (Bring Your Own Device) 政策時，為了保護公司資料，應強制要求裝置？",
        "options": [
            "(A) 是最新款手機",
            "(B) 安裝 MDM/MAM 軟體，實施密碼鎖定、儲存加密，並具備遠端抹除 (Remote Wipe) 功能",
            "(C) 不能安裝任何遊戲",
            "(D) 只能在公司充電"
        ],
        "answer": "B",
        "note": "這是 BYOD 安全的底線，確保裝置遺失時資料不外洩，且能將公私資料隔離。"
    },
    {
        "id": "B15-Plan-17",
        "question": "關於「影子 IT (Shadow IT)」的發現與管理，下列何種工具最有效？",
        "options": [
            "(A) 防毒軟體",
            "(B) CASB (Cloud Access Security Broker)",
            "(C) 員工訪談",
            "(D) 門禁系統"
        ],
        "answer": "B",
        "note": "CASB 分析防火牆日誌或透過 API，能識別組織內未經授權的雲端服務使用情形。"
    },
    {
        "id": "B15-Plan-18",
        "question": "在 AI 治理中，為了確保 AI 系統的「可解釋性 (Explainability)」，應避免？",
        "options": [
            "(A) 使用黑箱模型 (Black-box Model) 進行高風險決策 (如信貸、醫療)，除非有補償措施",
            "(B) 記錄訓練資料來源",
            "(C) 監控模型偏差",
            "(D) 進行模型審查"
        ],
        "answer": "A",
        "note": "高風險決策需要可解釋性，以符合法規 (如 GDPR 自動化決策權) 與道德要求。"
    },
    {
        "id": "B15-Plan-19",
        "question": "關於「資料生命週期管理 (DLM)」中的「銷毀」階段，對於雲端儲存資料的銷毀，最有效的確認方式是？",
        "options": [
            "(A) 實體破壞硬碟 (在公有雲難以執行)",
            "(B) 刪除金鑰 (Crypto-shredding / Cryptographic Erasure)",
            "(C) 刪除檔案連結",
            "(D) 寫信給客服"
        ],
        "answer": "B",
        "note": "在雲端環境無法物理接觸硬碟，刪除加密金鑰是確保資料無法被復原的標準作法。"
    },
    {
        "id": "B15-Plan-20",
        "question": "依據 NIST SP 800-207，零信任架構的部署模式中，「Agent/Gateway-based」模式的特點是？",
        "options": [
            "(A) 裝置需安裝代理程式 (Agent)，透過閘道器 (Gateway) 存取資源，適合遠端工作與 BYOD",
            "(B) 完全不需要安裝軟體",
            "(C) 只能在內網使用",
            "(D) 不支援雲端"
        ],
        "answer": "A",
        "note": "這是目前 ZTNA (零信任網路存取) 產品最主流的實作方式。"
    },
    // --- 綜合情境與法規 (單選) ---
    {
        "id": "B15-Plan-21",
        "question": "某公司發現供應商遭受勒索軟體攻擊，擔心自身受影響。這時應立即啟動什麼流程？",
        "options": [
            "(A) 供應鏈資安事故應變 (SCRM Incident Response)",
            "(B) 裁員",
            "(C) 停止所有業務",
            "(D) 發布新聞稿"
        ],
        "answer": "A",
        "note": "需評估與該供應商的連線、資料交換狀況，確認是否遭橫向感染，並啟動備案。"
    },
    {
        "id": "B15-Plan-22",
        "question": "關於《資通安全管理法》的「特定非公務機關」，若未依規定訂定資通安全維護計畫，經令限期改正而屆期未改正者，罰鍰金額為？",
        "options": [
            "(A) 1 萬 ~ 5 萬",
            "(B) 10 萬 ~ 100 萬",
            "(C) 30 萬 ~ 500 萬 (依最新修正草案/現行法規)",
            "(D) 不會罰錢"
        ],
        "answer": "B",
        "note": "依據現行資安法第 30 條，違反維護計畫相關規定，處 10 萬以上 100 萬以下罰鍰。"
    },
    {
        "id": "B15-Plan-23",
        "question": "ISO 27001 稽核中，稽核員發現「員工將密碼寫在便條紙貼在螢幕上」，這違反了哪個控制措施？",
        "options": [
            "(A) 存取控制",
            "(B) 實體安全 - 桌面淨空與螢幕淨空 (Clear desk and clear screen)",
            "(C) 網路安全",
            "(D) 供應鏈安全"
        ],
        "answer": "B",
        "note": "這是一個經典的實體安全違規案例。"
    },
    {
        "id": "B15-Plan-24",
        "question": "在「營運衝擊分析 (BIA)」中，評估「法律遵循性衝擊」時，主要考量？",
        "options": [
            "(A) 律師費",
            "(B) 因違反法律、法規或契約要求而導致的罰款、訴訟或營業執照吊銷風險",
            "(C) 法官的心情",
            "(D) 法律條文的字數"
        ],
        "answer": "B",
        "note": "法遵衝擊往往涉及巨額罰款與營運資格的喪失。"
    },
    {
        "id": "B15-Plan-25",
        "question": "關於「資安認知教育訓練」，對於開發人員 (Developers)，應加強哪方面的課程？",
        "options": [
            "(A) 如何使用印表機",
            "(B) 安全程式碼開發 (Secure Coding)、OWASP Top 10、常見漏洞修補",
            "(C) 社交工程防範 (雖然也需要，但非職位特定重點)",
            "(D) 機房管理"
        ],
        "answer": "B",
        "note": "針對角色 (Role-based) 的訓練才有效，開發者需具備寫出安全程式碼的能力。"
    },
    {
        "id": "B15-Plan-26",
        "question": "在雲端遷移過程中，「Rehost (Lift & Shift)」策略的資安風險在於？",
        "options": [
            "(A) 成本太高",
            "(B) 可能將原本存在於地端環境的弱點、惡意軟體或錯誤設定，原封不動地帶到雲端",
            "(C) 速度太慢",
            "(D) 雲端不支援"
        ],
        "answer": "B",
        "note": "直接搬遷而不進行重構或強化，往往繼承了舊有的技術債與風險。"
    },
    {
        "id": "B15-Plan-27",
        "question": "關於「最小功能 (Least Functionality)」原則，在伺服器強化 (Hardening) 時的應用是？",
        "options": [
            "(A) 安裝所有軟體",
            "(B) 僅安裝與執行業務所需的服務、應用程式與通訊協定，移除或停用不必要的元件",
            "(C) 買最便宜的伺服器",
            "(D) 不設定密碼"
        ],
        "answer": "B",
        "note": "減少攻擊面 (Attack Surface) 的核心作法。"
    },
    {
        "id": "B15-Plan-28",
        "question": "在資安事件分級中，若事件涉及「核心業務運作停頓，且無法於 RTO 內恢復」，通常應列為？",
        "options": [
            "(A) 1 級",
            "(B) 2 級",
            "(C) 3 級或 4 級 (視是否涉及關鍵基礎設施或國家機密)",
            "(D) 0 級"
        ],
        "answer": "C",
        "note": "核心業務中斷且超時，屬於嚴重事件 (3級起跳)。"
    },
    {
        "id": "B15-Plan-29",
        "question": "關於「縱深防禦」在「人員 (People)」層面的落實，包括？",
        "options": [
            "(A) 只有教育訓練",
            "(B) 人員篩選 (背景查核)、簽署保密協定、持續的認知訓練、職務輪調與離職管理",
            "(C) 監控員工私生活",
            "(D) 限制員工飲食"
        ],
        "answer": "B",
        "note": "人員安全管理涵蓋從入職前到離職後的完整生命週期。"
    },
    {
        "id": "B15-Plan-30",
        "question": "企業進行「滲透測試」的主要商業效益是？",
        "options": [
            "(A) 為了好玩",
            "(B) 驗證資安投資的有效性，發現並修補高風險漏洞，避免因真實攻擊造成的鉅額損失 (ROI)",
            "(C) 應付稽核",
            "(D) 消耗預算"
        ],
        "answer": "B",
        "note": "滲透測試是驗證防禦成效的實戰手段，能大幅降低被入侵的期望損失。"
    }
];

// 將 Batch 15 的題目合併到主陣列
if (typeof protectionQuestions !== 'undefined') {
    protectionQuestions.push(...protectionQuestions_Batch15);
}
if (typeof planningQuestions !== 'undefined') {
    planningQuestions.push(...planningQuestions_Batch15);
}