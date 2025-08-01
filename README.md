# BrokenAuth Analyzer (Burp Suite Extension)


## 🔍 Overview
BrokenAuth Analyzer is a **Burp Suite Extension** designed to help penetration testers identify **Broken Authentication** vulnerabilities. It automates header manipulation techniques to detect improper session handling and authentication weaknesses.

---

## ✅ Features
- Detects broken authentication issues using header tampering.
- Supports **manual trigger** and **auto-scan** mode (Proxy/History).
- GUI Tabs:
  - **Summary**: Shows SAFE vs VULNERABLE endpoints.
  - **Results**: Detailed table with inline Request/Response viewer.
  - **Settings**: Configure headers and custom options.
- Highlights **VULNERABLE** rows in red, **SAFE** rows in green.

---

## 🛠 Installation
1. Download **broken_auth_analyzer.py** from this repository.
2. Open Burp Suite → Extender → Extensions → Add.
3. Select:
   - **Extension Type**: Python
   - **Extension file**: `broken_auth_analyzer.py`
4. Ensure Jython 2.7.x is configured in Burp Suite.

---

## ▶️ Usage
- Navigate to **BrokenAuth Analyzer** tab in Burp.
- Send HTTP requests to the extension:
  - **Manual Mode**: Right-click any request → `Send to BrokenAuth Analyzer`.
  - **Auto Mode**: Enable `Auto Scan` in settings to scan Proxy/History requests automatically.

---

## ⚙️ Requirements
- **Burp Suite Professional or Community**
- **Jython 2.7.x**

---

## 🔒 Disclaimer
This tool is for **authorized security testing only**. Do not use it on systems without permission.

---

## 👨‍💻 Author
Developed by Your Narendra Reddy
