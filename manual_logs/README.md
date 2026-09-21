# 🚀 Manual Log Collection with Nginx Reverse Proxy

This setup uses **Nginx** as a reverse proxy in front of OWASP Juice Shop (`http://localhost:3000`).

Whenever you interact with Juice Shop through Nginx (`http://localhost:80` or `http://localhost:8088`), Nginx automatically captures every request in:
- `manual_logs.txt` (Standard text format with response timing)
- `manual_logs.json` (Structured JSON format per line)

---

## 🏃 How to Run (Step-by-Step)

### Step 1: Ensure Juice Shop is running on port 3000
```bash
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

---

### Step 2: Start Nginx with Docker

Run this command from inside your project folder (`C:\Users\Sourjya Saha\Desktop\WAF-TEST`):

```powershell
docker run -d --name nginx-logger -p 80:80 -v "${PWD}/manual_logs/nginx.conf:/etc/nginx/nginx.conf:ro" -v "${PWD}/manual_logs:/var/log/nginx" nginx:alpine
```

*(If port 80 is in use on Windows by IIS/System, use `-p 8088:80` and open `http://localhost:8088` instead).*

---

### Step 3: Perform your Manual Actions & Tests

Open your browser and navigate to:
👉 **`http://localhost`** (or `http://localhost:8088`)

Now do any manual actions:
1. Register and login with accounts.
2. Search products, add items to cart, checkout.
3. Inject SQLi payloads (`' OR 1=1--`), XSS strings (`<iframe src="javascript:alert(1)">`), or broken access paths (`/ftp`, `/rest/admin`).
4. Send manual `curl` commands or Postman requests targeting `http://localhost/api/...`.

---

### Step 4: Watch Your Logs Stream Live

In PowerShell, watch the logs in real-time as you click:

```powershell
Get-Content -Path .\manual_logs\manual_logs.txt -Wait -Tail 10
```

Or for JSON:
```powershell
Get-Content -Path .\manual_logs\manual_logs.json -Wait -Tail 10
```

---

### Step 5: Stop Nginx When Done
```powershell
docker stop nginx-logger
docker rm nginx-logger
```
