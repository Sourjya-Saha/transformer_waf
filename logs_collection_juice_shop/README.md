# OWASP Juice Shop 20,000 HTTP Logs Collection

Automated **Playwright** synthetic traffic generator and full HTTP transaction log recorder for OWASP Juice Shop.

---

## ❓ Do You Need Any AI Model (Groq / OpenAI API Keys)?

**No, absolutely not.** You do **NOT** need any AI model, LLM API keys, or cloud AI services to run this script or collect 20,000 logs:
1. **Deterministic Speed & Efficiency**: Playwright uses direct asynchronous browser automation and network event listeners (`page.on('response', ...)`), logging hundreds of requests per second directly to disk.
2. **Zero Cost & No Rate Limits**: Running LLM API calls for 20k operations would be slow, costly, and hit rate limits. Playwright's native Python async engine runs entirely on your local machine with zero external dependencies.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
Ensure you have Python 3.9+ installed and install Playwright:

```powershell
pip install playwright
playwright install chromium
```

---

### 2. Run OWASP Juice Shop Locally

You can run OWASP Juice Shop on your machine using either Docker or Node.js:

#### Option A: Run via Docker (Recommended)
```powershell
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

#### Option B: Run via Node.js
```powershell
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start
```
Juice Shop will be accessible at: `http://localhost:3000`

---

### 3. Run the 20,000 Log Collection Script

Navigate to this folder and start the collector:

```powershell
python collect_juice_shop_logs.py --url http://localhost:3000 --logs 20000 --workers 4
```

#### CLI Parameters:
* `--url`: The URL where Juice Shop is running (default: `http://localhost:3000` or `https://juice-shop.herokuapp.com`).
* `--logs`: Target number of HTTP transactions to collect (default: `20000`).
* `--workers`: Number of concurrent headless browser contexts (default: `4`).

---

## 📁 Output Log Formats

The script writes to two output files in real time:

### 1. Plain Text Log (`juice_shop_logs.txt`)
Standard single-line web server access log format:
```text
[2026-09-21T15:20:01.123456+00:00] IP:127.0.0.1 METHOD:GET URL:http://localhost:3000/rest/products/search?q=apple STATUS:200 SIZE:1420B TYPE:fetch
[2026-09-21T15:20:01.345678+00:00] IP:127.0.0.1 METHOD:POST URL:http://localhost:3000/api/Feedbacks/ STATUS:201 SIZE:280B TYPE:xhr
```

### 2. Structured JSON Log (`juice_shop_logs.json`)
Rich JSON array with detailed request and response metadata:
```json
{
  "total_logs": 20000,
  "logs": [
    {
      "log_id": 1,
      "timestamp": "2026-09-21T15:20:01.123456+00:00",
      "client_ip": "127.0.0.1",
      "method": "GET",
      "url": "http://localhost:3000/rest/products/search?q=apple",
      "status_code": 200,
      "status_text": "OK",
      "resource_type": "fetch",
      "request_headers": {
        "accept": "application/json",
        "user-agent": "Mozilla/5.0 ..."
      },
      "request_payload": "",
      "response_headers": {
        "content-type": "application/json; charset=utf-8",
        "content-length": "1420"
      },
      "response_size_bytes": 1420
    }
  ]
}
```

---

## 🔄 User Journeys Simulated by the Script
The script autonomously executes randomized, realistic end-to-end interactions across Juice Shop:
1. **Catalog Browsing & Keyword Searches** (searching juices, hoodies, fruit terms).
2. **Product Details & Reviews View** (opening modal dialogs).
3. **Cart & Basket Operations** (adding items to cart).
4. **Site Navigation** (About, Score Board, Photo Wall, Contact).
5. **Customer Feedback Submission** (submitting ratings and reviews).
6. **High-Throughput REST API Invocations** (REST endpoints for products, feedback, challenges).
