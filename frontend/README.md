# MedCore Health — Next.js 14 Frontend Application

A modern, clinical-grade electronic health records (EHR) web portal built with **Next.js 14 (App Router)**, **React 18**, and **Tailwind CSS**.

All requests from this frontend route through the **Deterministic Layer-7 Web Application Firewall (WAF)** at `http://localhost:8000` (or `http://localhost:80`), before reaching the protected FastAPI backend connected to your **MySQL database**.

---

## 🚀 Quick Start

### 1. Install Node Dependencies
Inside the `frontend/` directory:
```bash
npm install
```

### 2. Run Next.js Development Server
```bash
npm run dev
```

Open **`http://localhost:3000`** in your browser.

---

## 🛡️ Architecture & Ports

```
Next.js Frontend (Port 3000) ──► WAF Gateway (Port 8000) ──► FastAPI Backend (Port 8080) ──► MySQL (Port 3306)
```

| Port | Service | Description |
| :--- | :--- | :--- |
| **`3000`** | **Next.js Frontend** | Interactive EHR patient portal & live attack trigger UI |
| **`8000`** | **WAF Gateway** | Layer-7 deterministic reverse proxy firewall |
| **`8080`** | **FastAPI Backend** | Protected clinical API server (Tier 3) |
| **`3306`** | **MySQL Database** | Local MySQL Workbench / Server (`medcore_db`) |
| **`9000`** | **Live Attack Console** | Standalone 3-panel visualizer & forensic log tail |

---

## 🗄️ MySQL Database Setup (MySQL Workbench)
1. Open **MySQL Workbench** and connect to your local MySQL instance.
2. Open and execute [`demo_backend/schema.sql`](../demo_backend/schema.sql).
3. The `medcore_db` database and initial seed records for staff, patients, notes, and lab reports will be created instantly.

---

## 🧪 Built-In Live Viva Attack Triggers
The frontend includes an interactive **Live Attack Simulator Bar** on every page:
- **SQLi in Auth Body (`SQL-002`)**: Injects `' OR 1=1--` into login JSON body.
- **Reflected XSS in Search (`XSS-001`)**: Injects `<script>alert(1)</script>` in patient search.
- **Path Traversal in Downloads (`PT-001`)**: Requests `../../etc/passwd` on medical files.
- **Rate Limit Burst (`RATE-LIMIT`)**: Fires 25 rapid requests exceeding token bucket capacity.
- **XXE Lab Ingestion (`XXE-001`)**: Injects `DOCTYPE SYSTEM "file:///etc/passwd"` into XML imports.
