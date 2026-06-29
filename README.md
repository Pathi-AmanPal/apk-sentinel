# 🛡️ APK Sentinel

An advanced, GenAI-powered Android APK threat assessment platform combining deep static decompilation, real-time dynamic behavior tracing, semantic vector similarity indexing, and multi-pillar threat categorization.

---

## 📂 Repository Layout

```text
apk-sentinel/
├── backend/                  # Node.js / Express security engine
│   ├── src/
│   │   ├── core/             # Static, dynamic, and GenAI engines
│   │   ├── db/               # Vector similarity matching (Qdrant)
│   │   ├── routes/           # REST endpoints
│   │   └── server.js         # Entry point (serves public frontend)
│   ├── tools/                # Frida instrumentation scripts
│   ├── uploads/              # Local upload storage (ignored)
│   └── package.json
├── frontend/                 # Vite + React dashboard console
│   ├── src/                  # React dashboard components
│   ├── index.html
│   ├── vite.config.js        # Output redirection & API dev proxy
│   └── package.json
├── package.json              # Monorepo build coordinator
└── vercel.json               # Unified Vercel deployment configuration
```

---

## 🚀 Key Features

* **Static Analysis Pipeline**: Decompiles APK manifests using `Apktool` and extracts source bytecode with `JADX`. Scans for key android permission declarations and dangerous bytecode patterns.
* **Dynamic Analysis Sandboxing**: Automates target emulator setup, hooks critical APIs (SMS broadcasts, URL network connections, crypto routines, dex loading, root-checking) using custom **Frida** trace scripts, and records execution logs.
* **5-Pillar GenAI Assessment**: Uses **Google Gemini** to process decompiled assets and dynamic traces in a combined context:
  * *Pillar 1: Brand Impersonation / Identity Gap Analysis*
  * *Pillar 2: Code Deobfuscator & Intent Analyzer*
  * *Pillar 3: Threat Kill-Chain Classification (MITRE ATT&CK Mapping)*
  * *Pillar 4: Executive Security Verdict*
  * *Pillar 5: Environmental Evasion & Anti-Analysis Detection*
* **Vector Threat Database**: Indexes intent payloads inside **Qdrant Vector Database** to find semantic similarities with known banking trojan families (Anubis, Cerberus, FakePay).

---

## ⚡ Unified Vercel Deployment

This repository is optimized to deploy both the backend Express server and the React/Vite frontend as a single, unified project on Vercel:
1. **Zero CORS Headaches**: The Vite production build compiles directly into `backend/public/`, allowing the Express backend to serve it statically.
2. **Serverless Directory Resolution**: Resolves uploads and reports to `/tmp` automatically when running inside Vercel, bypassing read-only filesystem restrictions.
3. **Resilient Job Store**: Uses a hybrid file-persisted state-recovery mechanism so polling client requests resolve correctly even if a serverless container warm-restarts.

---

## 📡 REST API Reference

All backend routes are prefixed with `/api`.

### 1. Upload APK for Analysis
* **Endpoint**: `POST /api/analyze`
* **Content-Type**: `multipart/form-data`
* **Request Fields**:
  * `apk`: File (the `.apk` file to analyze)
* **Response**:
  ```json
  {
    "success": true,
    "jobId": "f846be0c-b634-41f6-bd9b-ee289616c75b",
    "status": "active",
    "message": "APK analysis started. Poll /api/status/:jobId for updates.",
    "pollUrl": "/api/status/f846be0c-b634-41f6-bd9b-ee289616c75b"
  }
  ```

### 2. Poll Job Status
* **Endpoint**: `GET /api/status/:jobId`
* **Response (Active/Running)**:
  ```json
  {
    "success": true,
    "jobId": "f846be0c-b634-41f6-bd9b-ee289616c75b",
    "status": "active",
    "progress": 45,
    "createdAt": "2026-06-18T15:38:50.480Z"
  }
  ```
* **Response (Completed)**:
  ```json
  {
    "success": true,
    "jobId": "f846be0c-b634-41f6-bd9b-ee289616c75b",
    "status": "completed",
    "progress": 100,
    "result": {
      "jobId": "f846be0c-b634-41f6-bd9b-ee289616c75b",
      "riskScore": 86,
      "severity": "CRITICAL",
      "recommendation": "BLOCK_IMMEDIATELY",
      "reportUrl": "/api/report/f846be0c-b634-41f6-bd9b-ee289616c75b"
    }
  }
  ```

### 3. Fetch Security Report
* **Endpoint**: `GET /api/report/:jobId?format=json`
* **Response**: Returns the complete 5-pillar security evaluation including executive summary, temporal attack timelines, network exfiltration targets, and risk breakdown.

---

## 🛠️ Local Development Setup

To run the application locally, you will run the backend and the frontend development servers concurrently.

### 1. Environment Configuration

Create a `.env` file in the `backend/` directory:
```env
PORT=3000
GEMINI_API_KEY=your_gemini_api_key
STUB_ANALYSIS=true  # Set to false to invoke local JADX & Frida tools
```

### 2. Run Backend Security Engine

```bash
cd backend
npm install
npm run dev
```
The backend API server will run at `http://localhost:3000`.

### 3. Run Frontend Dashboard Console

```bash
cd frontend
npm install
npm run dev
```
The Vite development server will run at `http://localhost:5173`. Any API calls to `/api` will be proxied automatically to the backend on port `3000`.
