# APK Sentinel

A GenAI-powered Android APK static and dynamic analysis threat assessment tool.

## Repository Structure

- `backend/` - Node.js Express server incorporating the static analysis engine (Apktool/JADX), dynamic trace hooks (Frida/ADB), and 5-pillar GenAI classifier (Gemini).
- `frontend/` - Reserved for the user interface dashboard application.

## Getting Started

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Copy environment example file and configure variables:
   ```bash
   cp .env.example .env
   ```
4. Start the server:
   ```bash
   npm run dev
   ```

### Deployment

The backend is configured for serverless deployment on Vercel via `@vercel/node`.
- Configuration: `backend/vercel.json`
- Routing & Temp file writes are handled dynamically.
