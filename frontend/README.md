# APK Sentinel — Frontend

A "forensic case file" dashboard for the APK Sentinel backend: drop in an `.apk`,
watch a live sandbox console while it's analyzed, then read the full 5-pillar
threat dossier — risk gauge, permissions, behavioral timeline, network activity,
and the investigator checklist — with a one-click PDF download.

Built with React + Vite, no UI framework — all styling is hand-rolled from a
small token system in `src/styles/tokens.css` (phosphor-amber accent, mono
data face, dossier/stamp motifs) so it matches the security-tooling subject
matter instead of looking like a generic admin template.

## Setup

```bash
cd frontend
npm install
cp .env.example .env       # point VITE_API_URL at your backend
npm run dev                # http://localhost:5173
```

The backend's CORS config (`backend/src/server.js`) already allows
`http://localhost:5173`, so no backend changes are needed.

## How it talks to the backend

`src/api.js` wraps the three documented endpoints exactly:

| Function         | Endpoint                          |
|-------------------|------------------------------------|
| `uploadApk(file)` | `POST /api/analyze`               |
| `getStatus(id)`   | `GET /api/status/:jobId`          |
| `getReport(id)`   | `GET /api/report/:jobId?format=json` |
| `pdfReportUrl(id)`| `GET /api/report/:jobId?format=pdf`  |

`pollStatus()` polls `/api/status/:jobId` every ~1.8s and feeds `progress`
into the live console, whose log lines are keyed to the exact checkpoints
the backend pipeline emits (10 / 25 / 45 / 75 / 90 / 100 — see
`backend/src/core/pipeline.js`), so the console narrates real pipeline
stages rather than a generic spinner.

## Structure

```
src/
├── api.js                 # backend client (upload / poll / report)
├── App.jsx                # phase state machine: idle → scanning → report
├── components/
│   ├── UploadPanel.jsx     # drag/drop intake
│   ├── ScanConsole.jsx     # live polling console
│   ├── VerdictStamp.jsx    # risk gauge + severity stamp (signature element)
│   ├── ReportView.jsx      # full dossier: all 5 pillars + static/dynamic data
│   └── ui.jsx              # shared primitives (Panel, Pill, Bar, etc.)
├── fixtures/sample-report.json  # for visually testing ReportView without a backend
└── styles/tokens.css       # design tokens
```

## Notes

- Every field rendered in `ReportView.jsx` maps 1:1 to the JSON shape produced
  by `reportGenerator.js` (`verdict`, `narrative`, `staticAnalysis`,
  `dynamicAnalysis`, `genaiAnalysis`, `riskBreakdown`) — no guessed fields.
- 100MB upload limit and `.apk`-only validation mirror the backend's multer
  config; the upload panel doesn't try to enforce anything the server doesn't.
