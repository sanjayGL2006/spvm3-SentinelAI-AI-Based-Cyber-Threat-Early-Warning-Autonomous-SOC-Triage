# SentinelAI - Frontend

The frontend of SentinelAI is a modern, responsive web dashboard built with **React** and **TypeScript**, powered by **Vite** for fast development and building. It provides security analysts with a clear view of current threats, system statistics, and interactive controls to manage alerts.

## 🛠️ Technologies
- **React 18**
- **TypeScript** for type-safe components
- **Vite** for the build tooling and development server

## ⚙️ Setup and Running

1. **Navigate to the frontend directory:**
   ```bash
   cd frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm run dev
   ```
   The dashboard will be accessible at `http://localhost:5173`.

## ✨ Features

- **Threat Dashboard**: A high-level overview of system statistics, active threats broken down by severity, and top offending source IPs.
- **Alert Management**: View detailed alerts with human-readable explanations, MITRE ATT&CK technique mappings, and AI-generated risk scores (0-100).
- **Incident Response Simulation**: Interact with alerts by changing their status (e.g., "Investigating", "False Positive", "Resolved") or by initiating a simulated containment action that internally blocks the source IP.
- **Demo Mode**: One-click generation of synthetic threat data to test and visualize the system's capabilities.
- **Custom Data Ingestion**: Upload custom log CSVs directly through the UI for ad-hoc analysis.

## 🔌 API Connectivity
The frontend expects the backend FastAPI server to be running on `http://localhost:8000`. If you change the backend port, ensure you update any relevant fetch URLs or proxy settings in the frontend configuration.
