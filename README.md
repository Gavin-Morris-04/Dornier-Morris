# AI Phishing Prevention

---

## Architecture Overview

* **Frontend (`/frontend`):** A React (TypeScript) SPA built with Vite. It runs inside a secure Microsoft iFrame sandbox, communicating with Outlook via the `Office.js` SDK. It automatically handles secure HTTPS protocol requirements locally via self-signed SSL certificates.
* **Backend (`/backend`):** An asynchronous FastAPI (Python) service that handles data validation via Pydantic and serves as the hosting framework for text-classification and AI-detection models.

---

## Prerequisites

Before setting up the project, ensure you have the following environments installed on your machine:
1.  **Python (v3.11 or higher)** -> *CRITICAL: During installation on Windows, ensure you check the box that says **"Add python.exe to PATH"**.*
2.  **Node.js (LTS Version)**

---

## Local Development Setup

Follow these steps sequentially to spin up your local environment.

### Step 1: Boot the FastAPI Backend

1. Open your terminal or command prompt and navigate to the backend directory:
    ```bash
    cd backend
    ```
2. Install the necessary Python dependencies:
    ```bash
    python -m pip install -r requirements.txt
    ```
3. Start the local Uvicorn development server:
    ```bash
    python -m uvicorn main:app --reload --port 8000
    ```
    *The backend is running successfully once you see:* `INFO: Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)`

---

### Step 2: Boot the React Task Pane Frontend

1. Open a **brand new terminal window or tab** (leaving the backend running) and navigate to the frontend directory:
    ```bash
    cd frontend
    ```
2. Install the frontend Node packages:
    ```bash
    npm install
    ```
3. Launch the secure Vite development server:
    ```bash
    npm run dev
    ```
    *The frontend is running successfully once you see an active local HTTPS address:* `➜  Local:   https://localhost:3000/`

---

### Step 3: Sideload into Microsoft Outlook

Because this is a native enterprise add-in, you manifest it directly into your live Outlook account for development:

1. Open your web browser and log into **Outlook Web (Microsoft 365)**.
2. Open or click on any email in your inbox to reveal the reading view.
3. On the top-right toolbar of the active email, click the **Apps** icon button, then click **Add apps**.
4. In the overlay panel, click **Manage your apps** near the bottom left.
5. Click **Upload a custom app** -> **Upload from file**.
6. Navigate to your project's root directory and select the `manifest.xml` file.

The **AI Security Shield** panel will immediately hook into your Outlook sidebar. As you click through different emails, the task pane will dynamically capture the email text, pass it securely to your local Python API, and render the results live.

