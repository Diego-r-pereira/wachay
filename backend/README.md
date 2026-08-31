# WACHAY - Backend Service

FastAPI-powered backend for WACHAY providing REST endpoints, AI/ML inference (fire detection and weather risk prediction), emergency messaging (Twilio/Telegram), and RAG assistance.

## Features

- **FastAPI Architecture**: High-performance asynchronous API endpoints.
- **AI / ML Integration**: MobileNetV2 fire classification & weather risk estimation.
- **Emergency Notifications**: Real-time alerts via WhatsApp and Telegram.
- **RAG Assistance**: AI knowledge base for emergency response.

## Setup Instructions

1. **Activate Virtual Environment**:
   ```bash
   # Windows
   .venv\Scripts\activate
   # Linux / macOS
   source .venv/bin/activate
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Copy `.env.example` to `.env` and fill in necessary keys:
   ```bash
   cp .env.example .env
   ```

4. **Run Server**:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
