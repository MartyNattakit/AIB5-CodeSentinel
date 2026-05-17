"""
app.py
HF Spaces entry point — serves both the FastAPI backend and the frontend UI.
HF Spaces runs this file directly with: python app.py
"""

import uvicorn
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from api.main import app

# ── Serve frontend ────────────────────────────────────────────────────────────
# Mount the frontend folder so index.html is served at "/"

FRONTEND_DIR = Path(__file__).parent / "frontend"

@app.get("/", include_in_schema=False)
async def serve_frontend():
    return FileResponse(FRONTEND_DIR / "index.html")

# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=7860,      # HF Spaces default port
        reload=False,
    )