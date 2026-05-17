"""
api/main.py
FastAPI application — exposes the vulnerability classification pipeline
as an HTTP API. Single endpoint: POST /classify

Run locally:
    uvicorn api.main:app --reload --port 8000

Run in HF Spaces:
    uvicorn api.main:app --host 0.0.0.0 --port 7860
"""

from __future__ import annotations
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from pipeline.router import get_router

# ── Lifespan — warm up classifier on startup ──────────────────────────────────
# RoBERTa (125MB) loads fast — warm it up at startup so first request isn't slow
# Qwen (5GB) is lazy-loaded on first code input — too large to preload

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[API] Warming up RoBERTa classifier...")
    router = get_router()
    router._get_classifier()  # preload RoBERTa only
    print("[API] Ready.")
    yield
    print("[API] Shutting down.")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CodeSentinel API",
    description=(
        "Vulnerability classification API. "
        "Classifies code snippets and CVE descriptions into CWE categories, "
        "with optional ATLAS AI/ML attack pattern matching."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# Allow frontend (HF Spaces, localhost) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this in production
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ── Schemas ───────────────────────────────────────────────────────────────────

class ClassifyRequest(BaseModel):
    input: str = Field(
        ...,
        min_length=10,
        max_length=8000,
        description="Raw input — code snippet, CVE description, or bug report.",
        examples=[
            "def get_user(name): return db.execute('SELECT * FROM users WHERE name=' + name)"
        ],
    )


class CWEPrediction(BaseModel):
    cwe_id:      str
    cwe_name:    str
    severity:    str
    confidence:  float


class ATLASMatch(BaseModel):
    atlas_id:        str
    technique:       str
    tactic:          str
    confidence:      str
    matched_signals: list[str]
    description:     str
    mitigations:     list[str]
    real_world:      Optional[str]
    reasoning:       str


class ClassifyResponse(BaseModel):
    # Primary result
    cwe_id:       str
    cwe_name:     str
    severity:     str
    confidence:   float

    # Explanation (Qwen's structured description or original input)
    description:  str

    # Top-3 alternatives (excluding top-1)
    alternatives: list[CWEPrediction]

    # ATLAS match — None if no AI/ML signals detected
    atlas_match:  Optional[ATLASMatch]

    # Metadata
    input_type:   str   # "code" or "text"
    warning:      Optional[str]
    elapsed_s:    float


class HealthResponse(BaseModel):
    status:  str
    version: str
    models:  dict


class ErrorResponse(BaseModel):
    error:   str
    detail:  Optional[str]


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    return {"message": "CodeSentinel API v0.1 — POST /classify to classify input."}


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check — returns model load status."""
    router = get_router()
    return {
        "status":  "ok",
        "version": "0.1.0",
        "models": {
            "roberta":       "loaded" if router._classifier is not None else "not loaded",
            "qwen":          "loaded" if router._code_analyzer is not None else "not loaded (lazy)",
            "atlas_matcher": "loaded" if router._atlas_matcher is not None else "not loaded (lazy)",
        }
    }


@app.post(
    "/classify",
    response_model=ClassifyResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid input"},
        500: {"model": ErrorResponse, "description": "Internal classification error"},
    },
)
async def classify(request: ClassifyRequest):
    """
    Classify a vulnerability input.

    - **Code snippets** → Qwen analyzes → RoBERTa classifies → CWE result
    - **CVE/text descriptions** → RoBERTa classifies directly → CWE result
    - **AI/ML-related inputs** → also runs ATLAS pattern matcher

    Returns a unified output card with CWE ID, severity, explanation,
    remediation hints, and optional ATLAS technique match.
    """
    try:
        router = get_router()
        result = router.run(request.input)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Classification failed: {str(e)}"
        )

    # Build alternatives list
    alternatives = [
        CWEPrediction(**alt) for alt in result.get("alternatives", [])
    ]

    # Build ATLAS match if present
    atlas_match = None
    if result.get("atlas_match"):
        atlas_match = ATLASMatch(**result["atlas_match"])

    return ClassifyResponse(
        cwe_id=result["cwe_id"],
        cwe_name=result["cwe_name"],
        severity=result["severity"],
        confidence=result["confidence"],
        description=result["description"],
        alternatives=alternatives,
        atlas_match=atlas_match,
        input_type=result["input_type"],
        warning=result.get("warning"),
        elapsed_s=result["elapsed_s"],
    )


# ── Error handlers ────────────────────────────────────────────────────────────

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Not found", "detail": str(request.url)}
    )


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": "Check server logs."}
    )