"""
pipeline/classifier.py
RoBERTa-based CWE classifier — wraps the fine-tuned model for inference.
Input:  natural language vulnerability description (str)
Output: list of top-k CWE predictions with confidence scores
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline

# ── Constants ────────────────────────────────────────────────────────────────

HF_REPO = "martynattakit/vuln-classifier-roberta"
MAX_LENGTH = 256
TOP_K = 3

# CWEs where the model is known to be unreliable (from eval report)
LOW_CONFIDENCE_CWES = {
    "CWE-77",   # 0 samples in training — never predicts correctly
    "CWE-863",  # F1 0.60 — overlaps with CWE-862
}

CWE_DESCRIPTIONS = {
    "CWE-787": "Out-of-bounds Write",
    "CWE-79":  "Cross-site Scripting (XSS)",
    "CWE-89":  "SQL Injection",
    "CWE-416": "Use After Free",
    "CWE-78":  "OS Command Injection",
    "CWE-20":  "Improper Input Validation",
    "CWE-125": "Out-of-bounds Read",
    "CWE-22":  "Path Traversal",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-434": "Unrestricted File Upload",
    "CWE-862": "Missing Authorization",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-287": "Improper Authentication",
    "CWE-190": "Integer Overflow",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-77":  "Command Injection",
    "CWE-119": "Buffer Overflow (Generic)",
    "CWE-798": "Hardcoded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-306": "Missing Authentication",
    "CWE-362": "Race Condition",
    "CWE-269": "Improper Privilege Management",
    "CWE-94":  "Code Injection",
    "CWE-863": "Incorrect Authorization",
    "CWE-276": "Incorrect Default Permissions",
}

SEVERITY_MAP = {
    "CWE-787": "HIGH",
    "CWE-79":  "MEDIUM",
    "CWE-89":  "HIGH",
    "CWE-416": "HIGH",
    "CWE-78":  "HIGH",
    "CWE-20":  "MEDIUM",
    "CWE-125": "MEDIUM",
    "CWE-22":  "HIGH",
    "CWE-352": "MEDIUM",
    "CWE-434": "HIGH",
    "CWE-862": "HIGH",
    "CWE-476": "MEDIUM",
    "CWE-287": "HIGH",
    "CWE-190": "MEDIUM",
    "CWE-502": "HIGH",
    "CWE-77":  "HIGH",
    "CWE-119": "HIGH",
    "CWE-798": "CRITICAL",
    "CWE-918": "HIGH",
    "CWE-306": "CRITICAL",
    "CWE-362": "MEDIUM",
    "CWE-269": "HIGH",
    "CWE-94":  "HIGH",
    "CWE-863": "HIGH",
    "CWE-276": "MEDIUM",
}

# ── Classifier class ─────────────────────────────────────────────────────────

class CWEClassifier:
    """
    Wraps the fine-tuned RoBERTa model for CWE classification.
    Lazy-loaded on first call — fast import, slow first inference.
    """

    def __init__(self, repo: str = HF_REPO, device: Optional[str] = None):
        self.repo = repo
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self._pipeline = None

    def _load(self):
        """Lazy load the model on first inference call."""
        if self._pipeline is not None:
            return

        print(f"[CWEClassifier] Loading model from {self.repo}...")
        self._pipeline = pipeline(
            "text-classification",
            model=self.repo,
            tokenizer=self.repo,
            device=0 if self.device == "cuda" else -1,
            top_k=TOP_K,
            truncation=True,
            max_length=MAX_LENGTH,
        )
        print("[CWEClassifier] Model loaded.")

    def classify(self, text: str) -> dict:
        """
        Classify a vulnerability description.

        Args:
            text: Natural language vulnerability description.
                  Should follow the structured format:
                  "This function performs X on Y without Z, which may allow..."

        Returns:
            {
                "top1":        { "cwe_id", "description", "severity", "confidence" },
                "top3":        [ { "cwe_id", "description", "severity", "confidence" }, ... ],
                "warning":     str | None,   # set if top1 is a known weak class
                "raw_scores":  { cwe_id: score, ... }
            }
        """
        self._load()

        if not text or not text.strip():
            raise ValueError("Input text cannot be empty.")

        raw = self._pipeline(text[:MAX_LENGTH * 4])  # rough char limit before tokenizer
        predictions = raw[0]  # list of {label, score}

        results = []
        for pred in predictions:
            cwe_id = pred["label"]
            confidence = round(pred["score"], 4)
            results.append({
                "cwe_id":      cwe_id,
                "description": CWE_DESCRIPTIONS.get(cwe_id, "Unknown"),
                "severity":    SEVERITY_MAP.get(cwe_id, "UNKNOWN"),
                "confidence":  confidence,
            })

        top1 = results[0]

        # Warn if top1 is a known unreliable class
        warning = None
        if top1["cwe_id"] in LOW_CONFIDENCE_CWES:
            warning = (
                f"{top1['cwe_id']} has limited training data — "
                f"confidence may be unreliable. Review top-3 predictions."
            )

        # Also warn if top1 confidence is low
        if top1["confidence"] < 0.5 and warning is None:
            warning = (
                f"Low confidence ({top1['confidence']:.0%}) — "
                f"input may not match known vulnerability patterns."
            )

        return {
            "top1":       top1,
            "top3":       results,
            "warning":    warning,
            "raw_scores": {p["label"]: round(p["score"], 4) for p in predictions},
        }


# ── Module-level singleton ───────────────────────────────────────────────────

_classifier: Optional[CWEClassifier] = None

def get_classifier() -> CWEClassifier:
    """Return the module-level singleton classifier."""
    global _classifier
    if _classifier is None:
        _classifier = CWEClassifier()
    return _classifier


def classify(text: str) -> dict:
    """Convenience function — classify without instantiating manually."""
    return get_classifier().classify(text)


# ── CLI test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_cases = [
        "This function constructs a SQL query by concatenating user-controlled input without parameterization, which may allow an attacker to inject arbitrary SQL commands.",
        "This function reflects user-supplied data into the HTTP response without encoding, which may allow an attacker to inject malicious scripts.",
        "This function performs operations on a memory buffer without verifying bounds, which may allow an attacker to read or write out-of-bounds memory.",
    ]

    clf = CWEClassifier()
    for text in test_cases:
        result = clf.classify(text)
        print(f"Input: {text[:60]}...")
        print(f"  Top-1: {result['top1']['cwe_id']} ({result['top1']['severity']}) — {result['top1']['confidence']:.1%}")
        if result["warning"]:
            print(f"  ⚠ {result['warning']}")
        print()
