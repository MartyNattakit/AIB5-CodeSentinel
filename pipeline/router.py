"""
pipeline/router.py
The glue layer — routes input through the correct models and returns
a unified output card. This is the only file that knows about all three
pipeline components.

Input:  raw user input (str) — code, CVE text, bug report, anything
Output: unified result dict (see OutputCard schema in api/schemas.py)
"""

from __future__ import annotations
import re
import time
from typing import Optional

# ── ATLAS signal keywords ─────────────────────────────────────────────────────
# If any of these appear in the raw input, run the ATLAS matcher in parallel

ATLAS_SIGNALS = {
    # Model-related
    "model", "llm", "language model", "neural network", "neural net",
    "transformer", "embedding", "embeddings", "inference", "training data",
    "fine-tun", "fine_tun", "finetun",
    # Attack-related
    "prompt injection", "prompt engineer", "jailbreak", "adversarial",
    "data poison", "model inversion", "membership inference", "model extraction",
    "model stealing", "backdoor", "trojan",
    # Infrastructure
    "api key", "openai", "anthropic", "huggingface", "ollama", "vector db",
    "vector database", "chromadb", "rag", "retrieval", "mcp server",
    "model registry", "mlflow", "weights", "checkpoint", "safetensor",
    # General AI/ML
    "machine learning", "deep learning", "gradient", "loss function",
    "classifier", "tokenizer", "attention", "gpt", "bert", "claude", "gemini",
}

# ── Code detection heuristics ─────────────────────────────────────────────────

CODE_PATTERNS = [
    r"def\s+\w+\s*\(",           # Python function
    r"function\s+\w+\s*\(",      # JS/PHP function
    r"void\s+\w+\s*\(",          # C/C++ void function
    r"int\s+\w+\s*\(",           # C/C++ int function
    r"public\s+\w+\s+\w+\s*\(",  # Java method
    r"private\s+\w+\s+\w+\s*\(", # Java private method
    r"#include\s*[<\"]",         # C/C++ include
    r"import\s+[\w.]+",          # Python/Java import
    r"require\s*\(",             # JS require
    r"SELECT\s+.+FROM",          # SQL (case insensitive checked below)
    r"<\?php",                   # PHP
    r"func\s+\w+\s*\(",          # Go function
    r"fn\s+\w+\s*\(",            # Rust function
]

_CODE_RE = re.compile("|".join(CODE_PATTERNS), re.IGNORECASE)

def _is_code(text: str) -> bool:
    """
    Heuristic: does this input look like source code?
    Checks for language-specific syntax patterns.
    """
    # Check structural signals
    if _CODE_RE.search(text):
        return True

    # Check for high density of code-like characters
    code_chars = sum(text.count(c) for c in "{}[]();")
    if len(text) > 0 and code_chars / len(text) > 0.05:
        return True

    # Check for indentation patterns (4-space or tab-indented blocks)
    lines = text.split("\n")
    indented = sum(1 for l in lines if l.startswith("    ") or l.startswith("\t"))
    if len(lines) > 3 and indented / len(lines) > 0.3:
        return True

    return False


def _has_atlas_signals(text: str) -> bool:
    """Check if input contains AI/ML attack-related keywords."""
    text_lower = text.lower()
    return any(signal in text_lower for signal in ATLAS_SIGNALS)


# ── Router ────────────────────────────────────────────────────────────────────

class Router:
    """
    Routes input through the correct pipeline components.

    Load order matters for memory:
    1. Classifier (RoBERTa, 125MB) — always loaded
    2. CodeAnalyzer (Qwen 7B, ~5GB) — loaded on first code input
    3. ATLASMatcher (RAG, lightweight) — loaded on first ATLAS signal
    """

    def __init__(self):
        self._classifier    = None
        self._code_analyzer = None
        self._atlas_matcher = None

    def _get_classifier(self):
        if self._classifier is None:
            from pipeline.classifier import CWEClassifier
            self._classifier = CWEClassifier()
        return self._classifier

    def _get_code_analyzer(self):
        if self._code_analyzer is None:
            from pipeline.code_analyzer import CodeAnalyzer
            self._code_analyzer = CodeAnalyzer()
        return self._code_analyzer

    def _get_atlas_matcher(self):
        if self._atlas_matcher is None:
            from pipeline.atlas_matcher import ATLASMatcher
            self._atlas_matcher = ATLASMatcher()
        return self._atlas_matcher

    def run(self, user_input: str) -> dict:
        """
        Main entry point. Routes input and returns a unified output card.

        Args:
            user_input: Raw text from the paste box — code, CVE, bug report.

        Returns:
            Unified output card dict (see OutputCard in api/schemas.py).
        """
        if not user_input or not user_input.strip():
            raise ValueError("Input cannot be empty.")

        start = time.time()

        # ── Step 1: Check for ATLAS signals on raw input FIRST ───────────────
        # Must run on raw input before any model touches it — Qwen might
        # paraphrase away AI/ML context
        run_atlas = _has_atlas_signals(user_input)

        # ── Step 2: Route based on input type ────────────────────────────────
        is_code = _is_code(user_input)

        if is_code:
            # Code path: Qwen → description → RoBERTa
            description = self._get_code_analyzer().analyze(user_input)
            input_type = "code"
        else:
            # Text path: directly to RoBERTa
            description = user_input
            input_type = "text"

        # ── Step 3: CWE classification ────────────────────────────────────────
        cwe_result = self._get_classifier().classify(description)

        # ── Step 4: ATLAS matching (conditional) ──────────────────────────────
        atlas_result = None
        if run_atlas:
            atlas_result = self._get_atlas_matcher().match(user_input)

        elapsed = round(time.time() - start, 2)

        # ── Step 5: Build unified output card ─────────────────────────────────
        return _build_output_card(
            raw_input=user_input,
            input_type=input_type,
            description=description,
            cwe_result=cwe_result,
            atlas_result=atlas_result,
            elapsed_seconds=elapsed,
        )


def _build_output_card(
    raw_input: str,
    input_type: str,
    description: str,
    cwe_result: dict,
    atlas_result: Optional[dict],
    elapsed_seconds: float,
) -> dict:
    """
    Build the unified output card shown to the user.
    Schema mirrors api/schemas.py OutputCard.
    """
    top1 = cwe_result["top1"]

    card = {
        # What the user sees front-and-center
        "cwe_id":       top1["cwe_id"],
        "cwe_name":     top1["description"],
        "severity":     top1["severity"],
        "confidence":   top1["confidence"],

        # Explanation
        "description":  description,

        # Top-3 alternatives
        "alternatives": cwe_result["top3"][1:],  # exclude top1

        # ATLAS match (None if no AI/ML signals detected)
        "atlas_match":  atlas_result,

        # Metadata
        "input_type":   input_type,     # "code" or "text"
        "warning":      cwe_result.get("warning"),
        "elapsed_s":    elapsed_seconds,
    }

    return card


# ── Module-level singleton ────────────────────────────────────────────────────

_router: Optional[Router] = None

def get_router() -> Router:
    """Return the module-level singleton router."""
    global _router
    if _router is None:
        _router = Router()
    return _router


def route(user_input: str) -> dict:
    """Convenience function — route without instantiating manually."""
    return get_router().run(user_input)


# ── CLI test ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    test_inputs = [
        # Code input
        'def get_user(username):\n    query = "SELECT * FROM users WHERE name = \'" + username + "\'"\n    return db.execute(query)',

        # Text input
        "The login endpoint does not verify that the authenticated user has permission to access the requested resource.",

        # ATLAS signal input
        "The LLM API endpoint accepts user-supplied prompts without sanitization, allowing prompt injection attacks that bypass the system instructions.",
    ]

    router = Router()
    for inp in test_inputs:
        print(f"Input: {inp[:80]}...")
        result = router.run(inp)
        print(f"  Type:       {result['input_type']}")
        print(f"  CWE:        {result['cwe_id']} — {result['cwe_name']}")
        print(f"  Severity:   {result['severity']}")
        print(f"  Confidence: {result['confidence']:.1%}")
        if result["atlas_match"]:
            print(f"  ATLAS:      {result['atlas_match']['atlas_id']} — {result['atlas_match']['technique']}")
        if result["warning"]:
            print(f"  ⚠ {result['warning']}")
        print(f"  Time:       {result['elapsed_s']}s")
        print()
