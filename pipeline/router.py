"""
pipeline/router.py
The glue layer — routes input through the correct models and returns
a unified output card. This is the only file that knows about all three
pipeline components.
"""

from __future__ import annotations
import re
import time
from typing import Optional

# ── ATLAS signal keywords ─────────────────────────────────────────────────────

ATLAS_SIGNALS = {
    "model", "llm", "language model", "neural network", "neural net",
    "transformer", "embedding", "embeddings", "inference", "training data",
    "fine-tun", "fine_tun", "finetun",
    "prompt injection", "prompt engineer", "jailbreak", "adversarial",
    "data poison", "model inversion", "membership inference", "model extraction",
    "model stealing", "backdoor", "trojan",
    "api key", "openai", "anthropic", "huggingface", "ollama", "vector db",
    "vector database", "chromadb", "rag", "retrieval", "mcp server",
    "model registry", "mlflow", "weights", "checkpoint", "safetensor",
    "machine learning", "deep learning", "gradient", "loss function",
    "classifier", "tokenizer", "attention", "gpt", "bert", "claude", "gemini",
}

# ── Code detection heuristics ─────────────────────────────────────────────────

CODE_PATTERNS = [
    r"def\s+\w+\s*\(",
    r"function\s+\w+\s*\(",
    r"void\s+\w+\s*\(",
    r"int\s+\w+\s*\(",
    r"public\s+\w+\s+\w+\s*\(",
    r"private\s+\w+\s+\w+\s*\(",
    r"#include\s*[<\"]",
    r"import\s+[\w.]+",
    r"require\s*\(",
    r"SELECT\s+.+FROM",
    r"<\?php",
    r"func\s+\w+\s*\(",
    r"fn\s+\w+\s*\(",
]

_CODE_RE = re.compile("|".join(CODE_PATTERNS), re.IGNORECASE)

def _is_code(text: str) -> bool:
    if _CODE_RE.search(text):
        return True
    code_chars = sum(text.count(c) for c in "{}[]();")
    if len(text) > 0 and code_chars / len(text) > 0.05:
        return True
    lines = text.split("\n")
    indented = sum(1 for l in lines if l.startswith("    ") or l.startswith("\t"))
    if len(lines) > 3 and indented / len(lines) > 0.3:
        return True
    return False


def _has_atlas_signals(text: str) -> bool:
    text_lower = text.lower()
    return any(signal in text_lower for signal in ATLAS_SIGNALS)


# ── Router ────────────────────────────────────────────────────────────────────

class Router:
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
        if not user_input or not user_input.strip():
            raise ValueError("Input cannot be empty.")

        start = time.time()

        run_atlas = _has_atlas_signals(user_input)
        is_code   = _is_code(user_input)

        description = user_input
        input_type  = "text"
        code_analysis_warning = None

        if is_code:
            try:
                description = self._get_code_analyzer().analyze(user_input)
                input_type  = "code"
            except Exception as e:
                error_str = str(e).lower()
                if "cuda" in error_str or "bitsandbytes" in error_str or "gpu" in error_str:
                    description = user_input
                    input_type  = "code"
                    code_analysis_warning = (
                        "GPU not available — code passed directly to classifier. "
                        "For best results, describe the vulnerability in plain English."
                    )
                else:
                    raise

        cwe_result = self._get_classifier().classify(description)

        atlas_result = None
        if run_atlas:
            try:
                atlas_result = self._get_atlas_matcher().match(user_input)
            except Exception:
                pass

        elapsed = round(time.time() - start, 2)

        existing_warning = cwe_result.get("warning")
        if code_analysis_warning and existing_warning:
            final_warning = f"{code_analysis_warning} | {existing_warning}"
        elif code_analysis_warning:
            final_warning = code_analysis_warning
        else:
            final_warning = existing_warning

        return _build_output_card(
            raw_input=user_input,
            input_type=input_type,
            description=description,
            cwe_result=cwe_result,
            atlas_result=atlas_result,
            elapsed_seconds=elapsed,
            warning_override=final_warning,
        )


def _build_output_card(
    raw_input: str,
    input_type: str,
    description: str,
    cwe_result: dict,
    atlas_result: Optional[dict],
    elapsed_seconds: float,
    warning_override: Optional[str] = None,
) -> dict:
    top1 = cwe_result["top1"]

    return {
        "cwe_id":      top1["cwe_id"],
        "cwe_name":    top1["description"],
        "severity":    top1["severity"],
        "confidence":  top1["confidence"],
        "description": description,
        "alternatives": cwe_result["top3"][1:],
        "atlas_match": atlas_result,
        "input_type":  input_type,
        "warning":     warning_override if warning_override is not None else cwe_result.get("warning"),
        "elapsed_s":   elapsed_seconds,
    }


# ── Module-level singleton ────────────────────────────────────────────────────

_router: Optional[Router] = None

def get_router() -> Router:
    global _router
    if _router is None:
        _router = Router()
    return _router


def route(user_input: str) -> dict:
    return get_router().run(user_input)