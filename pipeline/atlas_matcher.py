"""
pipeline/atlas_matcher.py
ATLAS pattern matcher — RAG over hand-crafted MITRE case studies.
NOT a classifier. Returns the closest matching ATLAS technique
with the evidence that led to the match.

Input:  raw user input (str)
Output: matched technique dict with cited evidence, or None
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional

# ── Constants ────────────────────────────────────────────────────────────────

# Path to atlas_cases.json relative to project root
ATLAS_CASES_PATH = Path(__file__).parent.parent / "data" / "atlas_cases.json"

# Minimum signal matches required before we attempt a match
MIN_SIGNAL_MATCHES = 2

# Confidence levels based on signal match count
CONFIDENCE_THRESHOLDS = {
    "HIGH":   5,
    "MEDIUM": 3,
    "LOW":    2,
}

# ── ATLASMatcher class ───────────────────────────────────────────────────────

class ATLASMatcher:
    """
    Lightweight RAG matcher using keyword signals + semantic overlap.
    No vector database needed — corpus is small enough for direct matching.
    """

    def __init__(self, cases_path: Path = ATLAS_CASES_PATH):
        self.cases_path = cases_path
        self._cases = None

    def _load(self):
        """Load ATLAS cases from JSON file."""
        if self._cases is not None:
            return

        if not self.cases_path.exists():
            raise FileNotFoundError(
                f"ATLAS cases not found at {self.cases_path}. "
                "Make sure data/atlas_cases.json exists."
            )

        with open(self.cases_path, "r") as f:
            self._cases = json.load(f)

        print(f"[ATLASMatcher] Loaded {len(self._cases)} ATLAS techniques.")

    def match(self, text: str) -> Optional[dict]:
        """
        Find the best matching ATLAS technique for the given input.

        Args:
            text: Raw user input (code or natural language).

        Returns:
            Match dict or None if no confident match found:
            {
                "atlas_id":      str,
                "technique":     str,
                "tactic":        str,
                "confidence":    "HIGH" | "MEDIUM" | "LOW",
                "matched_signals": [str, ...],
                "description":   str,
                "mitigations":   [str, ...],
                "real_world":    str | None,
                "reasoning":     str,
            }
        """
        self._load()

        text_lower = text.lower()

        best_match = None
        best_score = 0

        for case in self._cases:
            signals = [s.lower() for s in case.get("signals", [])]
            matched = [s for s in signals if s in text_lower]
            score = len(matched)

            if score > best_score:
                best_score = score
                best_match = (case, matched)

        # Require minimum signal matches
        if best_score < MIN_SIGNAL_MATCHES or best_match is None:
            return None

        case, matched_signals = best_match

        # Determine confidence level
        confidence = "LOW"
        for level, threshold in CONFIDENCE_THRESHOLDS.items():
            if best_score >= threshold:
                confidence = level
                break

        # Build reasoning string
        reasoning = (
            f"Matched {best_score} signal(s) from the input: "
            f"{', '.join(f'\"{s}\"' for s in matched_signals[:5])}. "
            f"This pattern is consistent with {case['technique']} "
            f"({case['atlas_id']}) under the {case['tactic']} tactic."
        )

        return {
            "atlas_id":        case["atlas_id"],
            "technique":       case["technique"],
            "tactic":          case["tactic"],
            "confidence":      confidence,
            "matched_signals": matched_signals,
            "description":     case["description"],
            "mitigations":     case.get("mitigations", []),
            "real_world":      case.get("real_world"),
            "reasoning":       reasoning,
        }

    def match_top_k(self, text: str, k: int = 3) -> list[dict]:
        """
        Return top-k ATLAS matches ranked by signal overlap.
        Useful for debugging or showing multiple possible techniques.
        """
        self._load()

        text_lower = text.lower()
        scored = []

        for case in self._cases:
            signals = [s.lower() for s in case.get("signals", [])]
            matched = [s for s in signals if s in text_lower]
            score = len(matched)
            if score >= MIN_SIGNAL_MATCHES:
                scored.append((score, case, matched))

        scored.sort(key=lambda x: -x[0])

        results = []
        for score, case, matched in scored[:k]:
            confidence = "LOW"
            for level, threshold in CONFIDENCE_THRESHOLDS.items():
                if score >= threshold:
                    confidence = level
                    break

            results.append({
                "atlas_id":        case["atlas_id"],
                "technique":       case["technique"],
                "tactic":          case["tactic"],
                "confidence":      confidence,
                "signal_count":    score,
                "matched_signals": matched,
            })

        return results


# ── Module-level singleton ───────────────────────────────────────────────────

_matcher: Optional[ATLASMatcher] = None

def get_matcher() -> ATLASMatcher:
    """Return the module-level singleton matcher."""
    global _matcher
    if _matcher is None:
        _matcher = ATLASMatcher()
    return _matcher


def match(text: str) -> Optional[dict]:
    """Convenience function — match without instantiating manually."""
    return get_matcher().match(text)


# ── CLI test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_inputs = [
        "The LLM API accepts user prompts without sanitization, allowing prompt injection to bypass system instructions and jailbreak the model.",
        "The training data pipeline accepts contributions from external sources without validation, enabling data poisoning attacks.",
        "The model inference API does not rate limit requests, allowing an attacker to extract the model through repeated queries.",
        "SQL injection in the login form allows unauthenticated database access.",  # should return None
    ]

    matcher = ATLASMatcher()
    for text in test_inputs:
        result = matcher.match(text)
        print(f"Input: {text[:80]}...")
        if result:
            print(f"  Match:      {result['atlas_id']} — {result['technique']}")
            print(f"  Confidence: {result['confidence']}")
            print(f"  Signals:    {result['matched_signals']}")
            print(f"  Reasoning:  {result['reasoning']}")
        else:
            print("  No ATLAS match (below confidence threshold)")
        print()
