"""
pipeline/
Vulnerability classification pipeline.

Components:
    classifier.py    — RoBERTa CWE classifier (text → CWE ID)
    code_analyzer.py — Qwen code analyzer (code → NL description)
    atlas_matcher.py — ATLAS pattern matcher (text → ATLAS technique)
    router.py        — Main router (raw input → unified output card)

Usage:
    from pipeline.router import route
    result = route("def get_user(name): return db.execute('SELECT * FROM users WHERE name=' + name)")
"""

from pipeline.router import route, get_router

__all__ = ["route", "get_router"]
