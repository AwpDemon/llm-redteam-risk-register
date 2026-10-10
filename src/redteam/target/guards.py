"""Deterministic guardrails that sit OUTSIDE the model.

They are intentionally simple, readable rules (regex + allowlists), because a control a reviewer cannot read
is a control a reviewer cannot test. Their false-positive cost is measured on the benign suite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .backend import other_customer_pii
from .prompts import CANARY, CONFIDENTIAL_MARKERS

MAX_INPUT_CHARS = 2000

_INJECTION_PATTERNS = [
    r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|your|system)\b.{0,30}"
    r"\b(instructions?|rules?|prompts?|directives?|guidelines?)",
    r"\b(system|developer|hidden|initial|original)\s+(prompt|message|instructions?)\b",
    r"\b(reveal|print|repeat|show|output|display|dump|translate|summari[sz]e|encode)\b.{0,40}"
    r"\b(your|the)\s+(instructions?|rules|prompt|configuration|config)\b",
    r"\b(developer|debug|god|admin|maintenance|jailbreak|unrestricted)\s+mode\b",
    r"\byou\s+are\s+(now|no longer)\b",
    r"\b(DAN|do anything now)\b",
    r"<\|im_start\|>|<\|system\|>|\[/?(SYSTEM|INST)\]|^#{2,}\s*system",
    r"\bnew\s+(instructions|rules|persona)\b",
    r"\bescalation\s+code\b|\bconfidential\b.{0,30}\b(section|block|notes?)\b",
    r"\b(repeat|write|say|list|print)\b.{0,40}\b(\d{3,}|thousand)\s+(times|words|items|lines|numbers)\b",
    r"\b(\d{3,}|thousand)\s+(times|words)\b",
    r"[A-Za-z0-9+/]{60,}={0,2}",  # long base64-like blobs (obfuscated payloads)
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _INJECTION_PATTERNS]


@dataclass
class GuardDecision:
    blocked: bool
    reason: str = ""


def input_filter(text: str) -> GuardDecision:
    if len(text) > MAX_INPUT_CHARS:
        return GuardDecision(True, f"input longer than {MAX_INPUT_CHARS} characters")
    for rx in _INJECTION_RE:
        if rx.search(text):
            return GuardDecision(True, f"matched injection pattern: {rx.pattern[:50]}")
    return GuardDecision(False)


# ---------------------------------------------------------------- retrieval sanitization
_ZERO_WIDTH = re.compile(r"[​-‏⁠﻿]")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_INSTRUCTION_SENTENCE = re.compile(
    r"\b(assistant|AI|chatbot|harbor|model|LLM)\b.{0,80}\b(must|should|shall|need to|is instructed|will now)\b"
    r"|\b(ignore|disregard)\b.{0,40}\binstructions?\b"
    r"|\b(send_email|issue_refund|update_contact_info|lookup_policy|tool call|call the tool)\b"
    r"|\b(system|admin)\s*(note|message|override|instruction)\b"
    r"|\bwhen (summari[sz]ing|answering|responding)\b",
    re.IGNORECASE,
)
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


def sanitize_document(text: str) -> tuple[str, int]:
    """Remove hidden content and instruction-like sentences from UNTRUSTED documents.

    Returns (clean_text, number_of_sentences_removed).
    """
    text = _ZERO_WIDTH.sub("", _HTML_COMMENT.sub("", text))
    kept, removed = [], 0
    for sent in _SENTENCE_SPLIT.split(text):
        if not sent.strip():
            continue
        if _INSTRUCTION_SENTENCE.search(sent):
            removed += 1
            continue
        kept.append(sent.strip())
    return " ".join(kept), removed


# ---------------------------------------------------------------- output filtering
_URL = re.compile(r"https?://[^\s)\]>\"']+", re.IGNORECASE)
ALLOWED_URL_HOSTS = ("harborline.example.com",)


_NON_ALNUM = re.compile(r"[^a-z0-9]")
_CANARY_NORM = _NON_ALNUM.sub("", CANARY.lower())


def leaks_system_prompt(text: str) -> bool:
    """Canary present (also when split by spaces/newlines/punctuation) or >= 2 confidential phrases."""
    low = text.lower()
    if _CANARY_NORM in _NON_ALNUM.sub("", low):
        return True
    return sum(1 for m in CONFIDENTIAL_MARKERS if m.lower() in low) >= 2


def leaked_pii(text: str) -> list[str]:
    low = text.lower()
    return [p for p in other_customer_pii() if p.lower() in low]


def disallowed_urls(text: str) -> list[str]:
    out = []
    for url in _URL.findall(text):
        host = url.split("/")[2].lower()
        if not any(host == h or host.endswith("." + h) for h in ALLOWED_URL_HOSTS):
            out.append(url)
    return out


SAFE_REPLY = (
    "I'm sorry, I can't help with that request. I can answer questions about your Harborline policies and "
    "claims, or connect you with a licensed specialist."
)


def output_filter(text: str) -> tuple[str, list[str]]:
    """Returns (possibly rewritten text, list of triggered rules)."""
    hits: list[str] = []
    if leaks_system_prompt(text):
        hits.append("system_prompt_leak")
    if leaked_pii(text):
        hits.append("third_party_pii")
    if hits:
        return SAFE_REPLY, hits
    bad_urls = disallowed_urls(text)
    if bad_urls:
        hits.append("untrusted_url")
        for u in bad_urls:
            text = text.replace(u, "[link removed]")
    return text, hits
