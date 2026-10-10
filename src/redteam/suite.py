"""Load and validate the attack and benign suites."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SUITE_DIR = REPO_ROOT / "suite"

GRADER_TYPES = {
    "regex",
    "system_prompt_leak",
    "pii_leak",
    "tool_executed",
    "third_party_access",
    "consumption",
    "judge",
}


@dataclass
class AttackCase:
    id: str
    category: str
    technique: str
    prompt: str
    success_criteria: str
    graders: list[dict[str, Any]]
    owasp: list[str]
    atlas: list[str]
    history: list[dict[str, str]] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    reference: str | None = None

    @property
    def judge_only(self) -> bool:
        return all(g["type"] == "judge" for g in self.graders)


@dataclass
class BenignCase:
    id: str
    prompt: str
    expect_regex: list[str]
    expect_tool: str | None = None


def _build_prompt(raw: dict[str, Any]) -> str:
    if "prompt" in raw:
        return str(raw["prompt"]).strip()
    rep = raw["prompt_repeat"]
    return rep["prefix"] + rep["text"] * int(rep["times"]) + rep["suffix"]


def load_attacks(path: Path | None = None) -> tuple[dict[str, dict], list[AttackCase]]:
    data = yaml.safe_load((path or SUITE_DIR / "attacks.yaml").read_text(encoding="utf-8"))
    cats = data["categories"]
    cases: list[AttackCase] = []
    seen: set[str] = set()
    for raw in data["cases"]:
        cid = raw["id"]
        if cid in seen:
            raise ValueError(f"duplicate case id {cid}")
        seen.add(cid)
        cat = raw["category"]
        if cat not in cats:
            raise ValueError(f"{cid}: unknown category {cat}")
        for g in raw["graders"]:
            if g["type"] not in GRADER_TYPES:
                raise ValueError(f"{cid}: unknown grader {g['type']}")
        cases.append(
            AttackCase(
                id=cid,
                category=cat,
                technique=raw.get("technique", ""),
                prompt=_build_prompt(raw),
                success_criteria=str(raw["success_criteria"]).strip(),
                graders=raw["graders"],
                owasp=sorted(set(cats[cat]["owasp"] + raw.get("owasp_extra", []))),
                atlas=sorted(set(cats[cat]["atlas"] + raw.get("atlas_extra", []))),
                history=raw.get("history", []),
                attachments=raw.get("attachments", []),
                reference=raw.get("reference"),
            )
        )
    return cats, cases


def load_benign(path: Path | None = None) -> list[BenignCase]:
    data = yaml.safe_load((path or SUITE_DIR / "benign.yaml").read_text(encoding="utf-8"))
    return [
        BenignCase(
            id=c["id"], prompt=c["prompt"].strip(), expect_regex=c["expect_regex"], expect_tool=c.get("expect_tool")
        )
        for c in data["cases"]
    ]
