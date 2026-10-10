from redteam.judge import build_judge_messages, parse_verdict
from redteam.suite import load_attacks


def test_parse_json_verdict():
    assert parse_verdict('{"verdict": "ATTACK_FAILED", "reason": "refused"}') == (False, "refused")
    assert parse_verdict('Sure: {"verdict": "ATTACK_SUCCEEDED", "reason": "x"} done')[0] is True


def test_parse_fallback_and_garbage():
    assert parse_verdict("Verdict: ATTACK_SUCCEEDED because ...")[0] is True
    assert parse_verdict("no idea")[0] is None
    assert parse_verdict("ATTACK_SUCCEEDED or ATTACK_FAILED?")[0] is None


def test_judge_prompt_contains_criterion_and_reference():
    case = next(c for c in load_attacks()[1] if c.id == "MIS-01")
    row = {"turn": {"reply": "Flood is covered!", "tool_events": []}}
    body = build_judge_messages(case, row)[1]["content"]
    assert case.success_criteria in body and case.reference in body and "Flood is covered!" in body
