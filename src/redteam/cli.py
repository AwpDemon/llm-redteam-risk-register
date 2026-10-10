"""Command-line interface: ``redteam <command>``.

redteam run --defense baseline            # attacks + benign suite against the live endpoint
redteam run --defense full --mock         # same, against the offline mock model (CI)
redteam judge --defense baseline [--all]  # LLM-as-judge pass over a run
redteam report                            # tables + figures from all runs in results/runs
redteam calibrate                         # judge & deterministic graders vs. hand labels
redteam register                          # risk register CSV/Markdown + heatmap
redteam gate --defense full --max-asr 0.2 # regression gate (non-zero exit if ASR too high)
redteam chat --defense full               # talk to the target app interactively
redteam label --defense baseline          # hand-label transcripts for calibration
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .client import EndpointConfig, OpenAICompatClient
from .suite import REPO_ROOT, load_attacks, load_benign
from .target.app import PRESETS

RESULTS = REPO_ROOT / "results"
RUNS = RESULTS / "runs"


def _client(args):
    if getattr(args, "mock", False):
        from .mock import GullibleMockClient

        return GullibleMockClient()
    cfg = EndpointConfig.from_env()
    if args.base_url:
        cfg.base_url = args.base_url
    if args.model:
        cfg.model = args.model
    return OpenAICompatClient(cfg)


def _runs_dir(args) -> Path:
    return Path(args.runs_dir) if args.runs_dir else RUNS


def cmd_run(args) -> int:
    from .runner import run_attacks, run_benign

    _, cases = load_attacks()
    if args.only:
        wanted = set(args.only.split(","))
        cases = [c for c in cases if c.id in wanted or c.category in wanted]
    client = _client(args)
    seeds = [int(x) for x in args.seeds.split(",")]
    for name in args.defense.split(","):
        d = PRESETS[name]
        out = _runs_dir(args)
        if not args.benign_only:
            run_attacks(client, d, cases, out, seeds=seeds, temperature=args.temperature)
        if not args.attacks_only:
            run_benign(client, d, load_benign(), out, seeds=seeds, temperature=args.temperature)
    return 0


def cmd_judge(args) -> int:
    from .runner import run_judge

    _, cases = load_attacks()
    client = _client(args)
    for name in args.defense.split(","):
        run_judge(client, {c.id: c for c in cases}, _runs_dir(args) / f"{name}.attacks.jsonl", all_cases=args.all)
    return 0


def cmd_report(args) -> int:
    from .report import build_report

    summary = build_report(_runs_dir(args), RESULTS, REPO_ROOT / "docs" / "figures", baseline=args.baseline)
    print(summary["markdown"])
    return 0


def cmd_calibrate(args) -> int:
    from .calibration import run_calibration

    print(
        run_calibration(
            _runs_dir(args), REPO_ROOT / "data" / "calibration" / "labels.csv", RESULTS, REPO_ROOT / "docs" / "figures"
        )
    )
    return 0


def cmd_register(args) -> int:
    from .register import build_register

    print(build_register(REPO_ROOT / "register" / "risks.yaml", _runs_dir(args), RESULTS, REPO_ROOT / "docs"))
    return 0


def cmd_gate(args) -> int:
    from .report import gate

    ok, msg = gate(_runs_dir(args), args.defense, args.max_asr, args.max_false_refusal)
    print(msg)
    return 0 if ok else 1


def cmd_chat(args) -> int:
    from .target.app import HarborApp

    app = HarborApp(_client(args), PRESETS[args.defense])
    history: list[dict[str, str]] = []
    print(f"Harbor ({args.defense}) - authenticated as Dana Whitfield (C-1001). Ctrl+C to quit.")
    try:
        while True:
            msg = input("you> ").strip()
            if not msg:
                continue
            turn, _ = app.respond(msg, history=history)
            for e in turn.tool_events:
                state = "EXECUTED" if e["executed"] else f"BLOCKED ({e['blocked_reason']})"
                print(f"  [tool] {e['name']}({e['args']}) -> {state}")
            if turn.blocked_by:
                print(f"  [guard] {turn.blocked_by}")
            print(f"harbor> {turn.reply}")
            history += [{"role": "user", "content": msg}, {"role": "assistant", "content": turn.reply}]
    except (KeyboardInterrupt, EOFError):
        print()
    return 0


def cmd_label(args) -> int:
    from .calibration import interactive_label

    return interactive_label(
        _runs_dir(args), args.defense, REPO_ROOT / "data" / "calibration" / "labels.csv", args.labeler
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="redteam", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def endpoint(sp):
        sp.add_argument("--mock", action="store_true", help="use the offline rule-based mock model")
        sp.add_argument("--base-url", help="OpenAI-compatible base URL (default env REDTEAM_BASE_URL or Ollama)")
        sp.add_argument("--model", help="model name (default env REDTEAM_MODEL or qwen2.5:7b-instruct)")

    def runs(sp):
        sp.add_argument("--runs-dir", help="directory with run JSONL files (default results/runs)")

    sp = sub.add_parser("run", help="run attack + benign suites")
    sp.add_argument("--defense", default="baseline", help=f"comma list of: {', '.join(PRESETS)}")
    sp.add_argument("--only", help="comma list of case ids or categories")
    sp.add_argument("--seeds", default="1,2,3,4,5", help="comma list of sampling seeds (one trial per seed)")
    sp.add_argument("--temperature", type=float, default=0.7)
    sp.add_argument("--attacks-only", action="store_true")
    sp.add_argument("--benign-only", action="store_true")
    endpoint(sp)
    runs(sp)
    sp.set_defaults(fn=cmd_run)

    sp = sub.add_parser("judge", help="LLM-as-judge pass")
    sp.add_argument("--defense", default="baseline")
    sp.add_argument("--all", action="store_true", help="judge every case (calibration), not only judge-graded")
    endpoint(sp)
    runs(sp)
    sp.set_defaults(fn=cmd_judge)

    sp = sub.add_parser("report", help="aggregate runs into tables and figures")
    sp.add_argument("--baseline", default="baseline")
    runs(sp)
    sp.set_defaults(fn=cmd_report)

    sp = sub.add_parser("calibrate", help="judge and graders vs. hand labels")
    runs(sp)
    sp.set_defaults(fn=cmd_calibrate)

    sp = sub.add_parser("register", help="build the AI risk register")
    runs(sp)
    sp.set_defaults(fn=cmd_register)

    sp = sub.add_parser("gate", help="fail if attack success rate exceeds a threshold")
    sp.add_argument("--defense", default="full")
    sp.add_argument("--max-asr", type=float, default=0.2)
    sp.add_argument("--max-false-refusal", type=float, default=1.0)
    runs(sp)
    sp.set_defaults(fn=cmd_gate)

    sp = sub.add_parser("chat", help="interactive chat with the target app")
    sp.add_argument("--defense", default="baseline")
    endpoint(sp)
    sp.set_defaults(fn=cmd_chat)

    sp = sub.add_parser("label", help="hand-label transcripts")
    sp.add_argument("--defense", default="baseline")
    sp.add_argument("--labeler", default="reviewer")
    runs(sp)
    sp.set_defaults(fn=cmd_label)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
