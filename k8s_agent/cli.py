"""
Command-line interface for the Kubernetes Log Investigation Agent.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent import KubernetesInvestigationAgent
from .formatters import render_markdown, render_terminal


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Kubernetes Log Investigation Agent: Analyzes k8s logs and produces evidence-backed reports."
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default=None,
        help="Path to the Kubernetes log file to investigate (reads from stdin if omitted).",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="file_opt",
        help="Alternative flag to specify log file path.",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "markdown", "json"],
        default="terminal",
        help="Output format (default: terminal).",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Save report to specified output file.",
    )
    parser.add_argument(
        "--context",
        type=int,
        default=1,
        help="Number of context lines surrounding each evidence line (default: 1).",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Enable Gemini LLM augmentation (requires GEMINI_API_KEY).",
    )
    parser.add_argument(
        "--demo",
        choices=["oom", "probe", "dns", "rbac", "json"],
        help="Run investigation on a built-in Kubernetes incident sample.",
    )
    return parser


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()

    agent = KubernetesInvestigationAgent(
        context_window=args.context,
        enable_llm=args.llm,
    )

    log_path = args.file_opt or args.logfile

    if args.demo:
        demo_dir = Path(__file__).resolve().parent.parent / "sample_logs"
        demo_file_map = {
            "oom": demo_dir / "oom_killed.log",
            "probe": demo_dir / "crashloop_probe.log",
            "dns": demo_dir / "dns_network_failure.log",
            "rbac": demo_dir / "rbac_permission_denied.log",
            "json": demo_dir / "json_microservice_crash.log",
        }
        target = demo_file_map.get(args.demo)
        if not target or not target.exists():
            print(f"Error: Demo file {target} does not exist.", file=sys.stderr)
            return 1
        report = agent.investigate_file(target)
    elif log_path:
        path = Path(log_path)
        if not path.exists():
            print(f"Error: Log file not found: {log_path}", file=sys.stderr)
            return 1
        report = agent.investigate_file(path)
    elif not sys.stdin.isatty():
        # Reading from piped stdin
        content = sys.stdin.read()
        if not content.strip():
            print("Error: Stdin was empty.", file=sys.stderr)
            return 1
        report = agent.investigate_text(content)
    else:
        parser.print_help()
        print("\nTip: Pass a log file, pipe via stdin, or run with --demo oom", file=sys.stderr)
        return 1

    # Format the report
    if args.format == "json":
        output_text = report.to_json(indent=2)
    elif args.format == "markdown":
        output_text = render_markdown(report)
    else:
        output_text = render_terminal(report, color=True)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(output_text, encoding="utf-8")
        print(f"Investigation report saved to {out_path}")
    else:
        print(output_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
