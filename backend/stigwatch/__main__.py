"""Command line entry point (python -m stigwatch)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import benchmarks


def _cmd_benchmarks(args: argparse.Namespace) -> int:
    if getattr(args, "bench_cmd", None) == "import":
        try:
            target = benchmarks.import_zip(
                Path(args.file), Path(args.out) if args.out else None, args.source_url or ""
            )
            b = benchmarks.load_benchmark_file(target)
        except benchmarks.BenchmarkError as exc:
            print(f"import failed: {exc}", file=sys.stderr)
            return 1
        print(f"{benchmarks.summary_line(b)} -> {target}")
        return 0
    if args.check:
        directory = Path(args.dir) if args.dir else benchmarks.BUNDLED_DIR
        lines, problems = benchmarks.check_directory(directory)
        for line in lines:
            print(line)
        for p in problems:
            print(f"ERROR: {p}", file=sys.stderr)
        return 1 if problems else 0
    for bid in benchmarks.list_benchmarks():
        print(benchmarks.summary_line(benchmarks.load_benchmark(bid)))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="stigwatch")
    sub = parser.add_subparsers(dest="command")
    b = sub.add_parser("benchmarks", help="inspect, verify or import DISA STIG benchmarks")
    b.add_argument("--check", action="store_true", help="validate the committed catalog")
    b.add_argument("--dir", help="catalog directory for --check (default: bundled)")
    bsub = b.add_subparsers(dest="bench_cmd")
    imp = bsub.add_parser("import", help="import a DISA STIG zip into the local data dir")
    imp.add_argument("file", help="path to the DISA STIG .zip")
    imp.add_argument("--out", help="output directory (default: STIGWATCH_DATA_DIR/benchmarks)")
    imp.add_argument("--source-url", help="where the zip was downloaded from")
    b.set_defaults(func=_cmd_benchmarks)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
