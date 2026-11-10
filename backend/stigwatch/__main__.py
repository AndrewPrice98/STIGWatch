"""Command line entry point (python -m stigwatch)."""

from __future__ import annotations

import argparse
import json
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


MAX_COLLECTOR_BYTES = 32 * 1024 * 1024


def _read_collector(path: str) -> dict:
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"not a file: {path}")
    if p.stat().st_size > MAX_COLLECTOR_BYTES:
        raise ValueError("collector file is too large")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("collector output must be a JSON object")
    return data


def _cmd_collect_parse(args: argparse.Namespace) -> int:
    from .checks import engine

    try:
        data = _read_collector(args.file)
        module = engine.collector_module(data)
        if module.COLLECTOR != args.collector:
            raise ValueError(f"file is from the {data.get('collector')!r} collector, not {args.collector!r}")
        info = module.summary(data)
    except ValueError as exc:
        print(f"invalid collector file: {exc}", file=sys.stderr)
        return 1
    print(f"host {info['host']} collected {info['collected_at']}: {info['ok']} of {info['facts']} facts read")
    for fid, reason in sorted(info["unavailable"].items()):
        print(f"  unavailable  {fid}: {reason}")
    for fid in info["missing"]:
        print(f"  missing      {fid}")
    for fid in info["unknown"]:
        print(f"  unknown      {fid} (ignored)")
    status = 0
    if args.min_ok is not None and info["ok"] < args.min_ok:
        print(f"only {info['ok']} facts read; at least {args.min_ok} required", file=sys.stderr)
        status = 1
    required = [f.strip() for f in (args.require or "").split(",") if f.strip()]
    not_read = [f for f in required if f not in info["read"]]
    if not_read:
        print("required facts not read: " + ", ".join(not_read), file=sys.stderr)
        status = 1
    return status


def _cmd_scan(args: argparse.Namespace) -> int:
    from .checks import engine

    try:
        data = _read_collector(args.file)
        bench = benchmarks.load_benchmark(args.benchmark) if args.benchmark else None
        results = engine.evaluate(data, bench)
        if bench is None:
            bench = benchmarks.load_benchmark(engine.collector_module(data).BENCHMARK)
    except (ValueError, benchmarks.BenchmarkError) as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        return 1
    counts = engine.status_counts(results)
    host = data.get("host", {}).get("name")
    print(f"{host}: {bench.benchmark_id} {bench.label}, {len(results)} rules")
    for status, n in counts.items():
        print(f"  {status:15} {n}")
    by_id = {r.stig_id: r for r in bench.rules}
    for cat in ("CAT I", "CAT II", "CAT III"):
        opens = [r for r in results if r.status == engine.OPEN and by_id[r.stig_id].cat == cat]
        if not opens:
            continue
        print(f"Open {cat} ({len(opens)}):")
        for r in opens:
            print(f"  {r.stig_id}  {by_id[r.stig_id].title[:90]}")
    return 0


def _cmd_coverage(args: argparse.Namespace) -> int:
    from .checks import engine

    try:
        lines = engine.coverage_lines(args.benchmark)
    except (ValueError, benchmarks.BenchmarkError) as exc:
        print(f"coverage failed: {exc}", file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    return 0


def _read_password(args: argparse.Namespace) -> str:
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        import getpass

        password = getpass.getpass("Admin password: ")
        if password != getpass.getpass("Repeat password: "):
            sys.exit("Passwords do not match.")
    if len(password) < 12:
        sys.exit("Use at least 12 characters.")
    return password


def _update_env_file(path: Path, values: dict[str, str]) -> None:
    """Set keys in a .env file, keeping any other lines as they are."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = dict(values)
    out = []
    for line in lines:
        key = line.split("=", 1)[0].strip()
        if key in remaining:
            out.append(f"{key}={remaining.pop(key)}")
        else:
            out.append(line)
    out += [f"{k}={v}" for k, v in remaining.items()]
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def _cmd_create_admin(args: argparse.Namespace) -> int:
    import secrets

    from . import config
    from .auth import hash_password

    password = _read_password(args)
    values = {
        "STIGWATCH_ADMIN_USER": args.username,
        "STIGWATCH_ADMIN_PASSWORD_HASH": hash_password(password),
        # Reuse an existing secret so current sessions stay valid, unless asked to rotate.
        "STIGWATCH_SECRET_KEY": (config.secret_key() if config.secret_key() and not args.rotate_secret
                                 else secrets.token_urlsafe(48)),
    }
    if args.print:
        print("Set these environment variables on your host. Keep them secret.\n")
        for key, value in values.items():
            print(f"{key}={value}")
        print("STIGWATCH_TRUST_PROXY=true")
        return 0
    _update_env_file(config.ENV_FILE, {**values, "STIGWATCH_COOKIE_SECURE": "false"})
    print(f"Admin '{args.username}' saved to {config.ENV_FILE} (git-ignored).")
    print("Restart the API to pick it up. For a hosted deployment, run again with --print.")
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

    cp = sub.add_parser("collect-parse", help="validate a collector file and summarise its facts")
    cp.add_argument("collector", choices=["linux", "windows"], help="collector type")
    cp.add_argument("file", help="collector JSON file")
    cp.add_argument("--min-ok", type=int, help="fail when fewer facts were read")
    cp.add_argument("--require", help="comma-separated fact ids that must have been read")
    cp.set_defaults(func=_cmd_collect_parse)

    sc = sub.add_parser("scan", help="evaluate a collector file against its benchmark")
    sc.add_argument("file", help="collector JSON file")
    sc.add_argument("--benchmark", help="benchmark id (default: the collector's benchmark)")
    sc.set_defaults(func=_cmd_scan)

    cv = sub.add_parser("coverage", help="automated and manual rule counts by CAT")
    cv.add_argument("benchmark", help="benchmark id, e.g. ubuntu-22.04")
    cv.set_defaults(func=_cmd_coverage)

    admin = sub.add_parser("create-admin", help="set the dashboard login (writes backend/.env)")
    admin.add_argument("--username", default="admin")
    admin.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    admin.add_argument("--print", action="store_true",
                       help="print the variables for a hosting provider instead of writing .env")
    admin.add_argument("--rotate-secret", action="store_true", help="new signing secret (logs everyone out)")
    admin.set_defaults(func=_cmd_create_admin)
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
