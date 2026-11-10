"""Write the generated remediation for the demo fleet into a directory (used by CI).

    python scripts/generate_remediation_samples.py OUT_DIR

For every demo host it writes the Ansible playbook (Linux) or PowerShell script (Windows)
for the host's latest scan, and for each benchmark one file in which every rule is open, so
every generator path is exercised. CI parses the .ps1 files with the PowerShell AST and runs
them in their default dry-run mode; nothing here applies anything.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from stigwatch import benchmarks, config, db, demo, remediation  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    out = Path(argv[1])
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        conn = db.connect(Path(tmp) / "demo.db")
        demo.seed(conn)
        for host in db.list_hosts(conn):
            scan = db.list_scans(conn, host["id"])[-1]
            opens = [r for r in db.scan_results(conn, scan["id"]) if r["status"] == "Open"]
            bench = demo.bundled_benchmark(host["benchmark_id"])
            if host["os"] == "linux":
                text, name = remediation.ansible_playbook(host, opens, bench), f"{host['name']}.yml"
            else:
                text, name = remediation.powershell_script(
                    host, opens, bench,
                    domain_role=remediation.domain_role_of(db.get_raw(conn, scan["id"]))), f"{host['name']}.ps1"
            (out / name).write_text(text, encoding="utf-8", newline="\n")
        conn.close()
    for bid, ext, fn in (("ubuntu-22.04", "yml", remediation.ansible_playbook),
                         ("windows-server-2022", "ps1", remediation.powershell_script)):
        bench = demo.bundled_benchmark(bid)
        everything = [{"stig_id": r.stig_id, "status": "Open"} for r in bench.rules]
        (out / f"all-rules-{bid}.{ext}").write_text(
            fn({"name": "all-rules"}, everything, bench), encoding="utf-8", newline="\n")
    print(f"wrote {len(list(out.iterdir()))} files to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
