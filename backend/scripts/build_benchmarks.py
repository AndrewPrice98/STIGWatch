"""Maintainer tool: build (or verify) the committed benchmark catalog from DISA zips.

    python scripts/build_benchmarks.py ZIP [ZIP ...]           # write data/benchmarks/*.json
    python scripts/build_benchmarks.py --check ZIP [ZIP ...]   # rebuild and compare, exit 1 on diff

CI cannot download the zips, so CI runs `python -m stigwatch benchmarks --check`, which
validates the committed JSON's integrity. This script is the local rebuild check.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from stigwatch import benchmarks as bm  # noqa: E402

BASE = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
SOURCE_URLS = {
    "ubuntu-22.04": BASE + "U_CAN_Ubuntu_22-04_LTS_V{v}R{r}_STIG.zip",
    "windows-server-2022": BASE + "U_MS_Windows_Server_2022_V{v}R{r}_STIG.zip",
}


def build(zip_path: Path) -> dict:
    data = bm.build_from_zip(zip_path)
    tmpl = SOURCE_URLS.get(data["benchmark_id"])
    if tmpl:
        data["source_url"] = tmpl.format(v=data["version"], r=data["release"])
    return data


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--out", default=str(bm.BUNDLED_DIR))
    ap.add_argument("zips", nargs="+")
    args = ap.parse_args()
    out = Path(args.out)
    rc = 0
    for z in args.zips:
        data = build(Path(z))
        target = out / f"{data['benchmark_id']}.json"
        text = bm.dumps(data)
        if args.check:
            current = target.read_text(encoding="utf-8") if target.is_file() else None
            if current != text:
                print(f"DIFF: {target} differs from a rebuild of {z}", file=sys.stderr)
                rc = 1
            else:
                print(f"ok: {target.name} matches {Path(z).name}")
        else:
            out.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {target}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
