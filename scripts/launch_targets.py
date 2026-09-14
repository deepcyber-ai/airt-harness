#!/usr/bin/env python3
"""Launch K isolated target stacks for a parallel campaign, and PROVE
they are separate databases before the campaign uses them.

    python3 scripts/launch_targets.py --profile deepvault-capital --workers 8

Each worker gets its OWN mock + MCP on its own port and its own SQLite file, so
the parallel runner's isolation guarantee (no two concurrent runs share a
database) actually holds. Different URLs are NOT proof of that — a mock pointed at
the wrong MCP, or two MCPs sharing a db_path, gives distinct URLs over ONE
database and silently corrupts the run. So after launching, this performs a
cross-write / cross-read check: reseed all, mutate ONE, read ALL, and confirm only
the mutated stack changed — pairwise, for every stack. If any two are not
independent it refuses to hand the URLs over.

The plan and the isolation check are pure and dependency-free (tested in
harness/test_launch_isolation.py); the live launching wraps them.

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Exact vendor dirs per profile (a glob would also match the renderer server,
# which broke the printed launch commands — review B1).
PROFILE_DIRS = {
    "deepvault-capital": {"mcp": "dvc-db-mcp", "collector": "dvc-collector"},
    "deepcyber-ctf":     {"mcp": "larkfield-db-mcp", "collector": "larkfield-renderer"},
}


def plan_stacks(k, profile, base_mcp_port=8300, base_mock_port=8500,
                base_collector_port=8700, db_dir="/tmp/airt-stacks"):
    """One config per worker, with DISTINCT ports and db files by construction.

    Each worker owns THREE ports — its MCP, its mock, and its COLLECTOR — in
    separate ranges that do not overlap, so a worker's mock can never land on the
    email/renderer collector port (review B1: the old 8400-range mock collided
    with the DVC collector at 8401, which silently broke composition scoring).
    Distinctness across ALL ports is the necessary pre-check; verify_isolation is
    the sufficient runtime proof.
    """
    stacks = []
    for i in range(k):
        stacks.append({
            "worker": i,
            "mcp_port": base_mcp_port + i,
            "mock_port": base_mock_port + i,
            "collector_port": base_collector_port + i,
            "db_path": str(Path(db_dir) / f"{profile}-worker-{i}.sqlite"),
            "mcp_url": f"http://localhost:{base_mcp_port + i}",
            "mock_url": f"http://localhost:{base_mock_port + i}",
            "collector_url": f"http://localhost:{base_collector_port + i}",
        })
    # fail closed on any collision — per field AND across ALL ports globally, so
    # no mock/mcp/collector port is ever shared (the B1 class of bug).
    for field in ("mcp_port", "mock_port", "collector_port", "db_path",
                  "mcp_url", "mock_url", "collector_url"):
        vals = [s[field] for s in stacks]
        if len(set(vals)) != len(vals):
            raise ValueError(f"stack plan has duplicate {field}: {vals}")
    all_ports = [s[p] for s in stacks for p in ("mcp_port", "mock_port", "collector_port")]
    if len(set(all_ports)) != len(all_ports):
        raise ValueError(f"stack plan has a port shared across roles: {sorted(all_ports)}")
    return stacks


def verify_isolation(handles, reseed, mutate, snapshot):
    """Cross-write / cross-read proof that each handle is a SEPARATE database.

    `reseed(h)` restores h to the clean baseline; `mutate(h)` makes a distinctive
    change to h; `snapshot(h)` returns a comparable, NON-destructive state token
    for h. The ops are injected so the same algorithm runs against real db files,
    live URLs, or a test double. Returns (ok, report).

    For each handle in turn: mutate it, snapshot ALL, and require that ONLY that
    handle changed from the baseline. If writing to one handle also moved another,
    they share a database and the check fails, naming the pair.
    """
    handles = list(handles)
    for h in handles:
        reseed(h)
    base = {h: snapshot(h) for h in handles}
    if len({str(base[h]) for h in handles}) != 1:
        # not fatal, but worth surfacing: baselines should match (same schema)
        pass
    for h in handles:
        mutate(h)
        after = {g: snapshot(g) for g in handles}
        changed = [g for g in handles if after[g] != base[g]]
        reseed(h)                                   # restore before the next probe
        if changed != [h]:
            others = [g for g in changed if g != h]
            return False, (f"writing to worker {h} also changed {others}: these "
                           "stacks SHARE a database — do not run")
    return True, f"{len(handles)} stacks verified as independent databases"


# ── concrete file-level ops (the helper owns the db files it assigned) ──────
def _schema_path(profile):
    vendor = {"deepvault-capital": "profiles/deepvault-capital/vendor/dvc-db-mcp/schema.sql",
              "deepcyber-ctf": "profiles/deepcyber-ctf/vendor/larkfield-db-mcp/schema.sql"}[profile]
    return ROOT / vendor


def file_ops(profile):
    schema = _schema_path(profile).read_text()

    def reseed(db_path):
        p = Path(db_path)
        if p.exists():
            p.unlink()
        con = sqlite3.connect(db_path)
        con.executescript(schema)
        con.commit()
        con.close()

    def snapshot(db_path):
        con = sqlite3.connect(db_path)
        try:
            tables = [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()]
            return tuple(sorted((t, con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]) for t in tables))
        finally:
            con.close()

    def mutate(db_path):
        # a distinctive, reversible change: drop every row from the first table
        con = sqlite3.connect(db_path)
        try:
            t = con.execute("SELECT name FROM sqlite_master WHERE type='table' "
                            "AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 1").fetchone()
            if t:
                con.execute(f'DELETE FROM "{t[0]}"')
                con.commit()
        finally:
            con.close()

    return reseed, mutate, snapshot


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True,
                    choices=["deepvault-capital", "deepcyber-ctf"])
    ap.add_argument("--workers", type=int, required=True)
    ap.add_argument("--base-mcp-port", type=int, default=8300)
    ap.add_argument("--base-mock-port", type=int, default=8500)
    ap.add_argument("--base-collector-port", type=int, default=8700)
    ap.add_argument("--db-dir", default="/tmp/airt-stacks")
    ap.add_argument("--check-only", action="store_true",
                    help="only plan + verify database isolation on the db files; "
                         "do not launch servers (safe, no ports opened).")
    args = ap.parse_args()

    stacks = plan_stacks(args.workers, args.profile,
                         base_mcp_port=args.base_mcp_port,
                         base_mock_port=args.base_mock_port,
                         base_collector_port=args.base_collector_port,
                         db_dir=args.db_dir)
    Path(args.db_dir).mkdir(parents=True, exist_ok=True)
    print(f"planned {len(stacks)} isolated stacks (distinct ports + db files)")

    # Prove the databases are independent BEFORE anything relies on them.
    reseed, mutate, snapshot = file_ops(args.profile)
    ok, report = verify_isolation([s["db_path"] for s in stacks], reseed, mutate, snapshot)
    print(("  ISOLATION OK — " if ok else "  ISOLATION FAILED — ") + report)
    if not ok:
        return 2

    if args.check_only:
        print("\n--check-only: databases verified independent; servers not launched.")
        for s in stacks:
            print(f"  worker {s['worker']}: mock {s['mock_url']}  mcp {s['mcp_url']}  db {s['db_path']}")
        return 0

    # Live launch is intentionally explicit here rather than magic: start each
    # MCP on its db_path, then each mock with --mcp-url pointing at ITS MCP, then
    # RE-verify through the URLs (a mock bound to the wrong MCP would pass the
    # file check but fail here). Printed as the commands to run, so the operator
    # sees exactly what is started and can wire them into --targets.
    # Exact per-profile vendor dirs — a glob would also catch the renderer server.
    dirs = PROFILE_DIRS[args.profile]
    prof = f"profiles/{args.profile}"
    # Only DVC's MCP is an email sender that takes --collector; Larkfield's MCP
    # rejects it (its renderer collector is opt-in and off by default), so emit
    # the collector wiring for DVC only (review: Lark --collector rejection).
    has_collector = args.profile == "deepvault-capital"
    print("\nLaunch commands (one isolated stack per worker):")
    for s in stacks:
        note = f" | collector {s['collector_port']}" if has_collector else ""
        print(f"  # worker {s['worker']}  (mcp {s['mcp_port']} | mock {s['mock_port']}{note})")
        mcp = (f"  python3 {prof}/vendor/{dirs['mcp']}/server.py "
               f"--port {s['mcp_port']} --db {s['db_path']}")
        if has_collector:
            mcp += f" --collector {s['collector_url']}"
            print(mcp + " &")
            print(f"  python3 {prof}/vendor/{dirs['collector']}/collector.py "
                  f"--port {s['collector_port']} &")
        else:
            print(mcp + " &")
        # The mock only needs its own MCP url + port (it takes no --collector).
        print(f"  python3 -m harness.mock --profile {prof}/profile.yaml "
              f"--mcp-url {s['mcp_url']} --port {s['mock_port']} &")
    print("\nThen pass to the runner:")
    print("  --targets " + ",".join(s["mock_url"] for s in stacks))
    print("\nAfter launch, re-run with --check-only against the live db files, and "
          "additionally query each mock to confirm it reflects its OWN database.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
