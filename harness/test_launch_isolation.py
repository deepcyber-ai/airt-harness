"""Launch helper — prove target stacks are SEPARATE databases.

No network. Different URLs are not proof of distinct databases; scripts/
launch_targets.py must verify it. These test the two pure cores: the stack plan
(distinct ports + db files, fail-closed on collision) and the cross-write /
cross-read isolation check (only the mutated stack may change), plus the real
sqlite file ops used against the db files the helper assigns.
"""
import importlib.util, os, sys, tempfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("launch_targets", os.path.join(ROOT, "scripts/launch_targets.py"))
L = importlib.util.module_from_spec(spec); spec.loader.exec_module(L)

R = []
def ck(label, cond): R.append((bool(cond), label))

# ── plan_stacks: K stacks, everything distinct (incl. collector) ──
stacks = L.plan_stacks(8, "deepvault-capital")
ck("plans one stack per worker", len(stacks) == 8)
for field in ("mcp_port", "mock_port", "collector_port", "db_path",
              "mcp_url", "mock_url", "collector_url"):
    vals = [s[field] for s in stacks]
    ck(f"all {field} are distinct", len(set(vals)) == len(vals))
ck("each stack has its own db file path", all(f"worker-{s['worker']}" in s["db_path"] for s in stacks))
ck("each worker has its OWN collector port", all("collector_port" in s for s in stacks))

# B1: no mock/mcp/collector port is EVER shared across roles (the collision that
# put a worker's mock on the DVC collector's 8401 and broke composition scoring).
all_ports = [s[p] for s in stacks for p in ("mcp_port", "mock_port", "collector_port")]
ck("B1: no port is shared across mcp / mock / collector roles",
   len(set(all_ports)) == len(all_ports))
# and larger K still never collides
big = L.plan_stacks(40, "deepvault-capital")
big_ports = [s[p] for s in big for p in ("mcp_port", "mock_port", "collector_port")]
ck("B1: 40 workers still have no cross-role port collision", len(set(big_ports)) == len(big_ports))

# ── verify_isolation: independent handles PASS ──
def fake_world(shared_pair=None):
    # handle -> state list; a shared pair aliases one list object
    world = {i: ["seed"] for i in range(3)}
    if shared_pair:
        a, b = shared_pair
        world[b] = world[a]                      # b now shares a's database
    def reseed(h):  world[h][:] = ["seed"]
    def mutate(h):  world[h].append("MUT")
    def snapshot(h): return tuple(world[h])
    return list(world.keys())[:3] if not shared_pair else [0, 1, 2], reseed, mutate, snapshot

handles, reseed, mutate, snapshot = fake_world()
ok, report = L.verify_isolation(handles, reseed, mutate, snapshot)
ck("three independent stacks pass isolation", ok and "independent" in report)

# ── verify_isolation: a SHARED pair is caught, and named ──
handles, reseed, mutate, snapshot = fake_world(shared_pair=(0, 1))
ok, report = L.verify_isolation(handles, reseed, mutate, snapshot)
ck("a shared database is caught (not ok)", not ok)
ck("the report says the stacks SHARE a database", "SHARE a database" in report)
ck("the offending other stack is named", "[1]" in report or "1" in report)

# a different shared pair
handles, reseed, mutate, snapshot = fake_world(shared_pair=(1, 2))
ok, _ = L.verify_isolation(handles, reseed, mutate, snapshot)
ck("a different shared pair is also caught", not ok)

# ── real sqlite file ops: two SEPARATE files are independent ──
for profile in ("deepvault-capital", "deepcyber-ctf"):
    reseed, mutate, snapshot = L.file_ops(profile)
    dbs = []
    try:
        for _ in range(3):
            fd, p = tempfile.mkstemp(suffix=".sqlite"); os.close(fd); dbs.append(p)
        ok, report = L.verify_isolation(dbs, reseed, mutate, snapshot)
        ck(f"{profile}: three separate db files verify as independent", ok)
        # the ops themselves behave
        reseed(dbs[0]); base = snapshot(dbs[0])
        ck(f"{profile}: a fresh reseed has a non-empty baseline", any(c > 0 for _, c in base))
        mutate(dbs[0]); after = snapshot(dbs[0])
        ck(f"{profile}: mutate changes the snapshot", after != base)
        reseed(dbs[0])
        ck(f"{profile}: reseed restores the baseline", snapshot(dbs[0]) == base)
    finally:
        for p in dbs:
            if os.path.exists(p): os.remove(p)

# ── real file ops: TWO handles on the SAME file are caught as shared ──
reseed, mutate, snapshot = L.file_ops("deepvault-capital")
fd, shared = tempfile.mkstemp(suffix=".sqlite"); os.close(fd)
fd, solo = tempfile.mkstemp(suffix=".sqlite"); os.close(fd)
try:
    # simulate the misconfig: worker 'A' and 'B' both point at one file
    class SamePath(str):
        pass
    a, b = SamePath(shared), SamePath(shared)   # distinct handle objects, same path
    # give them distinct identity so the dict keeps both, but ops hit one file
    a_key, b_key = ("A", shared), ("B", shared)
    def r2(h): reseed(h[1])
    def m2(h): mutate(h[1])
    def s2(h): return snapshot(h[1])
    ok, report = L.verify_isolation([a_key, b_key, ("C", solo)], r2, m2, s2)
    ck("two workers bound to ONE db file are caught as sharing", not ok and "SHARE" in report)
finally:
    for p in (shared, solo):
        if os.path.exists(p): os.remove(p)

# ── main() runs for both profiles/modes and emits CORRECT commands (review B1) ──
import subprocess, tempfile
for profile, mcp_dir, coll_dir in [("deepvault-capital", "dvc-db-mcp", "dvc-collector"),
                                   ("deepcyber-ctf", "larkfield-db-mcp", "larkfield-renderer")]:
    with tempfile.TemporaryDirectory() as td:
        script = os.path.join(ROOT, "scripts/launch_targets.py")
        for mode in (["--check-only"], []):
            r = subprocess.run([sys.executable, script, "--profile", profile,
                                "--workers", "2", "--db-dir", td] + mode,
                               capture_output=True, text=True)
            ck(f"main() {profile} {mode or ['live-print']} exits 0 (no TypeError)", r.returncode == 0)
        # the live-print output must wire the collector correctly
        out = subprocess.run([sys.executable, script, "--profile", profile,
                              "--workers", "2", "--db-dir", td],
                             capture_output=True, text=True).stdout
        ck(f"{profile}: MCP command uses the EXACT mcp dir", f"vendor/{mcp_dir}/server.py" in out)
        ck(f"{profile}: the mock takes NO --collector-url", "--collector-url" not in out)
        ck(f"{profile}: no leftover glob in the commands", "vendor/*/" not in out)
        if profile == "deepvault-capital":            # only DVC wires a collector
            ck(f"{profile}: collector command uses the EXACT collector dir", f"vendor/{coll_dir}/collector.py" in out)
            ck(f"{profile}: DVC MCP --collector binds worker 0's collector (8700)", "--collector http://localhost:8700" in out)
            ck(f"{profile}: DVC MCP --collector binds worker 1's collector (8701)", "--collector http://localhost:8701" in out)
        else:                                          # Lark MCP rejects --collector; must NOT emit it
            ck(f"{profile}: Lark emits NO --collector on the MCP", "--collector http" not in out)
            ck(f"{profile}: Lark does not start the renderer collector by default", f"vendor/{coll_dir}/collector.py" not in out)

passed = sum(1 for x in R if x[0])
for okk, l in R:
    if not okk: print(f"  FAIL {l}")
print(f"\nlaunch isolation: {passed}/{len(R)} passed")
sys.exit(0 if passed == len(R) else 1)
