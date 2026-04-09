# Contributing to AIRT Harness

## Development Setup

```bash
git clone https://github.com/deepcyber-ai/airt-harness.git
cd airt-harness
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the package in editable mode and puts the CLI commands on PATH:

```bash
airt-launch --help
airt-stop --help
airt-logs --help
airt-replay --help
```

## Running from Source (without Docker)

```bash
# Terminal 1: mock server
python -m harness.mock --backend echo --port 8089

# Terminal 2: harness
BACKEND=mock uvicorn harness.server:app --port 8000

# Terminal 3: GUI (optional)
python -m harness.gui
```

## Smoke Test

The smoke test verifies the full replay loop end-to-end: launch, send messages, replay from intel logs, and optionally replay from an external metabase CSV.

### Prerequisites

- Docker running (`colima start` on macOS)
- Package installed (`pip install -e .`)

### Run

```bash
./scripts/smoke-test.sh
```

This will:

1. Check that `airt-launch`, `airt-replay` are on PATH and Docker is running
2. Launch the harness container with the echo backend (no API key needed)
3. Send 3 test messages to generate intel logs
4. Replay the session from intel logs and verify the comparison report
5. Tear down the container on exit

### Testing with a metabase CSV

To also test the metabase adapter, set the `SMOKE_METABASE` environment variable:

```bash
SMOKE_METABASE=/path/to/evidence/metabase.csv ./scripts/smoke-test.sh
```

The metabase CSV must have at minimum: `session_id`, `turn`, `request` (or `prompt`), `answer` (or `response`).

### Manual smoke test

If you prefer to run each step manually:

```bash
# 1. Launch
MOCK_BACKEND=echo airt-launch

# 2. Send messages
curl -s -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -H "x-session-id: my-test" \
  -d '{"input": "Hello"}' | python3 -m json.tool

curl -s -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -H "x-session-id: my-test" \
  -d '{"input": "Tell me more"}' | python3 -m json.tool

# 3. Replay from intel
airt-replay profiles/default/ --list-sessions
airt-replay profiles/default/ --session my-test
airt-replay profiles/default/ --session my-test -o /tmp/report.md
cat /tmp/report.md

# 4. Replay from a metabase CSV (if available)
airt-replay /path/to/metabase.csv --list-sessions
airt-replay /path/to/metabase.csv --session <session-id> --delay 0.5

# 5. Clean up
airt-stop
```

## Publishing to PyPI

### First-time setup

1. Create a PyPI account at https://pypi.org/account/register/
2. Enable 2FA (required for publishing)
3. Create an API token at https://pypi.org/manage/account/token/
   - First upload: scope to "Entire account"
   - After first upload: create a project-scoped token for `airt-harness`
4. Install build tools:

```bash
pip install build twine
```

5. Optionally save your token in `~/.pypirc` so you don't have to paste it each time:

```ini
[pypi]
username = __token__
password = pypi-YOUR-TOKEN-HERE
```

### Publishing a release

1. **Update the version** in both files (keep them in sync):

   - `harness/__init__.py` — the `__version__` string
   - `pyproject.toml` — the `version` field

2. **Run the smoke test** to verify everything works:

   ```bash
   ./scripts/smoke-test.sh
   ```

3. **Build the package**:

   ```bash
   rm -rf dist/
   python -m build
   ```

   This creates `dist/airt_harness-X.Y.Z.tar.gz` and `dist/airt_harness-X.Y.Z-py3-none-any.whl`.

4. **Check the package** (optional but recommended):

   ```bash
   python -m twine check dist/*
   ```

5. **Upload to PyPI**:

   ```bash
   python -m twine upload dist/*
   ```

   If you don't have `~/.pypirc`, it will prompt:
   ```
   Username: __token__
   Password: <paste your API token>
   ```

6. **Verify the release**:

   ```bash
   pip install --upgrade airt-harness
   airt-replay --help
   ```

   The package page is at https://pypi.org/project/airt-harness/

### Testing with TestPyPI first

To do a dry run before publishing to the real PyPI:

```bash
# Upload to TestPyPI
python -m twine upload --repository testpypi dist/*

# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ airt-harness
```

TestPyPI account: https://test.pypi.org/account/register/ (separate from PyPI).

### Version numbering

Follow semantic versioning:

- **Patch** (1.2.1): bug fixes, documentation
- **Minor** (1.3.0): new features, backward compatible
- **Major** (2.0.0): breaking changes to the API or CLI

## Project Structure

```
airt-harness/
├── harness/
│   ├── __init__.py          # Package metadata and version
│   ├── server.py            # FastAPI harness server
│   ├── mock.py              # Mock LLM server
│   ├── gui.py               # Gradio chat UI
│   ├── replay.py            # Replay engine, source adapters, judge framework
│   ├── docker.py            # Docker CLI commands (launch, stop, logs)
│   └── mappers/
│       ├── __init__.py      # BaseMapper, CanonicalResponse, mapper loading
│       └── example.py       # Reference mapper (flat JSON)
├── profiles/
│   └── default/             # Built-in demo profile (Deep Vault Capital)
├── scripts/
│   ├── airt-launch.sh       # Shell wrapper for docker launch
│   ├── airt-stop.sh         # Shell wrapper for docker stop
│   ├── airt-logs.sh         # Shell wrapper for docker logs
│   ├── airt-replay.sh       # Shell wrapper for replay
│   └── smoke-test.sh        # End-to-end smoke test
├── pyproject.toml           # Package config, dependencies, entry points
├── requirements.txt         # Dependencies (for non-pip-install use)
├── Dockerfile               # Container build
├── README.md                # Public documentation
├── CONTRIBUTING.md           # This file
└── LICENSE                  # Apache 2.0
```
