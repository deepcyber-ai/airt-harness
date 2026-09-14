"""Docker convenience commands for the AIRT Harness.

Provides launch, stop, and logs commands as pip-installable entry points.
After ``pip install -e .`` these are available as:

    airt-launch [profile]       Start the harness container
    airt-stop                   Stop the running container
    airt-logs [-f]              Tail container logs

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import requests


CONTAINER_NAME = os.environ.get("CONTAINER_NAME", "airt-harness")
AIRT_IMAGE = os.environ.get("AIRT_IMAGE", "deepcyberx/airt-harness:1.3.0")


def _docker(*args: str, capture: bool = False) -> subprocess.CompletedProcess:
    cmd = ["docker", *args]
    return subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
    )


def _source_env(env_file: str) -> None:
    """Source key=value pairs from an env file into os.environ."""
    p = Path(env_file)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip("'\"")
            os.environ.setdefault(key, val)


# ── airt-launch ────────────────────────────────────────────────────


def launch():
    """Start the AIRT Harness container with a profile."""
    parser = argparse.ArgumentParser(
        prog="airt-launch",
        description="Start the AIRT Harness Docker container",
    )
    parser.add_argument(
        "profile",
        nargs="?",
        default="default",
        help="Profile name (looks for profiles/<name>/profile.yaml)",
    )
    parser.add_argument(
        "--image",
        default=AIRT_IMAGE,
        help=f"Docker image (default: {AIRT_IMAGE})",
    )
    parser.add_argument(
        "--backend",
        default=os.environ.get("MOCK_BACKEND", "gemini"),
        help="Mock LLM backend (default: gemini)",
    )
    parser.add_argument(
        "--env-file",
        default=os.environ.get("AIRT_ENV_FILE", ".env"),
        help="Env file for API keys (default: .env)",
    )
    parser.add_argument(
        "--gui-port", type=int,
        default=int(os.environ.get("AIRT_PORT_GUI", "7860")),
        help="GUI port (default: 7860)",
    )
    parser.add_argument(
        "--api-port", type=int,
        default=int(os.environ.get("AIRT_PORT_API", "8000")),
        help="Harness API port (default: 8000)",
    )
    parser.add_argument(
        "--mock-port", type=int,
        default=int(os.environ.get("AIRT_PORT_MOCK", "8089")),
        help="Mock API port (default: 8089)",
    )
    args = parser.parse_args()

    # Source .env
    _source_env(args.env_file)

    # Stop any previous container
    _docker("rm", "-f", CONTAINER_NAME, capture=True)

    # Build docker run args
    docker_args = [
        "run", "--rm", "-d",
        "--name", CONTAINER_NAME,
        "-p", f"{args.gui_port}:7860",
        "-p", f"{args.api_port}:8000",
        "-p", f"{args.mock_port}:8089",
        "-e", f"MOCK_BACKEND={args.backend}",
    ]

    for key in ("GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                "DEEPSEEK_API_KEY"):
        if os.environ.get(key):
            docker_args += ["-e", key]

    if args.profile == "default":
        print(f"Launching {CONTAINER_NAME} with default profile "
              "(Deep Vault Capital, baked in)...")
    else:
        profile_dir = Path(f"profiles/{args.profile}").resolve()
        if not profile_dir.is_dir():
            print(f"ERROR: profile directory not found: {profile_dir}",
                  file=sys.stderr)
            profiles = Path("profiles")
            if profiles.is_dir():
                print("Available profiles:", file=sys.stderr)
                for p in sorted(profiles.iterdir()):
                    if p.is_dir() and not p.name.startswith("."):
                        print(f"  - {p.name}", file=sys.stderr)
            sys.exit(1)
        if not (profile_dir / "profile.yaml").exists():
            print(f"ERROR: missing profile.yaml in {profile_dir}",
                  file=sys.stderr)
            sys.exit(1)

        print(f"Launching {CONTAINER_NAME} with {args.profile} profile...")
        print(f"  Mount: {profile_dir} -> /app/profiles/{args.profile}")
        docker_args += [
            "-v", f"{profile_dir}:/app/profiles/{args.profile}",
            "-e", f"PROFILE=profiles/{args.profile}/profile.yaml",
        ]

    docker_args.append(args.image)
    _docker(*docker_args, capture=True)

    # Wait for /health
    api_url = f"http://localhost:{args.api_port}"
    sys.stdout.write("Waiting for harness")
    sys.stdout.flush()

    for _ in range(30):
        try:
            resp = requests.get(f"{api_url}/health", timeout=2)
            if resp.ok:
                print(" ready.\n")
                try:
                    print(json.dumps(resp.json(), indent=2))
                except Exception:
                    print(resp.text)
                print(f"\nGUI:     http://localhost:{args.gui_port}")
                print(f"Harness: {api_url}")
                print(f"Mock:    http://localhost:{args.mock_port}")
                print(f"\nStop with:  airt-stop")
                print(f"Tail logs:  airt-logs")
                print(f"Replay:     airt-replay --help")
                return
        except Exception:
            pass
        time.sleep(1)
        sys.stdout.write(".")
        sys.stdout.flush()

    print("\nERROR: harness did not become healthy within 30s",
          file=sys.stderr)
    _docker("logs", "--tail", "40", CONTAINER_NAME)
    sys.exit(1)


# ── airt-stop ──────────────────────────────────────────────────────


def stop():
    """Stop the running AIRT Harness container."""
    result = _docker(
        "ps", "--format", "{{.Names}}", capture=True
    )
    if CONTAINER_NAME in result.stdout.splitlines():
        _docker("stop", CONTAINER_NAME, capture=True)
        print(f"stopped {CONTAINER_NAME}")
    else:
        print(f"{CONTAINER_NAME} is not running")


# ── airt-logs ──────────────────────────────────────────────────────


def logs():
    """Tail logs from the running AIRT Harness container."""
    parser = argparse.ArgumentParser(
        prog="airt-logs",
        description="Tail AIRT Harness container logs",
    )
    parser.add_argument(
        "-f", "--follow",
        action="store_true",
        help="Follow log output",
    )
    parser.add_argument(
        "--tail",
        default="50",
        help="Number of lines to show (default: 50)",
    )
    args = parser.parse_args()

    docker_args = ["logs", "--tail", args.tail]
    if args.follow:
        docker_args.append("-f")
    docker_args.append(CONTAINER_NAME)
    _docker(*docker_args)


if __name__ == "__main__":
    launch()
