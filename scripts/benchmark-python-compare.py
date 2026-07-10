#!/usr/bin/env python3
"""Compare the Rust MCP read path with the local Python pan-mcp tool path.

The Python side deliberately excludes FastMCP dispatch, while the Rust side
uses a real stdio MCP initialize/tools-call exchange. This makes any Rust
advantage conservative. Neither credentials nor device endpoints are emitted.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, TextIO

COMMAND = "<show><system><info/></system></show>"
PYTHON_WORKER = r"""
import json, os, sys
project, inventory, device = sys.argv[1:]
sys.path.insert(0, str(__import__('pathlib').Path(project) / 'src'))
os.environ['PANOS_MCP_INVENTORY'] = inventory
from panos_mcp.tools import execute_pan_op
for line in sys.stdin:
    if not line:
        break
    try:
        value = execute_pan_op(device, '<show><system><info/></system></show>')
        print(json.dumps({'ok': True, 'bytes': len(value)}), flush=True)
    except Exception as error:
        print(json.dumps({'ok': False, 'error_type': type(error).__name__}), flush=True)
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust-binary", type=Path, required=True)
    parser.add_argument("--rust-inventory", type=Path, required=True)
    parser.add_argument("--rust-device", required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--python-project", type=Path, required=True)
    parser.add_argument("--python-inventory", type=Path, required=True)
    parser.add_argument("--python-device", required=True)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def read_json_line(stream: TextIO, timeout: float = 120.0) -> dict[str, Any]:
    ready, _, _ = select.select([stream], [], [], timeout)
    if not ready:
        raise TimeoutError("benchmark subprocess response timed out")
    line = stream.readline()
    if not line:
        raise RuntimeError("benchmark subprocess exited without a response")
    return json.loads(line)


class RustMcp:
    def __init__(self, binary: Path, inventory: Path, device: str) -> None:
        environment = os.environ.copy()
        environment["RUST_LOG"] = "error"
        self.device = device
        self.next_id = 1
        self.process = subprocess.Popen(
            [str(binary), "--device-mapping", str(inventory), "--transport", "stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=environment,
        )
        self.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "phase4-benchmark", "version": "0.1.0"},
            },
        )
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    @property
    def stdin(self) -> TextIO:
        assert self.process.stdin is not None
        return self.process.stdin

    @property
    def stdout(self) -> TextIO:
        assert self.process.stdout is not None
        return self.process.stdout

    def send(self, message: dict[str, Any]) -> None:
        self.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.stdin.flush()

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        response = read_json_line(self.stdout)
        if response.get("id") != request_id or "error" in response:
            raise RuntimeError(f"Rust MCP {method} failed")
        return response["result"]

    def read(self) -> None:
        result = self.request(
            "tools/call",
            {
                "name": "execute_panos_op",
                "arguments": {"device": self.device, "command": COMMAND},
            },
        )
        if result.get("isError") is True:
            raise RuntimeError("Rust MCP read returned a tool error")

    def close(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)


class PythonTool:
    def __init__(self, python: Path, project: Path, inventory: Path, device: str) -> None:
        self.process = subprocess.Popen(
            [str(python), "-u", "-c", PYTHON_WORKER, str(project), str(inventory), device],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=os.environ.copy(),
        )

    @property
    def stdin(self) -> TextIO:
        assert self.process.stdin is not None
        return self.process.stdin

    @property
    def stdout(self) -> TextIO:
        assert self.process.stdout is not None
        return self.process.stdout

    def read(self) -> None:
        self.stdin.write("read\n")
        self.stdin.flush()
        result = read_json_line(self.stdout)
        if not result.get("ok"):
            raise RuntimeError(f"Python pan-mcp read failed: {result.get('error_type', 'unknown')}")

    def close(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)


def timed(call: Any) -> float:
    started = time.perf_counter_ns()
    call()
    return (time.perf_counter_ns() - started) / 1_000_000.0


def metrics(samples: list[float]) -> dict[str, float | int]:
    ordered = sorted(samples)
    p95_index = max(0, (len(ordered) * 95 + 99) // 100 - 1)
    return {
        "iterations": len(samples),
        "mean_ms": round(statistics.fmean(samples), 3),
        "p50_ms": round(statistics.median(samples), 3),
        "p95_ms": round(ordered[p95_index], 3),
        "min_ms": round(ordered[0], 3),
        "max_ms": round(ordered[-1], 3),
    }


def main() -> None:
    args = parse_args()
    if args.warmup < 1 or args.iterations < 5:
        raise SystemExit("warmup must be >= 1 and iterations must be >= 5")
    rust = RustMcp(args.rust_binary, args.rust_inventory, args.rust_device)
    python = PythonTool(
        args.python,
        args.python_project,
        args.python_inventory,
        args.python_device,
    )
    try:
        for _ in range(args.warmup):
            rust.read()
            python.read()
        rust_samples: list[float] = []
        python_samples: list[float] = []
        for index in range(args.iterations):
            if index % 2 == 0:
                rust_samples.append(timed(rust.read))
                python_samples.append(timed(python.read))
            else:
                python_samples.append(timed(python.read))
                rust_samples.append(timed(rust.read))
    finally:
        rust.close()
        python.close()

    result = {
        "schema_version": 1,
        "method": "same PAN-OS system-info XML command and network path; Rust full stdio MCP; Python direct pan-mcp tool (FastMCP dispatch excluded)",
        "rust": metrics(rust_samples),
        "python": metrics(python_samples),
    }
    result["p95_speedup"] = round(
        float(result["python"]["p95_ms"]) / float(result["rust"]["p95_ms"]), 3
    )
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)


if __name__ == "__main__":
    main()
