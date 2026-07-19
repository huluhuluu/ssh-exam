#!/usr/bin/env python3
import argparse
import statistics
import subprocess
import time


def percentile(values, fraction):
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction + 0.999999) - 1))
    return ordered[index]


def main():
    parser = argparse.ArgumentParser(description="Benchmark ssh-exam-key-policy process invocations")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--key-type", required=True)
    parser.add_argument("--key-base64", required=True)
    parser.add_argument("--iterations", type=int, default=200)
    args = parser.parse_args()
    if args.iterations < 20:
        parser.error("--iterations must be at least 20")

    command = [
        args.binary,
        "--config", args.config,
        "--username", args.username,
        "--fingerprint", args.fingerprint,
        "--key-type", args.key_type,
        "--key-base64", args.key_base64,
    ]
    durations = []
    for index in range(args.iterations + 10):
        started = time.perf_counter_ns()
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        if result.returncode != 0:
            raise SystemExit(f"policy invocation failed: {result.stderr.decode(errors='replace').strip()}")
        if index >= 10:
            durations.append(elapsed_ms)

    median = statistics.median(durations)
    p95 = percentile(durations, 0.95)
    print(f"iterations={len(durations)} median_ms={median:.3f} p95_ms={p95:.3f}")
    print("target: median <20 ms and p95 <50 ms")


if __name__ == "__main__":
    main()
