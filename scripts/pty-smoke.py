#!/usr/bin/env python3
import argparse
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import termios
import time


def set_size(fd, rows, columns):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))


def main():
    parser = argparse.ArgumentParser(description="PTY startup/resize/exit smoke test")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--fingerprint", required=True)
    args = parser.parse_args()

    master, slave = pty.openpty()
    set_size(slave, 24, 80)
    environment = os.environ.copy()
    environment["SUDO_USER"] = args.username
    environment.setdefault("TERM", "xterm-256color")
    process = subprocess.Popen(
        [
            args.binary,
            "--config", args.config,
            "--username", args.username,
            "--fingerprint", args.fingerprint,
        ],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=environment,
        close_fds=True,
    )
    os.close(slave)
    output = bytearray()
    deadline = time.monotonic() + 8
    while b"\x1b[?1049h" not in output and time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            output.extend(os.read(master, 65536))
        if process.poll() is not None:
            break
    if b"\x1b[?1049h" not in output:
        process.kill()
        raise SystemExit("TUI did not enter the alternate screen")

    set_size(master, 40, 120)
    process.send_signal(signal.SIGWINCH)
    time.sleep(0.1)
    os.write(master, b"q")
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        raise SystemExit("TUI did not exit after keyboard input")
    while True:
        ready, _, _ = select.select([master], [], [], 0)
        if not ready:
            break
        try:
            output.extend(os.read(master, 65536))
        except OSError:
            break
    os.close(master)
    if process.returncode != 0:
        raise SystemExit(f"TUI exited with status {process.returncode}")
    if b"\x1b[?1049l" not in output:
        raise SystemExit("TUI did not leave the alternate screen cleanly")
    print("PTY smoke passed: alternate screen, resize signal, keyboard exit, cleanup")


if __name__ == "__main__":
    main()
