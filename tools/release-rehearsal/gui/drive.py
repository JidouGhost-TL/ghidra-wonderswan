#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Private GUI control client. Transport uses a disposable filesystem directory."""
import argparse
from pathlib import Path
import time


class Session:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.sequence = len(list(self.directory.glob("request-*.txt")))

    def call(self, *command, timeout=20):
        self.sequence += 1
        target = self.directory / f"request-{self.sequence}.txt"
        draft = target.with_suffix(".part")
        draft.write_text("\t".join(command) + "\n", encoding="utf-8")
        draft.rename(target)
        result = self.directory / f"result-{self.sequence}.txt"
        until = time.monotonic() + timeout
        while not result.is_file():
            if time.monotonic() > until:
                raise TimeoutError(f"Control did not answer {command[0]}")
            time.sleep(0.08)
        status, _, response = result.read_text(encoding="utf-8").partition("\n")
        if status != "OK":
            raise RuntimeError(response)
        return response


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("directory", type=Path)
    cli.add_argument("command", nargs="+")
    args = cli.parse_args()
    print(Session(args.directory).call(*args.command))
