# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check that the owned launcher and its foreground JVM share a separate console."""
import ctypes
from ctypes.wintypes import DWORD
import os
import sys


def main():
    launcher, gui, parent = map(int, sys.argv[1:])
    console = ctypes.windll.kernel32
    if not console.AttachConsole(DWORD(launcher)):
        return 1
    try:
        members = (DWORD * 8)()
        count = console.GetConsoleProcessList(members, DWORD(len(members)))
        if not 0 < count <= len(members):
            return 1
        actual = set(members[:count])
        return 0 if {launcher, gui, os.getpid()} <= actual and parent not in actual else 1
    finally:
        console.FreeConsole()


if __name__ == "__main__":
    raise SystemExit(main())
