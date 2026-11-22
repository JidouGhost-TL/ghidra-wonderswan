#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Write three original monochrome WonderSwan cartridge images."""

import argparse
from pathlib import Path
from struct import pack_into


def cartridge(select_bank: bytes) -> bytearray:
    rom = bytearray(b"\xff") * 0x20000
    # The same CPU address in two mapped banks writes a different marker.
    rom[0x00069:0x0006F] = bytes.fromhex("b0 42 a2 00 02 cb")  # MOV AL,42; MOV [0200],AL; RETF
    rom[0x10069:0x1006F] = bytes.fromhex("b0 99 a2 00 02 cb")  # MOV AL,99; MOV [0200],AL; RETF

    start = (
        bytes.fromhex("31 c0 8e d8 8e d0 bc 00 30")  # DS=SS=0, SP=3000
        + select_bank
        + bytes.fromhex("e6 c2 9a 69 00 00 20 eb fe")  # OUT C2,AL; CALL FAR 2000:0069; loop
    )
    rom[0x10100:0x10100 + len(start)] = start

    # Reset vector: JMP FAR F000:0100. Footer: monochrome, 128 KiB, no save device.
    rom[-16:] = bytes.fromhex("ea 00 01 00 f0 00 00 00 01 00 00 00 00 00 00 00")
    pack_into("<H", rom, len(rom) - 2, sum(rom[:-2]) & 0xFFFF)
    return rom


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory for the generated cartridges")
    output = parser.parse_args().output
    output.mkdir()
    for name, select_bank in (
        ("bank-fe", bytes.fromhex("b0 fe")),        # MOV AL,FE
        ("bank-ff", bytes.fromhex("b0 ff")),        # MOV AL,FF
        ("bank-unknown", bytes.fromhex("e4 b5")),  # IN AL,B5
    ):
        (output / f"{name}.ws").write_bytes(cartridge(select_bank))


if __name__ == "__main__":
    main()
