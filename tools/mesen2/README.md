# Recording WonderSwan execution traces with Mesen 2

`trace.lua` runs a cartridge in Mesen 2 and records execution evidence the Ghidra
extension can import (see *Mesen 2 execution traces* in `wonderswan/README.md`):
`trace.tsv` (per-instruction CS:IP + registers for the first N steps),
`coverage.tsv` (every executed address over the whole run, with DS/ES sets and bank
state) and `trace.cdl` (Mesen's code/data log of the run), plus screenshots and logs.

Supported Mesen version: Mesen 2 at commit `b9fa69d` (the `Dockerfile` in this
directory builds that exact revision).

## Headless (Docker)

```sh
tools/mesen2/run-trace.sh game.wsc /tmp/gametrace [frames=1500] [trace_n=20000] [shot_every=100]
```

The image builds on first use. The scripted Start/A input matches the extension's
built-in emulator, so traces stay comparable with `WSEmulate` runs.
`run-trace.sh` mounts `settings.json` over Mesen's config: besides file I/O
access it raises the Lua per-callback timeout from 1 s to 60 s, without which
the end-of-run `.cdl` dump (a multi-megabyte CRC + flag loop in Lua) aborts on
larger cartridges. The `Dockerfile` bakes in the same settings.

## Long exploratory runs

For maximum code coverage, `trace.lua` also offers a seeded deterministic
exploratory input (`MESEN_INPUT_MODE=long`, `MESEN_SEED=<uint32>`):

```sh
MESEN_INPUT_MODE=long MESEN_SEED=12345 \
  tools/mesen2/run-trace.sh game.wsc /tmp/gamelong 20000 20000 1000
```

The generator (a self-contained xorshift32 in `trace.lua`, no game-specific data)
plays pseudo-random segments of 6–35 frames, each holding Start, A, B or a d-pad
direction from either button cluster (sometimes A/B combined with a direction);
idle segments are capped at 6–15 frames so the run never sits inputless for long.
On top of that, Start fires for 3 frames every 300 frames and A for 3 frames
mid-cycle (both from frame 100 on), which clears title, attract and menu screens
on most cartridges. The seed is recorded in `summary.txt` (`input=long seed=…`),
and re-running with the same seed reproduces every output byte-for-byte
(outputs freeze at the exit frame: Mesen's test runner keeps firing script
callbacks for a moment after `emu.exit()`, and without the freeze the extra
screenshots would depend on container stop timing).

A good seed convention for corpora is the first 32 bits of the SHA-256 of the
cartridge id. The `.cdl` code/data log needs no debugger: `trace.lua` dumps it
via `emu.getCdlData` in both modes, so long runs yield `coverage.tsv` +
`trace.cdl` (+ a short boot `trace.tsv` and `shot_*.png` stills) with no manual
play. Button names follow Mesen's WonderSwan controller (`a`, `b`, `start`,
`up`/`down`/`left`/`right`, `up2`/`down2`/`left2`/`right2`).

## In the Mesen UI

1. Set `MESEN_OUT` (and optionally `MESEN_FRAMES`, `MESEN_TRACE_N`,
   `MESEN_SHOT_EVERY`, `MESEN_INPUT_MODE`, `MESEN_SEED`) in the environment
   Mesen runs in.
2. Load the cartridge, open the Script Window (*Debug → Script Window*), enable
   file I/O access in its options, open `trace.lua` and run it. Outputs land in
   `MESEN_OUT` when the frame count is reached. (Reset the console first for a
   trace that starts at boot.)

To record a long-play code/data log instead of a scripted trace, play in Mesen
with the debugger enabled (*Debug → Debugger*): Mesen saves a `.cdl` next to its
debugger files on exit, which imports the same way (see the extension README for
how CDL bytes map to addresses).
