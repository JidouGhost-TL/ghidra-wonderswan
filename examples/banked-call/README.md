# Follow a banked call in Ghidra

This exercise uses three original 128 KiB WonderSwan cartridges that you generate locally. All three execute the same far call, `CALL 2000:0069` at `F000:010D`. They differ in how they populate the first bank window at `2000:0000` by writing to port `0xC2`. The routines at the two physical destinations leave different bytes at RAM address `0x0200`.

## Set up

Install Ghidra 12.1.3 and JDK 21. Download the V30MZ and WonderSwan ZIPs from the extension v0.1.0 release and check both files against the release checksum list. In the Ghidra project window, choose **File → Install Extensions**, add V30MZ first and WonderSwan second, enable both and restart. The headless launcher uses the same user installation. [Ghidra 12.1.3](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build) · [Extension v0.1.0 downloads](https://github.com/JidouGhost-TL/ghidra-wonderswan/releases/tag/v0.1.0) · [Release SHA256SUMS](https://github.com/JidouGhost-TL/ghidra-wonderswan/releases/download/v0.1.0/SHA256SUMS) · [Installation guide](https://jidoughost-tl.github.io/wonderswan-wiki/guides/installation)

Get the example scripts from the source checkout. The result table uses the released v0.1.0 extensions and the example files at the revision below. Use a shell with Git and Python 3 and point `GHIDRA_INSTALL_DIR` at the installed Ghidra distribution.

```sh
git clone https://github.com/JidouGhost-TL/ghidra-wonderswan.git
cd ghidra-wonderswan
git checkout --detach cd774aee301bf0e9afc24e33406987673dd6d75b
```

```sh
example="$PWD/examples/banked-call"
workdir="$PWD/banked-call-work"
G="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
mkdir "$workdir" &&
  mkdir "$workdir/projects" &&
  python3 "$example/make_cartridges.py" "$workdir/roms"
```

The output directory must be new. Keep the three generated images unchanged for the saved-project checks.

## Analyze, save and reopen

Run the block once for `bank-fe`. Change `sample` to `bank-ff` and then `bank-unknown` to reproduce the other cases. The pre-script enables built-in execution evidence and records which resolution rules fired. Ghidra detects the cartridge format and processor language automatically.

```sh
sample=bank-fe
mode=observed
project="$sample-$mode"
rom="$workdir/roms/$sample.ws"

"$G" "$workdir/projects" "$project" -import "$rom" \
  -scriptPath "$example" \
  -preScript ConfigureBankEvidence.java "$workdir/$project.jsonl" "$mode"
"$G" "$workdir/projects" "$project" -process "$sample.ws" -noanalysis -readOnly \
  -scriptPath "$example" \
  -postScript VerifyBankedCall.java "$rom" "$workdir/$project.txt" "$mode"
test -s "$workdir/$project.txt" && cat "$workdir/$project.txt"
```

Check the import log for `Analysis succeeded` and `Save succeeded`. The separate reopen checks the saved executable SHA-256 against the original cartridge, then records the raw call reference, physical call override, original-file offset, six target bytes and native decompiler output. A headless run can exit successfully after a script error. Require a new receipt file with the expected results.

| Cartridge | Bank selector written to `0xC2` | Saved call override destination | Offset in cartridge file | Byte written to RAM `0x0200` |
|---|---:|---|---:|---:|
| `bank-fe.ws` | Constant `0xFE` | `ROM0_BANK_00FE::020069` | `0x69` | `0x42` |
| `bank-ff.ws` | Constant `0xFF` | `ROM0_BANK_00FF::020069` | `0x10069` | `0x99` |
| `bank-unknown.ws` | Runtime read of port `0xB5`, observed as `0x40` in this run | `ROM0_BANK_0040::020069` | `0x69` | `0x42` |

In the CodeBrowser, go to `F000:010D`, right-click the call and open **References → Add/Edit…** to view its reference table. The raw `UNCONDITIONAL_CALL` points to `2000:0069` in the uninitialized `ROM0_WINDOW`. Follow the separate `CALL_OVERRIDE_UNCONDITIONAL` row to see the initialized bank overlay. Its suffix `020069` is the linear CPU address. The verifier uses cartridge mapping metadata to recover the file offset. In the decompiler, the selected function should store the marker to `uRam00000200` and return.

Now change `sample` to `bank-unknown` and `mode` to `static` in the command block. This makes a new project with **Run WSMachine** disabled and no external execution evidence. On v0.1.0 the raw window call is still present and the receipt shows zero physical overrides. Both constant cases also give zero physical overrides under the static-only settings in this release. The `0x40` result records one execution of the runtime selector. Different input values may choose a different physical bank.

## Check the runtime effect

Select a project from the observed runs and run the bundled emulator script. The example below reads the marker and records the first 32 instructions. Use a fresh output path for each run.

```sh
sample=bank-fe
project="$sample-observed"
run="$workdir/$project-run"
"$G" "$workdir/projects" "$project" -process "$sample.ws" -noanalysis -readOnly \
  -postScript WSEmulate.java "$run" 1 32 - 0 - - trace=1:32
od -An -tx1 -j 512 -N1 "$run/ram.bin"
head -13 "$run/trace.tsv"
```

The trace enters `2000:0069` at instruction 9. The far return at instruction 11 returns to `F000:0112` with SP restored to `0x3000` at instruction 12. The marker should match the table.

To check the runtime result with a separate emulator, use the repository's Mesen 2 trace runner with Docker. The first invocation builds its container image.

```sh
tools/mesen2/run-trace.sh "$workdir/roms/$sample.ws" "$workdir/$sample-reference" 1 32 0
od -An -tx1 -j 512 -N1 "$workdir/$sample-reference/ram.bin"
```

Selector values for the runtime-input cartridge can differ across environments. In our reference run `0x00` and `0x40` both map to file offset `0x69` in this two-bank cartridge. Compare the physical file offset, marker and far-return checkpoint.
