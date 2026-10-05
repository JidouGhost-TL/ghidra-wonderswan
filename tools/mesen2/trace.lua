-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Mesen 2 --testRunner trace script for WonderSwan ROMs (execution evidence for Ghidra).
-- Tested with Mesen 2 at commit b9fa69ddc6d0a331fb103fdb5eef6904305703c2.
-- Env: MESEN_FRAMES (default 1500), MESEN_TRACE_N (full register trace of the first N instructions,
-- default 20000), MESEN_SHOT_EVERY (screenshot every N frames, default 100, 0 = off), MESEN_OUT (/work/out),
-- MESEN_INPUT_MODE (standard|long, default standard), MESEN_SEED (long-mode PRNG seed, default 0).
-- Standard input (same as WSMachine/WSEmulate): Start on frames f>=100 with f%40<3, A on 20<=f%40<23.
-- Long input: seeded deterministic exploratory script (see pickSegment): segments of 6-35 frames each
-- holding a pseudo-random choice of Start/A/B/d-pad buttons (both d-pad clusters), short idles only,
-- plus periodic Start (f%300<3) and A (150<=f%300<153) bursts for f>=100 to clear title/attract screens.
-- Outputs: coverage.tsv (linear  count  ds-list  es-list  banks), trace.tsv (first N insns:
--          n cs ip ax bx cx dx si di bp sp ds es ss flags c0 c1 c2 c3), trace.cdl (Mesen CDLv2
--          code/data log of the run), ram.bin (64 KiB work RAM at the end), shot_<frame>.png, summary.txt.
-- The banks column holds the bank register relevant to the address's window (C0:.. for the linear
-- window, C2:/C3: for the ROM0/ROM1 windows): sampled over the first 64 visits like DS/ES, except
-- bank-window addresses record their bank on every visit (a cheap port read), so their sets are exact.
-- Older logs without the bank columns still import; their linear code is assumed to run with C0=0xFF
-- and their bank-window code imports without bank state (reported, not seeded).
-- Lua file I/O must be enabled (Mesen Script Window options, or the Docker image's settings.json).
local FRAMES = tonumber(os.getenv("MESEN_FRAMES") or "1500")
local TRACE_N = tonumber(os.getenv("MESEN_TRACE_N") or "20000")
local SHOT_EVERY = tonumber(os.getenv("MESEN_SHOT_EVERY") or "100")
local OUT = os.getenv("MESEN_OUT") or "/work/out"
local INPUT_MODE = os.getenv("MESEN_INPUT_MODE") or "standard"
local SEED = tonumber(os.getenv("MESEN_SEED") or "0") or 0

local frame, n = 0, 0
local done = false
local ramErr, cdlNote = nil, nil
local seen = {}          -- linear -> {count, ds = {}, es = {}, c0 = {}, banks = {}}
local trace = io.open(OUT .. "/trace.tsv", "w")
trace:write("n\tcs\tip\tax\tbx\tcx\tdx\tsi\tdi\tbp\tsp\tds\tes\tss\tflags\tc0\tc1\tc2\tc3\n")

local function flags(s)
  local f = 0xF002
  if s["cpu.flags.carry"] then f = f | 0x001 end
  if s["cpu.flags.parity"] then f = f | 0x004 end
  if s["cpu.flags.auxCarry"] then f = f | 0x010 end
  if s["cpu.flags.zero"] then f = f | 0x040 end
  if s["cpu.flags.sign"] then f = f | 0x080 end
  if s["cpu.flags.trap"] then f = f | 0x100 end
  if s["cpu.flags.irq"] then f = f | 0x200 end
  if s["cpu.flags.direction"] then f = f | 0x400 end
  if s["cpu.flags.overflow"] then f = f | 0x800 end
  return f
end

local addrMismatch = 0
local lastAddr, lastRep, lastOpAddr = -1, false, -1
-- REP string instructions: Mesen reports the first iteration at the prefix address and later
-- iterations at the opcode byte. Record a REP instruction once (first iteration), like WSMachine.
-- Returns (isRep, opcodeAddress): opcodeAddress is the first byte after all prefixes, which is
-- where Mesen reports the 2nd and later iterations.
local function repInfo(a)
  local rep = false
  for i = 0, 6 do
    local b = emu.read(a + i, emu.memType.wsMemory, false)
    if b == 0xF2 or b == 0xF3 then rep = true
    elseif not (b == 0x26 or b == 0x2E or b == 0x36 or b == 0x3E or b == 0xF0) then return rep, a + i end
  end
  return rep, a + 7
end

local function windowPort(a)
  if a >= 0x20000 and a < 0x30000 then return 0xC2 end
  if a >= 0x30000 and a < 0x40000 then return 0xC3 end
  return nil
end

local function recordWindowBank(e, port)
  local b = emu.read(port, emu.memType.wsPort, false)
  if type(b) == "number" and b >= 0 then e.banks[b & 0xFF] = true end
end

emu.addMemoryCallback(function(addr, value)
  if done then return end
  if lastRep and (addr == lastOpAddr or addr == lastAddr) then return end
  lastAddr = addr
  lastRep, lastOpAddr = repInfo(addr)
  n = n + 1
  -- The callback address is the linear CPU address; the full state is fetched only when needed
  -- (trace window, or the first 64 visits of an address for its DS/ES/C0 sets). During the trace
  -- window the shortcut is checked against CS*16+IP. Bank-window addresses record their bank on
  -- every visit through a cheap port read, so rule B1 sees every bank they ran under.
  local e = seen[addr]
  local wport = windowPort(addr)
  if e and e.count >= 64 and n > TRACE_N then
    e.count = e.count + 1
    if wport then recordWindowBank(e, wport) end
    return
  end
  local s = emu.getState()
  local lin = (s["cpu.cs"] * 16 + s["cpu.ip"]) & 0xFFFFF
  if n <= TRACE_N and lin ~= addr then addrMismatch = addrMismatch + 1 end
  if not e then e = { count = 0, ds = {}, es = {}, c0 = {}, banks = {} }; seen[addr] = e end
  e.count = e.count + 1
  e.ds[s["cpu.ds"]] = true; e.es[s["cpu.es"]] = true
  if addr >= 0x40000 then e.c0[s["cart.selectedBanks0"]] = true end
  if wport then recordWindowBank(e, wport) end
  if n <= TRACE_N then
    trace:write(string.format("%d\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%02x\t%02x\t%02x\t%02x\n",
      n, s["cpu.cs"], s["cpu.ip"], s["cpu.ax"], s["cpu.bx"], s["cpu.cx"], s["cpu.dx"], s["cpu.si"], s["cpu.di"],
      s["cpu.bp"], s["cpu.sp"], s["cpu.ds"], s["cpu.es"], s["cpu.ss"], flags(s),
      s["cart.selectedBanks0"], s["cart.selectedBanks1"], s["cart.selectedBanks2"], s["cart.selectedBanks3"]))
  end
end, emu.callbackType.exec, 0, 0xFFFFF, emu.cpuType.ws)

-- Seeded xorshift32 for the long exploratory input (deterministic per seed).
local rng = SEED & 0xFFFFFFFF
if rng == 0 then rng = 0x9E3779B9 end
local function rnd(limit)
  rng = rng ~ (rng << 13); rng = rng & 0xFFFFFFFF
  rng = rng ~ (rng >> 17)
  rng = rng ~ (rng << 5); rng = rng & 0xFFFFFFFF
  return rng % limit
end

-- Long-mode segment state: one held action per segment, re-picked at each boundary.
local segEnd, segButtons = 0, {}
local DPAD = { "up", "down", "left", "right", "up2", "down2", "left2", "right2" }
local function pickSegment(f)
  local len = 6 + rnd(30)
  local b = {}
  if f >= 30 then
    local r = rnd(16)
    if r < 2 then
      len = 6 + rnd(10) -- short idle only; never a long no-input stretch
    elseif r < 4 then b.start = true
    elseif r < 6 then b.a = true
    elseif r < 7 then b.b = true
    else
      b[DPAD[1 + rnd(8)]] = true
      if rnd(4) == 0 then b.a = true end
      if rnd(6) == 0 then b.b = true end
    end
  end
  segEnd, segButtons = f + len, b
end

emu.addEventCallback(function()
  if done then return end
  if INPUT_MODE == "long" then
    if frame >= segEnd then pickSegment(frame) end
    local b = {}
    for k, v in pairs(segButtons) do b[k] = v end
    -- Periodic punctuation to get past title, attract and menu screens.
    if frame >= 100 then
      local cyc = frame % 300
      if cyc < 3 then b.start = true end
      if cyc >= 150 and cyc < 153 then b.a = true end
    end
    emu.setInput(b, 0)
  else
    local ph = frame % 40
    emu.setInput({ start = (frame >= 100 and ph < 3), a = (frame >= 100 and ph >= 20 and ph < 23) }, 0)
  end
end, emu.eventType.inputPolled)

local function keys(t) local k = {} for v in pairs(t) do k[#k + 1] = string.format("%04x", v) end table.sort(k) return table.concat(k, ",") end
local function bankkeys(t) local k = {} for v in pairs(t) do k[#k + 1] = string.format("%02x", v) end table.sort(k) return table.concat(k, ",") end
local function bankcol(l, e)
  if l >= 0x40000 then local b = bankkeys(e.c0); return b == "" and "" or ("C0:" .. b) end
  if l >= 0x30000 then local b = bankkeys(e.banks); return b == "" and "" or ("C3:" .. b) end
  if l >= 0x20000 then local b = bankkeys(e.banks); return b == "" and "" or ("C2:" .. b) end
  return ""
end

local crcTab = nil
local function crc32file(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  if not crcTab then
    crcTab = {}
    for i = 0, 255 do
      local c = i
      for _ = 1, 8 do c = (c & 1) ~= 0 and (0xEDB88320 ~ (c >> 1)) or (c >> 1) end
      crcTab[i] = c
    end
  end
  local crc = 0xFFFFFFFF
  while true do
    local blk = f:read(65536)
    if not blk then break end
    for i = 1, #blk do crc = crcTab[(crc ~ blk:byte(i)) & 0xFF] ~ (crc >> 8) end
  end
  f:close()
  return (~crc) & 0xFFFFFFFF
end

local function dumpCdl()
  -- Mesen's Code/Data Logger accumulates over the run; dump it as a real CDLv2 file (header plus
  -- the ROM's CRC32) so it loads both in Mesen and in the Ghidra import.
  local okRom, romInfo = pcall(function() return emu.getRomInfo() end)
  local romPath = (okRom and type(romInfo) == "table") and romInfo.path or nil
  local okCdl, cdl = pcall(function() return emu.getCdlData(emu.memType.wsPrgRom) end)
  if not (okCdl and type(cdl) == "table") then return "getCdlData failed" end
  local size = 0
  if romPath then
    local rf = io.open(romPath, "rb")
    if rf then size = rf:seek("end"); rf:close() end
  end
  if not (type(size) == "number" and size > 0 and cdl[size - 1] ~= nil) then return "CDL size unknown" end
  local crc = romPath and crc32file(romPath) or nil
  local out = io.open(OUT .. "/trace.cdl", "wb")
  if not out then return "cannot write trace.cdl" end
  if crc then
    out:write("CDLv2")
    out:write(string.char(crc & 0xFF, (crc >> 8) & 0xFF, (crc >> 16) & 0xFF, (crc >> 24) & 0xFF))
  end
  local code, data, jt, se = 0, 0, 0, 0
  local chunk = {}
  for i = 0, size - 1 do
    local fl = cdl[i] or 0
    if (fl & 0x01) ~= 0 then code = code + 1 end
    if (fl & 0x02) ~= 0 then data = data + 1 end
    if (fl & 0x04) ~= 0 then jt = jt + 1 end
    if (fl & 0x08) ~= 0 then se = se + 1 end
    chunk[#chunk + 1] = string.char(fl & 0xFF)
    if #chunk >= 65536 then out:write(table.concat(chunk)); chunk = {} end
  end
  out:write(table.concat(chunk))
  out:close()
  return string.format("cdl_code=%d cdl_data=%d cdl_jump_targets=%d cdl_sub_entries=%d cdl_crc=%s",
    code, data, jt, se, crc and string.format("%08x", crc) or "none(headerless)")
end

emu.addEventCallback(function()
  -- Mesen's test runner keeps firing callbacks after emu.exit() until the container stops;
  -- freeze all outputs at the exit frame so re-runs are bit-identical.
  if done then return end
  if SHOT_EVERY > 0 and frame % SHOT_EVERY == 0 then
    local f = io.open(string.format("%s/shot_%05d.png", OUT, frame), "wb"); f:write(emu.takeScreenshot()); f:close()
  end
  frame = frame + 1
  if frame >= FRAMES then
    done = true
    trace:close()
    local c = io.open(OUT .. "/coverage.tsv", "w")
    local lins = {} for l in pairs(seen) do lins[#lins + 1] = l end table.sort(lins)
    for _, l in ipairs(lins) do local e = seen[l]; c:write(string.format("%05x\t%d\t%s\t%s\t%s\n", l, e.count, keys(e.ds), keys(e.es), bankcol(l, e))) end
    c:close()
    local r = io.open(OUT .. "/ram.bin", "wb")
    -- emu.read can return a non-byte (e.g. -1 past the end of 16 KiB mono work RAM); clamp instead
    -- of aborting the callback, which would leave the run without a summary
    local ok, err = pcall(function()
      for a = 0, 0xFFFF do local v = emu.read(a, emu.memType.wsWorkRam, false); if type(v) ~= "number" or v < 0 then v = 0 end; r:write(string.char(v & 0xFF)) end
    end)
    if not ok then ramErr = tostring(err) end
    r:close()
    local okCdl, cdlRes = pcall(dumpCdl)
    cdlNote = okCdl and cdlRes or ("cdl_error=" .. tostring(cdlRes):gsub("%s", "_"))
    local m = io.open(OUT .. "/summary.txt", "w"); m:write(string.format("frames=%d instructions=%d unique=%d callback_addr_mismatches_in_trace_window=%d input=%s seed=%d%s %s\n", frame, n, #lins, addrMismatch, INPUT_MODE, SEED, ramErr and (" ram_dump_error=" .. ramErr:gsub("%s", "_")) or "", cdlNote)); m:close()
    emu.exit(0)
  end
end, emu.eventType.endFrame)
