-- PCSX-Redux helper for the packed card boot: log when the stub, the program entry and main are reached, then the pc every
-- 5 frames, and stop with a full dump when the cpu reaches a given address (EDIT the three constants below).
--   pcsx-redux.exe -dofile F:/DEV/psx-x/tools/redux_trace.lua      -> build/dbg.log
local ffi = require 'ffi'
local LOG = 'F:/DEV/psx-x/build/dbg.log'
local STUB, ENTRY, MAIN = 0x8015f50c, 0x80112138, 0x80101020
local BAD = 0x800a4010
local f = io.open(LOG, 'w')
local function log(fmt, ...) f:write(string.format(fmt, ...) .. '\n'); f:flush() end
local names = { 'r0', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra' }

local function dump(why)
    local r = PCSX.getRegisters()
    log('=== %s === pc=%08x', why, tonumber(r.pc))
    for i = 0, 31 do log('%-3s=%08x', names[i + 1], tonumber(r.GPR.r[i])) end
    local mem = ffi.cast('uint32_t*', PCSX.getMemPtr())
    local sp = tonumber(r.GPR.n.sp)
    for i = 0, 47 do
        local a = (sp + 4 * i) % 0x200000
        log('stack %08x: %08x', 0x80000000 + a, mem[a / 4])
    end
end

local function bp(addr, name, stop)
    local ok, err = pcall(function()
        PCSX.addBreakpoint(addr, 'Exec', 4, name, function()
            local okd, errd = pcall(dump, name)
            if not okd then log('dump failed: %s', tostring(errd)) end
            if stop then PCSX.pauseEmulator() else PCSX.resumeEmulator() end
        end)
    end)
    log('bp %s: %s %s', name, tostring(ok), tostring(err))
end
-- breakpoints slowed the emulator to a crawl: only the heartbeat below is used (uncomment to stop at an address)
bp(STUB, "stub", false)
bp(ENTRY, "entry", false)
bp(MAIN, "main", false)
bp(0x80100000, "image start", false)
local hits = 0
pcall(function()
    PCSX.addBreakpoint(0x8005939c, 'Exec', 4, 'shell idle', function()
        hits = hits + 1
        if hits <= 3 then log('bp check: shell idle hit %d', hits) end
        PCSX.resumeEmulator()
    end)
end)

local frames = 0
pcall(function()
    PCSX.Events.createEventListener('GPU::Vsync', function()
        frames = frames + 1
        if frames % 10 == 0 then
            local r = PCSX.getRegisters()
            local mem = ffi.cast('uint32_t*', PCSX.getMemPtr())
            log('frame %d pc=%08x ra=%08x sp=%08x blob=%08x/%08x image=%08x/%08x probs=%08x', frames, tonumber(r.pc), tonumber(r.GPR.n.ra), tonumber(r.GPR.n.sp),
                mem[0x150000 / 4], mem[0x15F500 / 4], mem[0x100000 / 4], mem[0x101020 / 4], mem[0x180000 / 4])
        end
    end)
end)
