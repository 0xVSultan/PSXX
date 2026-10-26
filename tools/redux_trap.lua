-- PCSX-Redux debugging helper: stop when the CPU starts executing outside the program image and write the CPU state
-- to build/dbg.log (registers, stack, the words at the jump target).
--   pcsx-redux.exe -dofile F:/DEV/psx-x/tools/redux_trap.lua
-- Then map the addresses with:  mipsel-none-elf-nm -n build/psx/psxx_wallet.elf   (see tools/symaddr.py)
local ffi = require 'ffi'
local LOG = 'F:/DEV/psx-x/build/dbg.log'
local f = io.open(LOG, 'w')
local function log(fmt, ...)
    f:write(string.format(fmt, ...) .. '\n')
    f:flush()
end

local names = { 'r0', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra' }

local function dump(why)
    local r = PCSX.getRegisters()
    log('=== %s ===', why)
    log('pc=%08x', r.pc)
    for i = 0, 31 do
        log('%-3s=%08x', names[i + 1], tonumber(r.GPR.r[i]))
    end
    local mem = ffi.cast('uint32_t*', PCSX.getMemPtr())
    local sp = tonumber(r.GPR.n.sp)
    log('-- stack from sp=%08x', sp)
    for i = 0, 63 do
        local a = (sp + 4 * i) % 0x200000
        log('%08x: %08x', 0x80000000 + a, mem[a / 4])
    end
    local pc = tonumber(r.pc) % 0x200000
    log('-- words at pc')
    for i = 0, 7 do log('%08x: %08x', 0x80000000 + pc + 4 * i, mem[(pc + 4 * i) / 4]) end
    PCSX.pauseEmulator()
end

-- the image is below 0x80040000 (_end 0x8003fb60); anything above that is data, the heap or the stack
local ok, err = pcall(function()
    PCSX.addBreakpoint(0x80040000, 'Exec', 0x1C0000, 'left the program', function(address, width, cause)
        local okd, errd = pcall(function() dump(string.format('exec at %08x', tonumber(address))) end)
        if not okd then log('dump failed: %s', tostring(errd)) end
        PCSX.pauseEmulator()
    end)
end)
log('breakpoint set: %s %s', tostring(ok), tostring(err))

-- heartbeat: one line per second of emulated time, so the log shows whether (and where) the program is running
local frames = 0
local okh, errh = pcall(function()
    PCSX.Events.createEventListener('GPU::Vsync', function()
        frames = frames + 1
        if frames % 50 == 0 then
            local r = PCSX.getRegisters()
            log('frame %d pc=%08x ra=%08x sp=%08x', frames, tonumber(r.pc), tonumber(r.GPR.n.ra), tonumber(r.GPR.n.sp))
        end
    end)
end)
log('heartbeat: %s %s', tostring(okh), tostring(errh))
