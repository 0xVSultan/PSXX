-- PCSX-Redux: log the BIOS exception handler chain (list heads at the address stored at 0x100) every 10 frames from frame
-- 250 on, with the nodes of every list -> build/dbg.log. Boot a card to see which RAM the shell's nodes live in.
local ffi = require 'ffi'
local f = io.open('F:/DEV/psx-x/build/dbg.log', 'w')
local frames = 0
local function rd(mem, a) return tonumber(mem[(a % 0x200000) / 4]) end
PCSX.Events.createEventListener('GPU::Vsync', function()
    frames = frames + 1
    if frames >= 250 and frames % 10 == 0 then
        local mem = ffi.cast('uint32_t*', PCSX.getMemPtr())
        local head = rd(mem, 0x100)
        local line = string.format('frame %d [100]=%08x heads:', frames, head)
        for i = 0, 3 do line = line .. string.format(' %08x', rd(mem, head + 8 * i)) end
        f:write(line .. '\n')
        for i = 0, 3 do
            local node, n = rd(mem, head + 8 * i), 0
            while node ~= 0 and n < 8 and node < 0x80200000 do
                f:write(string.format('   list%d node %08x: %08x %08x %08x\n', i, node, rd(mem, node), rd(mem, node + 4), rd(mem, node + 8)))
                node = rd(mem, node)
                n = n + 1
            end
        end
        f:flush()
    end
end)
