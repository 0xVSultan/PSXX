-- PCSX-Redux: dump which 4 KB pages of RAM (0x80010000..0x80200000) hold live data (non zero words) at frame 395 of a card
-- boot, i.e. right when the BIOS shell has allocated its nodes and before a program is unpacked -> build/dbg.log
local ffi = require 'ffi'
local f = io.open('F:/DEV/psx-x/build/dbg.log', 'w')
local frames, done = 0, false
PCSX.Events.createEventListener('GPU::Vsync', function()
    frames = frames + 1
    if frames == 395 and not done then
        done = true
        local mem = ffi.cast('uint32_t*', PCSX.getMemPtr())
        for page = 0x10, 0x1FF do
            local nz = 0
            for w = 0, 1023 do
                if mem[page * 1024 + w] ~= 0 then nz = nz + 1 end
            end
            if nz > 0 then f:write(string.format('%08x %4d\n', 0x80000000 + page * 4096, nz)) end
        end
        f:write('done\n')
        f:flush()
    end
end)
