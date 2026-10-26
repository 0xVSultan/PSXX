"""Makes a small audio CD image (cue + bin) with tones, to try the CD player of the hide test (hal/psx/hidetest.c) in an emulator.

    py -3.13 tools/gen_testdisc.py [outdir]        (default build/testdisc)

Four audio tracks of 25 s each, a different melody-less tone pattern in each so that the track and the position can be heard:
track 1 a 440 Hz beep every second, track 2 880 Hz every half second, track 3 a rising sweep, track 4 a low 220 Hz hum.
Raw 16 bit stereo 44.1 kHz, as on a CD, tracks one after the other in a single bin (2 s of silence pre-gap is not added: INDEX 01 at the start). """
import math
import os
import struct
import sys

RATE = 44100
SECS = 25
SECTOR = 2352
FRAMES = RATE // 75                  # samples per sector


def track_samples(n):
    total = RATE * SECS
    out = bytearray()
    for i in range(total):
        t = i / RATE
        if n == 1:
            v = math.sin(2 * math.pi * 440 * t) if (t % 1.0) < 0.2 else 0.0
        elif n == 2:
            v = math.sin(2 * math.pi * 880 * t) if (t % 0.5) < 0.1 else 0.0
        elif n == 3:
            f = 200 + 600 * (t / SECS)
            v = math.sin(2 * math.pi * f * t)
        else:
            v = math.sin(2 * math.pi * 220 * t) * 0.8
        s = int(v * 12000)
        out += struct.pack('<hh', s, s)
    # whole sectors
    pad = (-len(out)) % SECTOR
    out += b'\0' * pad
    return bytes(out)


def msf(sector):
    return '%02d:%02d:%02d' % (sector // 4500, (sector // 75) % 60, sector % 75)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'build', 'testdisc')
    os.makedirs(outdir, exist_ok=True)
    cue = ['FILE "testdisc.bin" BINARY']
    data = bytearray()
    for n in range(1, 5):
        cue.append('  TRACK %02d AUDIO' % n)
        cue.append('    INDEX 01 %s' % msf(len(data) // SECTOR))
        data += track_samples(n)
    with open(os.path.join(outdir, 'testdisc.bin'), 'wb') as f:
        f.write(data)
    with open(os.path.join(outdir, 'testdisc.cue'), 'w') as f:
        f.write('\n'.join(cue) + '\n')
    print('wrote', os.path.abspath(outdir), len(data) // SECTOR, 'sectors')


main()
