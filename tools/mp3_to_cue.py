#!/usr/bin/env python3
"""Makes a standard audio CD image (one .bin, one .cue) from audio files (mp3, wav, flac, anything ffmpeg reads).

    py -3.13 tools/mp3_to_cue.py out/name  a.mp3 b.mp3 c.mp3 [--gap 2] [--max-minutes 79]

Every track is decoded by ffmpeg to 16 bit stereo, 44.1 kHz, little endian and padded with silence to a whole number of sectors (2352 bytes, 75 a second). The first track starts
at the beginning of the file (emulators add the 2 second pregap of the disc themselves; --gap puts more silence in front). The .cue names the .bin next to it: both go to an emulator
(no$psx, DuckStation, PCSX-Redux) as the disc. ffmpeg has to be on the PATH (or at C:\\Program Files\\ffmpeg\\bin).
"""
import argparse
import os
import shutil
import subprocess
import sys

SECTOR = 2352
FPS = 75


def find_ffmpeg():
    p = shutil.which("ffmpeg")
    if p:
        return p
    for c in (r"C:\Program Files\ffmpeg\bin\ffmpeg.exe", "/c/Program Files/ffmpeg/bin/ffmpeg"):
        if os.path.exists(c):
            return c
    sys.exit("ffmpeg not found")


def decode(ff, path):
    r = subprocess.run([ff, "-v", "error", "-i", path, "-vn", "-f", "s16le", "-acodec", "pcm_s16le", "-ar", "44100", "-ac", "2", "-"],
                       capture_output=True)
    if r.returncode:
        sys.exit("ffmpeg failed on %s: %s" % (path, r.stderr.decode(errors="replace")))
    pcm = r.stdout
    pcm += b"\0" * (-len(pcm) % SECTOR)
    return pcm


def msf(sectors):
    return "%02d:%02d:%02d" % (sectors // (FPS * 60), sectors // FPS % 60, sectors % FPS)


def duration(ff, path):
    probe = os.path.join(os.path.dirname(ff), "ffprobe")
    r = subprocess.run([probe, "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path], capture_output=True, text=True)
    if r.returncode:
        sys.exit("ffprobe failed on %s" % path)
    return float(r.stdout.strip())


def write_disc(ff, out, tracks, gap):
    bin_path, cue_path = out + ".bin", out + ".cue"
    os.makedirs(os.path.dirname(os.path.abspath(bin_path)), exist_ok=True)
    pos = gap * FPS
    cue = ['FILE "%s" BINARY' % os.path.basename(bin_path)]
    with open(bin_path, "wb") as f:
        f.write(bytes(1) * (gap * FPS * SECTOR))
        for n, t in enumerate(tracks, 1):
            pcm = decode(ff, t)
            sec = len(pcm) // SECTOR
            cue.append("  TRACK %02d AUDIO" % n)
            cue.append("    TITLE \"%s\"" % os.path.splitext(os.path.basename(t))[0].replace('"', "'"))
            cue.append("    INDEX 01 %s" % msf(pos))
            f.write(pcm)
            print("  track %02d  %s  at %s  %s" % (n, msf(sec), msf(pos), os.path.basename(t)))
            pos += sec
    with open(cue_path, "w", encoding="utf-8", newline="") as c:
        c.write(("\r\n").join(cue) + "\r\n")
    print("disc %s, %d tracks, %d sectors: %s, %s" % (msf(pos), len(tracks), pos, bin_path, cue_path))
    return pos / FPS / 60


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", help="output name without extension (name.bin and name.cue; with --split name-1, name-2, ...)")
    ap.add_argument("tracks", nargs="+", help="the audio files, in track order")
    ap.add_argument("--gap", type=int, default=0, help="seconds of silence before the first track (default 0)")
    ap.add_argument("--max-minutes", type=float, default=80.0, help="refuse a disc longer than this (default 80)")
    ap.add_argument("--split", action="store_true", help="more discs, in order, each up to --max-minutes (the files are measured first)")
    a = ap.parse_args()
    ff = find_ffmpeg()
    if not a.split:
        if write_disc(ff, a.out, a.tracks, a.gap) > a.max_minutes:
            sys.exit("longer than %.0f minutes: use --split or fewer tracks" % a.max_minutes)
        return
    discs, cur, total = [], [], a.gap
    for t in a.tracks:
        d = duration(ff, t) + 1.0 / FPS
        if cur and (total + d) / 60 > a.max_minutes:
            discs.append(cur)
            cur, total = [], a.gap
        cur.append(t)
        total += d
    discs.append(cur)
    for n, d in enumerate(discs, 1):
        print("disc %d of %d" % (n, len(discs)))
        write_disc(ff, "%s-%d" % (a.out, n), d, a.gap)


if __name__ == "__main__":
    main()
