#!/usr/bin/env python3
"""Emulator test matrix of the boot cards: one card set (a directory of tools/release.py cards), one BIOS after the other.

For every chosen BIOS the tool stops all emulators, sets the test environment of the chosen emulator (the BIOS image, the boot card in slot 1, the B card in slot 2,
fresh copies of the cards), starts it and waits for your verdict in the console:

    ok [summary]      the card boots and the program works
    bad [summary]     it does not
    skip              no verdict, the next BIOS
    again             start the same BIOS again (fresh cards)
    quit              stop; what is decided stays

The verdicts are in <set>/bios_matrix.json (every try, with the date) and <set>/bios_matrix.txt (the last verdict of every BIOS and emulator). The slot 2 card of
a run (it holds the PSXXCD logs of the program) is kept as <set>/matrix-logs/<bios>-<emulator>-slot2.mcd, the DuckStation TTY log next to it.

    py -3.13 tools/bios_matrix.py status  [--dir build/release/m42q]
    py -3.13 tools/bios_matrix.py build   [--dir ...] [--bios 4.1 ...]       # the missing boot cards (tools/release.py cards --minload); only when you want cards
    py -3.13 tools/bios_matrix.py run     [--dir ...] [--emu duckstation|nopsx|redux] [--bios 4.1 --bios 2.0-19950510-E | --bios pending|failed|all] [--slot2 B-ok.mcd] [--dry]

--bios takes a part of the name (4.1, 3.0-19961118-A, -E), 'pending' (no verdict yet for the emulator), 'failed' (the last verdict is bad) or 'all'. --dry only sets the
environment up (nothing is stopped or started, no verdict is asked).
"""
import argparse, binascii, datetime, hashlib, json, os, re, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BIOS_DIR = os.path.join(ROOT, "psxbios")
DEFAULT_BIOS = "2.0-19950510-E"                     # the boot card without a BIOS in its name (tools/release.py)

# the BIOS versions of FreePSXBoot's builder (toolchain/FreePSXBoot/builder/builder.cc): name, CRC32 of the 512 KB image
BIOSES = [
    ("1.0-19940922-I", 0x3b601fc8), ("1.1-19950122-I", 0x3539def6),
    ("2.0-19950507-A", 0x55847d8c), ("2.0-19950510-E", 0x9bb87c4b),
    ("2.1-19950717-A", 0xaff00f2f), ("2.1-19950717-E", 0x86c30531), ("2.1-19950717-I", 0xbc190209),
    ("2.2-19951204-A", 0x37157331), ("2.2-19951204-E", 0x1e26792f), ("2.2-19951204-I", 0x24fc7e17),
    ("3.0-19960909-I", 0xff3eeb8c), ("3.0-19961118-A", 0x8d8cb7e4), ("3.0-19970106-E", 0xd786f0b9),
    ("4.0-19970818-I", 0xec541cd0),
    ("4.1-19971114-A", 0xb7c43dad), ("4.1-19971216-A", 0x502224b6), ("4.1-19971216-E", 0x318178bf),
    ("4.3-20000311-I", 0xf2af798b),
    ("4.4-20000324-A", 0x6a0e22a0), ("4.4-20000324-E", 0x0bad7ea9),
    ("4.5-20000525-A", 0x171bdcec), ("4.5-20000525-E", 0x76b880e5),
]
EMUS = ("duckstation", "nopsx", "redux")
PROCS = ("duckstation-qt-x64-ReleaseLTCG.exe", "duckstation-qt-x64-ReleaseLTCG-Release.exe", "pcsx-redux.exe", "NO$PSX.EXE")
DS_DIR = os.path.join(ROOT, "toolchain", "duckstation")
NP_DIR = os.path.join(ROOT, "emulator", "npsx")
RX_DIR = os.path.join(ROOT, "emulator", "pcsx-redux")
RX_JSON = os.path.join(os.environ.get("APPDATA", ""), "pcsx-redux", "pcsx.json")


def die(msg):
    sys.exit("bios_matrix: " + msg)


# ---- the BIOS images -------------------------------------------------------------------------------------------------------------------------------------------------------

def find_images():
    """CRC32 -> path of an image of psxbios (and below: alt, .variants)"""
    found = {}
    for top, _dirs, files in os.walk(BIOS_DIR):
        for f in sorted(files):
            p = os.path.join(top, f)
            if os.path.getsize(p) != 512 * 1024:
                continue
            crc = binascii.crc32(open(p, "rb").read()) & 0xFFFFFFFF
            found.setdefault(crc, p)                 # the first one found (psxbios itself before alt)
    return found


# ---- the card set ----------------------------------------------------------------------------------------------------------------------------------------------------------

def set_dir(arg):
    if arg:
        d = arg if os.path.isabs(arg) else os.path.join(ROOT, arg)
        if not os.path.isdir(d):
            die("no such directory: %s" % d)
        return d
    best = None
    rel = os.path.join(ROOT, "build", "release")
    for n in os.listdir(rel):                        # the newest release directory with a boot card
        d = os.path.join(rel, n)
        cards = [f for f in os.listdir(d) if f.startswith("A-boot") and f.endswith(".mcd")] if os.path.isdir(d) else []
        if cards:
            t = max(os.path.getmtime(os.path.join(d, f)) for f in cards)
            if not best or t > best[0]:
                best = (t, d)
    if not best:
        die("no release directory with a boot card in build/release (--dir)")
    return best[1]


def boot_card(d, bios):
    for n in ("A-boot-%s-min.mcd" % bios, "A-boot-%s.mcd" % bios) + (("A-boot.mcd",) if bios == DEFAULT_BIOS else ()):
        if os.path.exists(os.path.join(d, n)):
            return n
    return None


# ---- the verdicts ----------------------------------------------------------------------------------------------------------------------------------------------------------

class Results:
    def __init__(self, d):
        self.d = d
        self.path = os.path.join(d, "bios_matrix.json")
        self.rows = json.load(open(self.path, encoding="utf-8"))["results"] if os.path.exists(self.path) else []

    def last(self, bios, emu):
        r = [x for x in self.rows if x["bios"] == bios and x["emu"] == emu]
        return r[-1] if r else None

    def add(self, bios, emu, result, summary, card):
        self.rows.append({"bios": bios, "emu": emu, "result": result, "summary": summary, "card": card, "time": datetime.datetime.now().isoformat(timespec="seconds")})
        self.save()

    def save(self):
        json.dump({"results": self.rows}, open(self.path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        open(os.path.join(self.d, "bios_matrix.txt"), "w", encoding="utf-8").write(self.table(None) + "\n")

    def table(self, emu_filter):
        lines = []
        for emu in EMUS:
            if emu_filter and emu != emu_filter:
                continue
            if not any(x["emu"] == emu for x in self.rows) and not emu_filter:
                continue
            lines.append("%s" % emu)
            n = {"ok": 0, "bad": 0, "skip": 0}
            for bios, _crc in BIOSES:
                r = self.last(bios, emu)
                if r:
                    n[r["result"]] = n.get(r["result"], 0) + 1
                lines.append("  %-16s %-8s %s%s" % (bios, r["result"].upper() if r else "-", r["summary"] if r else "", ("  [%s]" % r["time"]) if r and r["result"] != "skip" else ""))
            lines.append("  -> %d ok, %d bad, %d skipped, %d without verdict" % (n["ok"], n["bad"], n["skip"], len(BIOSES) - sum(n.values())))
        return "\n".join(lines) if lines else "(no verdicts yet)"


# ---- the emulators ---------------------------------------------------------------------------------------------------------------------------------------------------------

def stop_emulators():
    for p in PROCS:
        subprocess.run(["taskkill", "/F", "/IM", p], capture_output=True)
    time.sleep(2)
    out = subprocess.run(["tasklist"], capture_output=True, text=True).stdout.lower()
    left = [p for p in PROCS if p.lower() in out]
    if left:
        die("still running: %s" % ", ".join(left))


def set_ini(lines, section, key, value):
    """key = value in a section of an ini file (a list of lines), added if it is not there"""
    start = next((i for i, l in enumerate(lines) if l.strip() == "[%s]" % section), -1)
    if start < 0:
        lines += ["", "[%s]" % section, "%s = %s" % (key, value)]
        return
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("["):
            end = i
            break
    for i in range(start + 1, end):
        if re.match(r"^%s\s*=" % re.escape(key), lines[i]):
            lines[i] = "%s = %s" % (key, value)
            return
    lines.insert(end, "%s = %s" % (key, value))


def setup_duckstation(bios_img, c1, c2):
    ini = os.path.join(DS_DIR, "settings.ini")
    lines = open(ini, encoding="utf-8-sig").read().splitlines()
    name = os.path.basename(bios_img)
    for k in ("PathNTSCU", "PathNTSCJ", "PathPAL"):
        set_ini(lines, "BIOS", k, name)
    set_ini(lines, "BIOS", "SearchDirectory", os.path.dirname(bios_img))
    set_ini(lines, "BIOS", "TTYLogging", "true")
    set_ini(lines, "BIOS", "FastForwardBoot", "false")
    set_ini(lines, "BIOS", "PatchFastBoot", "false")
    set_ini(lines, "MemoryCards", "Card1Type", "Shared")
    set_ini(lines, "MemoryCards", "Card1Path", c1)
    set_ini(lines, "MemoryCards", "Card2Type", "Shared")
    set_ini(lines, "MemoryCards", "Card2Path", c2)
    set_ini(lines, "Logging", "LogToFile", "true")
    set_ini(lines, "Hotkeys", "SwapMemoryCards", "Keyboard/F5")
    open(ini, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    return ([os.path.join(DS_DIR, "duckstation-qt-x64-ReleaseLTCG.exe"), "-bios"], DS_DIR)


def setup_nopsx(bios_img, c1, c2):
    rom = os.path.join(NP_DIR, "PSX-BIOS.ROM")
    keep = rom + ".matrix-orig"
    if os.path.exists(rom) and not os.path.exists(keep):
        shutil.copy(rom, keep)
    shutil.copy(bios_img, rom)
    shutil.copy(c1, os.path.join(NP_DIR, "MEMCARD", "_01_1_A_.mcd"))
    shutil.copy(c2, os.path.join(NP_DIR, "MEMCARD", "_01_2_A_.mcd"))
    return ([os.path.join(NP_DIR, "NO$PSX.EXE")], NP_DIR)


def setup_redux(bios_img, c1, c2):
    j = json.load(open(RX_JSON, encoding="utf-8"))
    e = j["emulator"]
    e["Bios"] = bios_img
    e["BiosPath"] = os.path.dirname(bios_img)
    e["Mcd1"], e["Mcd1Inserted"] = c1, True
    e["Mcd2"], e["Mcd2Inserted"] = c2, True
    e["PsxExe"] = ""
    json.dump(j, open(RX_JSON, "w", encoding="utf-8"), indent=2)
    return ([os.path.join(RX_DIR, "pcsx-redux.exe"), "-run"], RX_DIR)


SETUP = {"duckstation": setup_duckstation, "nopsx": setup_nopsx, "redux": setup_redux}


# ---- the commands ----------------------------------------------------------------------------------------------------------------------------------------------------------

def pick(spec, res, emu):
    names = [b for b, _ in BIOSES]
    if not spec or "all" in spec:
        return names
    out = []
    for s in spec:
        if s == "pending":
            out += [b for b in names if not res.last(b, emu) or res.last(b, emu)["result"] == "skip"]
        elif s == "failed":
            out += [b for b in names if res.last(b, emu) and res.last(b, emu)["result"] == "bad"]
        else:
            m = [b for b in names if s in b]
            if not m:
                die("no BIOS matches '%s' (list: %s)" % (s, ", ".join(names)))
            out += m
    return [b for b in names if b in out]


def cmd_status(a):
    d = set_dir(a.dir)
    res = Results(d)
    imgs = find_images()
    print("card set: %s" % d)
    for bios, crc in BIOSES:
        c = boot_card(d, bios)
        stale = c and os.path.getmtime(os.path.join(d, c)) < os.path.getmtime(os.path.join(d, "base.exe")) - 1
        print("  %-16s image %-3s boot card %s%s" % (bios, "yes" if crc in imgs else "NO", c or "-", "   OLDER THAN base.exe" if stale else ""))
    print()
    print(res.table(None))


def cmd_build(a):
    d = set_dir(a.dir)
    imgs = find_images()
    res = Results(d)
    for bios in pick(a.bios, res, a.emu):
        if os.path.exists(os.path.join(d, "A-boot-%s-min.mcd" % bios)):
            continue
        packed = os.path.join(d, "base_packed.exe")
        if not os.path.exists(packed) or os.path.getmtime(packed) < os.path.getmtime(os.path.join(d, "base.exe")):
            print("base_packed.exe missing or older than base.exe: release.py cards (packs it and makes B-ok, B-damaged, B-empty)")
            subprocess.run([sys.executable, os.path.join(HERE, "release.py"), "cards", d, "--bios", bios, "--minload"], check=True)
            continue
        print("boot card for", bios)                # the packed base is there: only FreePSXBoot's builder, with the minimal stage2
        sys.path.insert(0, os.path.join(HERE, "stage2min"))
        import build as s2build
        subprocess.run([os.path.join(ROOT, "toolchain", "FreePSXBoot", "builder", "builder.exe"), "-bios", bios, "-slot", "1", "-minload",
                        s2build.build(os.path.join(ROOT, "build", "stage2min")), "-in", packed, "-out", os.path.join(d, "A-boot-%s-min.mcd" % bios)], check=True)


def cmd_run(a):
    d = set_dir(a.dir)
    res = Results(d)
    imgs = find_images()
    todo = pick(a.bios, res, a.emu)
    work = os.path.join(ROOT, "build", "matrix")
    logs = os.path.join(d, "matrix-logs")
    os.makedirs(work, exist_ok=True)
    os.makedirs(logs, exist_ok=True)
    slot2 = os.path.join(d, a.slot2)
    if not os.path.exists(slot2):
        die("slot 2 card not found: %s" % slot2)
    print("card set %s, emulator %s, slot 2 card %s" % (d, a.emu, a.slot2))
    print(res.table(a.emu))
    print()
    for bios in todo:
        crc = dict(BIOSES)[bios]
        card = boot_card(d, bios)
        if crc not in imgs:
            print("%s: no BIOS image in psxbios, skipped" % bios)
            continue
        if not card:
            print("%s: no boot card in the set (bios_matrix.py build), skipped" % bios)
            continue
        if os.path.getmtime(os.path.join(d, card)) < os.path.getmtime(os.path.join(d, "base.exe")) - 1:
            print("%s: the boot card is older than base.exe of the set (bios_matrix.py build), skipped" % bios)
            continue
        if a.emu == "nopsx" and card.endswith("-min.mcd"):
            print("  (note: the fastload boot card does not boot in no$psx, see psx-x-environment)")
        while True:
            c1 = os.path.join(work, "%s-slot1.mcd" % a.emu)
            c2 = os.path.join(work, "%s-slot2.mcd" % a.emu)
            if not a.dry:
                stop_emulators()
            shutil.copy(os.path.join(d, card), c1)
            shutil.copy(slot2, c2)
            cmd, cwd = SETUP[a.emu](imgs[crc], c1, c2)
            print("== %s: BIOS %s, boot card %s" % (bios, os.path.basename(imgs[crc]), card))
            if a.dry:
                print("   environment set (%s), not started: %s" % (a.emu, " ".join(cmd)))
                break
            if a.emu == "duckstation":
                open(os.path.join(DS_DIR, "duckstation.log"), "w").close()
            subprocess.Popen(cmd, cwd=cwd)
            ans = ""
            while True:
                line = input("   [ok / bad / skip / again / quit] [summary] > ").strip()
                ans, _, note = line.partition(" ")
                ans = ans.lower()
                if ans in ("ok", "bad", "skip", "again", "quit", "q", "s"):
                    break
                print("   ok, bad, skip, again or quit")
            note = note.strip()
            stop_emulators()
            tag = "%s-%s" % (bios, a.emu)
            shutil.copy(c2, os.path.join(logs, "%s-slot2.mcd" % tag))
            if a.emu == "duckstation" and os.path.exists(os.path.join(DS_DIR, "duckstation.log")):
                shutil.copy(os.path.join(DS_DIR, "duckstation.log"), os.path.join(logs, "%s.log" % tag))
            if ans == "again":
                continue
            if ans in ("quit", "q"):
                print(res.table(a.emu))
                return
            if ans in ("skip", "s"):
                ans = "skip"
            res.add(bios, a.emu, ans, note, card)
            print(res.table(a.emu))
            break
    print("done")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("status", "build", "run"):
        p = sub.add_parser(n)
        p.add_argument("--dir", help="the card set (default: the newest build/release/* with a boot card)")
        if n != "status":
            p.add_argument("--bios", action="append", help="part of a BIOS name, pending, failed or all (default all)")
            p.add_argument("--emu", choices=EMUS, default="duckstation")
        if n == "run":
            p.add_argument("--slot2", default="B-ok.mcd", help="the card of slot 2 from the set (default B-ok.mcd)")
            p.add_argument("--dry", action="store_true", help="set the environment up only")
    a = ap.parse_args()
    {"status": cmd_status, "build": cmd_build, "run": cmd_run}[a.cmd](a)


if __name__ == "__main__":
    main()
