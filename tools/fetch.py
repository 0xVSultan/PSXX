#!/usr/bin/env python3
"""Fetches what the repository does not carry: the downloaded sources of the generators (word lists, fonts: tools/SOURCES.md) and the Windows toolchain (toolchain/).

  py -3.13 tools/fetch.py sources            word lists and fonts -> tools/wordlist_dl, tools/wordlist_dl_xmr, tools/font_dl, tools/font_dl_terminus
  py -3.13 tools/fetch.py toolchain          PSn00bSDK 0.24, gcc 12.3 for mipsel, FreePSXBoot with the patched builder -> toolchain/
  py -3.13 tools/fetch.py all
  py -3.13 tools/fetch.py all --check        only check what is there (SHA-256), download nothing

Every download is checked against a SHA-256 that is written here; a file that does not match is deleted and the run stops. The `toolchain` step needs git and
g++ (MSYS2 ucrt64, see BUILD.md) on the PATH. Nothing is installed outside this directory tree."""
import argparse, gzip, hashlib, os, shutil, subprocess, sys, tarfile, urllib.request, zipfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
BIP39 = "https://raw.githubusercontent.com/bitcoin/bips/befa252b515d4104157bc57d3797050da51627fc/bip-0039/%s.txt"       # fixed commits, not master: the files cannot change under the SHA-256 sums
XMR = "https://raw.githubusercontent.com/monero-project/monero/c8699f2468aa81909182ce7060b340d5d7928039/src/mnemonics/%s"
SDK_REL = "https://github.com/Lameguy64/PSn00bSDK/releases/download/v0.24/"
# The toolchain archives can also come from a mirror of this project (the release assets of its repository): the same files, the same SHA-256. Set MIRROR here or the
# environment variable PSXX_MIRROR to the directory URL (ending in /); it is tried first, the upstream URL after it.
MIRROR = "https://github.com/0xVSultan/PSXX/releases/download/toolchain-0.24/"
FREEPSXBOOT = ("https://github.com/brad-lin/FreePSXBoot.git", "1976b3cadf1289d92eafd4a7eaf006b29c333c12")

BIP39_LISTS = {
    "chinese_simplified": "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726",
    "chinese_traditional": "417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f",
    "czech": "7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc",
    "english": "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
    "french": "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59",
    "italian": "d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2",
    "japanese": "2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd",
    "korean": "9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60",
    "portuguese": "2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f",
    "spanish": "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b",
}
XMR_LISTS = {
    "chinese_simplified.h": "4a38fbe7279616aa78aa11dbcf425d0ba5305fd2089cb4421d544f2c540d50fd",
    "dutch.h": "775d05f737f453d6798876d99961bb3bcfc49d47cb57860d3c0b2a03b9a64822",
    "english.h": "9bd756d29e689aae0e6e7f8b1196c4f35df350225c4668d4f6f41842f05fc2ca",
    "english_old.h": "20c9090994c5b441f2e550cddbf266d604b64e495d9b172e45a8031e1aa5d578",
    "esperanto.h": "382d9f9bfcf293e4dc9f156042fe5a3f2a151191bae368a494eaf53c77e16043",
    "french.h": "f4e42ab4eb9824a2cd829f132e33dfc46ae31c5788a37c9726d393e7cc809a82",
    "german.h": "7b910a96bc94d19eb3e4edd8179db383a68b03a7608396bbee0fdc46a7d4e88e",
    "italian.h": "d02956b528db827646a1f6f78c1a19716b9334985cb893eb09409834a04045db",
    "japanese.h": "3701f067006b60e95e266e7a385b472c5bddeb6f476e737eed6d3b7febefe6d5",
    "lojban.h": "6c84dedd2609060f30368b92b5e377207e28afcda5401b5060d57c633e623a04",
    "portuguese.h": "0a6b191930a29f1ae827c1f5f8905548035bac5e5b41386f0978cf39e4adcfa1",
    "russian.h": "2d3f282d11e917fcdd6248b87002f5b982b6abaa773e9676d21886b6a50a4762",
    "spanish.h": "994a941260f53e066753204f4b92c20bb1d830b58e76ff89c2caa71c34d546ef",
    "language_base.h": "2bc256f01c6904af914cb7c6526254267ed463882e216fd0eb1d9bbdf4bf5bb4",
    "singleton.h": "f540c185cd745a39e6780916163e3710ea20e8e97569e842b5b15e80adfb2256",
    "electrum-words.cpp": "f92675503096425c92f6cc8b38946a707db6999cfcd95657f87a58d364051e4f",
}
UNIFONT = ("https://unifoundry.com/pub/unifont/unifont-18.0.01/font-builds/unifont-18.0.01.hex.gz", "tools/font_dl/unifont/unifont-18.0.01.hex.gz",
           "e66385c79a0b8b24a466f3129930e08a966a935b4bf3b28c6bb17a9df9bf791d")
TERMINUS = ("https://sourceforge.net/projects/terminus-font/files/terminus-font-4.49/terminus-font-4.49.1.tar.gz/download", "tools/font_dl_terminus/terminus-font-4.49.1.tar.gz",
            "d961c1b781627bf417f9b340693d64fc219e0113ad3a3af1a3424c7aa373ef79")
SDK = (SDK_REL + "PSn00bSDK-0.24-win32.zip", "toolchain/dl/PSn00bSDK-0.24-win32.zip", "13a355afa89ecb2505882388841c42d9d231d40bbbe9ae22eb5e16abe19b2ea7")
GCC = (SDK_REL + "gcc-mipsel-none-elf-12.3.0-windows.zip", "toolchain/dl/gcc-mipsel-none-elf-12.3.0-windows.zip", "51df48145d5ef4b396d3932b72ccba538cc605c7c7745b32c58c277aa00523c5")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def get(url, rel, want, check, mirrored=False):
    """The file rel (under the root) with the SHA-256 want: there already, or downloaded. Returns True when it is there and right. mirrored: the mirror is tried first."""
    path = os.path.join(ROOT, rel)
    if os.path.exists(path):
        if sha256(path) == want:
            print("ok       ", rel)
            return True
        print("DIFFERENT", rel, "(SHA-256 is not the one that is expected)")
        if check:
            return False
        os.remove(path)
    elif check:
        print("MISSING  ", rel)
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mirror = os.environ.get("PSXX_MIRROR", MIRROR)
    urls = ([mirror + os.path.basename(rel)] if mirrored and mirror else []) + [url]
    for u in urls:
        print("download ", u)
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "psxx-fetch"})
            with urllib.request.urlopen(req) as r, open(path, "wb") as f:
                shutil.copyfileobj(r, f)
        except OSError as e:
            print("         failed:", e)
            continue
        if sha256(path) == want:
            return True
        os.remove(path)
        print("         the SHA-256 is not the expected one: the file was deleted")
    sys.exit("could not get %s with the expected SHA-256 (the upstream file may have changed or gone; see tools/SOURCES.md and BUILD.md)" % rel)


def sources(check):
    ok = True
    for n, h in BIP39_LISTS.items():
        ok &= get(BIP39 % n, "tools/wordlist_dl/%s.txt" % n, h, check)
    for n, h in XMR_LISTS.items():
        ok &= get(XMR % n, "tools/wordlist_dl/monero/%s" % n, h, check)
    en = os.path.join(ROOT, "tools", "wordlist_dl_xmr", "english.h")                       # the same file as monero/english.h
    if not check and os.path.exists(os.path.join(ROOT, "tools", "wordlist_dl", "monero", "english.h")):
        os.makedirs(os.path.dirname(en), exist_ok=True)
        shutil.copyfile(os.path.join(ROOT, "tools", "wordlist_dl", "monero", "english.h"), en)
    ok &= get(*UNIFONT, check)
    ok &= get(*TERMINUS, check)
    src = os.path.join(ROOT, "tools", "font_dl_terminus", "src")
    if not check and not os.path.isdir(os.path.join(src, "terminus-font-4.49.1")):
        with tarfile.open(os.path.join(ROOT, TERMINUS[1])) as t:
            t.extractall(src, filter="data")
    return ok


def toolchain(check):
    ok = get(*SDK, check, mirrored=True) and get(*GCC, check, mirrored=True)
    if check:
        for rel in ("toolchain/sdk/PSn00bSDK-0.24-win32/bin", "toolchain/gcc/bin", "toolchain/FreePSXBoot/builder/builder.exe"):
            e = os.path.exists(os.path.join(ROOT, rel))
            print("ok       " if e else "MISSING  ", rel)
            ok &= e
        return ok
    for z, d in ((SDK[1], "toolchain/sdk"), (GCC[1], "toolchain/gcc")):
        probe = os.path.join(ROOT, d, "PSn00bSDK-0.24-win32", "bin") if "sdk" in d else os.path.join(ROOT, d, "bin")
        if not os.path.isdir(probe):
            print("unpack   ", z, "->", d)
            zipfile.ZipFile(os.path.join(ROOT, z)).extractall(os.path.join(ROOT, d))
    fp = os.path.join(ROOT, "toolchain", "FreePSXBoot")
    if not os.path.isdir(os.path.join(fp, ".git")):
        subprocess.run(["git", "clone", "--quiet", FREEPSXBOOT[0], fp], check=True)
    subprocess.run(["git", "-C", fp, "checkout", "--quiet", FREEPSXBOOT[1]], check=True)
    b = os.path.join(fp, "builder")
    patched = os.path.join(ROOT, "tools", "stage2min", "builder.cc.patched")       # the builder that keeps the whole payload of a card (see BUILD.md)
    shutil.copyfile(patched, os.path.join(b, "builder.cc"))
    print("compile   toolchain/FreePSXBoot/builder/builder.exe")
    subprocess.run(["g++", "-include", "cstring", "-o", "builder.exe", "builder.cc", "-std=c++17", "-I."], cwd=b, check=True)
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("what", choices=("sources", "toolchain", "all"))
    ap.add_argument("--check", action="store_true", help="check what is there, download nothing")
    a = ap.parse_args()
    ok = True
    if a.what in ("sources", "all"): ok &= sources(a.check)
    if a.what in ("toolchain", "all"): ok &= toolchain(a.check)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
