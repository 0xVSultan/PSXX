"""Demo cards for the Monero part of the signer: slot 2 card with Monero signing requests (PSXXRQ files) for the demo wallet whose
25 words are printed by this script.

  python tools/xmr_demo.py <card.mcd>        copy build/card/blank-slot2.mcd to <card.mcd>, put the demo requests on it

The wallet is a test wallet (the seed is in this file): never put money on it. The requests are what a view-only wallet would send;
the ring members and the range proof are random stand-ins, so the signatures are valid CLSAGs but the transactions are not for a
live network."""
import os, shutil, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import psxx_tx
from xmr_tx import *

SEED = bytes.fromhex('3d4c1c8a1f0e6b7a9c2d5e8f10213243546576879aabbccddeeff00112233405')
TOOL = os.path.join(HERE, '..', 'build', 'host', 'xmr_tool.exe')


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    words = subprocess.run([TOOL, 'words', SEED.hex()], capture_output=True, text=True, check=True).stdout.strip()
    print('Demo wallet, the 25 words:\n  ' + words)
    shutil.copy(os.path.join(HERE, '..', 'build', 'card', 'blank-slot2.mcd'), sys.argv[1])
    card = psxx_tx.load_card(sys.argv[1])
    rng = Rng(b'psxx xmr demo')
    b, a, B, A = keys(SEED)
    XMR = 10 ** 12
    fee = 41000000
    other = keys(b'\x42' * 32)
    # a small payment: one input, ring 16, a payment and the change
    req, info = build(SEED, [dict(n=16, l=9, amount=3 * XMR + 500000000000)],
                      [make_output(NET_STD, other[2], other[3], 1 * XMR + 250000000000),
                       make_output(NET_STD, B, A, 2 * XMR + 250000000000 - fee)], fee, rng)
    psxx_tx.add_file(card, psxx_tx.REQ_TAG, psxx_tx.make_request('xmr', 0, '', req))
    # two inputs
    req, info = build(SEED, [dict(n=16, l=2, amount=XMR), dict(n=16, l=14, amount=2 * XMR)],
                      [make_output(NET_STD, other[2], other[3], 2 * XMR),
                       make_output(NET_STD, B, A, XMR - fee)], fee, rng)
    psxx_tx.add_file(card, psxx_tx.REQ_TAG, psxx_tx.make_request('xmr', 0, '', req))
    open(sys.argv[1], 'wb').write(card)
    print('wrote', sys.argv[1])


if __name__ == '__main__':
    main()
