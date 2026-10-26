"""Demo requests for the Orchard part of the signer: a slot 2 card with Zcash Orchard signing requests (PSXXRQ files) for the BIP39 test
mnemonic ("abandon abandon ... about", empty passphrase), account 0 (path m/32'/133'/0').

  python tools/orchard_demo.py <card.mcd> [24]   copy build/card/blank-slot2.mcd to <card.mcd> and put the demo requests on it; with 24 for a
                                                 wallet of 24 words and the passphrase TREZOR (typing it takes longer)

The notes are real Orchard notes made with the reference code of the Zcash foundation (build/refzcash): the signer opens the outputs with
the keys of the test mnemonic and checks them. The anchors, proofs and the rest of the transactions are random stand-ins, so the
signatures are valid RedPallas signatures of the signature hash, but the transactions are not for a live network."""
import os, shutil, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import psxx_tx
import gen_orchard_sign_vectors as g
from bip_utils import Bip39SeedGenerator

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# the harder wallet: 24 words and a passphrase (the typing takes minutes: time for the background build of the Sinsemilla table)
MNEMONIC24 = ("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful "
              "legal winner thank year wave sausage worth title")
PASSPHRASE24 = "TREZOR"


def main():
    if len(sys.argv) not in (2, 3):
        raise SystemExit(__doc__)
    shutil.copy(os.path.join(HERE, "..", "build", "card", "blank-slot2.mcd"), sys.argv[1])
    card = psxx_tx.load_card(sys.argv[1])
    hard = len(sys.argv) > 2 and sys.argv[2] == "24"
    seed = Bip39SeedGenerator(MNEMONIC24 if hard else MNEMONIC).Generate(PASSPHRASE24 if hard else "")
    if hard:
        print("24 words:", MNEMONIC24, "| passphrase:", PASSPHRASE24)
    W = g.Wallet(seed, 0)
    alice = g.FullViewingKey.from_spending_key(g.SpendingKey(bytes(range(32))))
    ZEC, fee = g.ZEC, 10000
    # 1. 1.5 ZEC to Alice from a note of 2 ZEC, the change back to us (internal address)
    spent = g.note_of(W.fvk, 0, 2 * ZEC)
    pay, change = g.note_of(alice, 0, ZEC + ZEC // 2), g.note_of(W.fvi, 0, ZEC // 2 - fee)
    c = g.build(seed, 0, 1, 2, fee, actions=[((spent, W.fvk), pay, W.fvk.ovk, None), (None, change, W.fvi.ovk, None)], notedata=[(1, spent, 2 * ZEC)])
    psxx_tx.add_file(card, psxx_tx.REQ_TAG, psxx_tx.make_request("zecu", 0, "m/32'/133'/0'", c.req))
    # 2. the same, but nothing is said about the note spent: the signer shows it as blind
    c = g.build(seed, 0, 1, 2, fee, actions=[((spent, W.fvk), pay, W.fvk.ovk, None), (None, change, W.fvi.ovk, None)])
    psxx_tx.add_file(card, psxx_tx.REQ_TAG, psxx_tx.make_request("zecu", 0, "m/32'/133'/0'", c.req))
    open(sys.argv[1], "wb").write(card)
    print("wrote", sys.argv[1], "- Alice's address:", g.ua(alice, 0))


if __name__ == "__main__":
    main()
