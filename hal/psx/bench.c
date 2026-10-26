/* Timing/size probe for the crypto core on the PSX. Output goes to the TTY (printf).
 * Time base: VSync counter (VBlank, 50 Hz PAL / 60 Hz NTSC). Run as a plain exe in an emulator or on hardware. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <psxgpu.h>
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "hash/keccak.h"
#include "ec/secp256k1.h"
#include "ec/ed25519.h"
#include "coin/xmr.h"
#include "coin/bip32.h"
#include "coin/bip39.h"
#include "coin/orchard.h"

static int hz;
static uint8_t buf[256], out[64];

/* ms per operation = frames * 1000 / hz / reps */
#define TIME(label, reps, ...) do {                                              \
    int t0 = VSync(-1);                                                           \
    for (int r_ = 0; r_ < (reps); r_++) { __VA_ARGS__; }                                 \
    int dt = VSync(-1) - t0;                                                      \
    int ms = dt * 1000 / hz / (reps);                                             \
    printf("%-34s %3d x: %6d frames, %d ms each\n", label, (reps), dt, ms);       \
} while (0)

int main(void)
{
    ResetGraph(0);
    hz = (GetVideoMode() == MODE_PAL) ? 50 : 60;
    printf("psxx bench (%d Hz frame counter)\n", hz);
    for (int i = 0; i < 256; i++) buf[i] = (uint8_t)i;
    VSync(0);

    TIME("sha256 (256 B)", 200, sha256(buf, 256, out));
    TIME("sha512 (256 B)", 100, sha512(buf, 256, out));
    TIME("keccak256 (256 B)", 200, keccak256(buf, 256, out));
    TIME("pbkdf2-hmac-sha512 2048 iter", 1, pbkdf2_hmac_sha512(buf, 16, buf, 16, 2048, out, 64));
    TIME("secp256k1 k*G, first (builds table)", 1, { uint8_t p[33]; buf[0] = 1; secp256k1_pubkey_create(p, buf); });
    TIME("secp256k1 k*G, table ready", 8, { uint8_t p[33]; buf[0] = 3; secp256k1_pubkey_create(p, buf); buf[0]++; });
    TIME("ed25519 base, first (builds table)", 1, { uint8_t p[32]; ed25519_scalarmult_base(p, buf); });
    TIME("ed25519 base, table ready", 8, { uint8_t p[32]; buf[0]++; ed25519_scalarmult_base(p, buf); });
    TIME("xmr keys + address", 1, { xmr_keys k; char a[100]; xmr_keys_from_seed(&k, buf); xmr_address(a, sizeof a, 0x12, k.spend_pub, k.view_pub); });
    TIME("bip32 master + 5 levels", 1, {
        bip32_node n; uint32_t path[5] = {44 | BIP32_HARDENED, BIP32_HARDENED, BIP32_HARDENED, 0, 0};
        bip32_master(&n, buf, 32); bip32_derive_path(&n, path, 5); });
    TIME("bip39 entropy->mnemonic->entropy", 10, {
        char m[BIP39_MAX_MNEMONIC]; uint8_t e[32];
        bip39_entropy_to_mnemonic(buf, 32, m, sizeof m); bip39_mnemonic_to_entropy(m, e); });
    TIME("bip39 mnemonic->seed", 1, { uint8_t sd[64]; bip39_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "TREZOR", sd); });
    TIME("zcash orchard m/32'/133'/0' + address", 1, {
        uint8_t sk[32], ch[32], j0[11] = {0}, d[11], addr[43]; orchard_fvk f;
        orchard_master(sk, ch, buf, 64);
        orchard_child(sk, ch, 0x80000000u | 32); orchard_child(sk, ch, 0x80000000u | 133); orchard_child(sk, ch, 0x80000000u);
        orchard_fvk_from_sk(&f, sk); orchard_diversifier(d, f.dk, j0); orchard_address(addr, &f, d); });
    printf("bench done\n");
    for (;;) VSync(0);
    return 0;
}
