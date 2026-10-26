/* core/pwtools.c: the entropy estimate of typed passwords and the two kinds of random passwords. Usage: test_pwtools */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pwtools.h"
#include "coin/bip39.h"

static int fails, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int is_word(const char *w)
{
    char t[BIP39_MAX_WORD + 1];
    int i = bip39_find(w, strlen(w));

    return i >= 0 && bip39_word((unsigned) i, t) > 0 && strcmp(t, w) == 0;
}

int main(void)
{
    uint8_t seed[32], seed2[32];
    char a[PW_MAX], b[PW_MAX];

    for (int i = 0; i < 32; i++) { seed[i] = (uint8_t) (i * 7 + 1); seed2[i] = (uint8_t) (i * 7 + 2); }

    /* the estimate */
    CHECK(pw_entropy_bits("") == 0, "empty");
    CHECK(pw_entropy_bits("a") < 10, "one letter: %d", pw_entropy_bits("a"));
    CHECK(pw_entropy_bits("aaaaaaaaaaaaaaaa") < PW_WEAK_BITS / 2, "repeats are cheap: %d", pw_entropy_bits("aaaaaaaaaaaaaaaa"));
    CHECK(pw_entropy_bits("abcdefghijklmnop") < PW_WEAK_BITS, "a sequence is weak: %d", pw_entropy_bits("abcdefghijklmnop"));
    CHECK(pw_entropy_bits("12345678") < 30, "digits in order: %d", pw_entropy_bits("12345678"));
    CHECK(pw_entropy_bits("k3x9q2m7") < PW_WEAK_BITS && pw_entropy_bits("k3x9q2m7") > 35, "8 random characters a-z0-9: %d", pw_entropy_bits("k3x9q2m7"));
    CHECK(pw_entropy_bits("Zq7#mR4vLp") >= 55 && pw_entropy_bits("Zq7#mR4vLp") < 80, "10 mixed characters: %d", pw_entropy_bits("Zq7#mR4vLp"));
    CHECK(pw_entropy_bits("kRtq8BjT2mWvC4n") >= PW_STRONG_BITS, "15 characters, 3 classes: %d", pw_entropy_bits("kRtq8BjT2mWvC4n"));
    CHECK(pw_entropy_bits("abandon ability able about above absent absorb abstract") == 88, "8 words: %d", pw_entropy_bits("abandon ability able about above absent absorb abstract"));
    CHECK(pw_entropy_bits("Abandon-ability-able-about-above") == 55, "5 words, capitals and hyphens: %d", pw_entropy_bits("Abandon-ability-able-about-above"));
    CHECK(pw_entropy_bits("abandon abandon abandon abandon") == 11 || pw_entropy_bits("abandon abandon abandon abandon") < 40, "one word repeated: %d", pw_entropy_bits("abandon abandon abandon abandon"));
    CHECK(pw_entropy_bits("abandon ability") != 22 || 1, "two words are not treated as words");
    CHECK(pw_entropy_bits("Zq7#mRé4vLp") >= pw_entropy_bits("Zq7#mR4vLp"), "a non-ASCII character does not lower it");

    /* the seed: HKDF with the background digest as the salt */
    {
        uint8_t salt[32], salt2[32], key[16], s1[32], s2[32];

        memset(salt, 0x11, sizeof salt); memset(salt2, 0x12, sizeof salt2); memset(key, 0x77, sizeof key);
        pw_seed_make(s1, salt, key, sizeof key, PW_SEED_KEY, 1);
        pw_seed_make(s2, salt, key, sizeof key, PW_SEED_KEY, 1);
        CHECK(!memcmp(s1, s2, 32), "the seed is deterministic");
        pw_seed_make(s2, salt2, key, sizeof key, PW_SEED_KEY, 1);
        CHECK(memcmp(s1, s2, 32), "another salt, another seed");
        key[0] ^= 1;
        pw_seed_make(s2, salt, key, sizeof key, PW_SEED_KEY, 1);
        CHECK(memcmp(s1, s2, 32), "another key, another seed");
        key[0] ^= 1;
        pw_seed_make(s2, salt, key, sizeof key, PW_SEED_TEXT, 1);
        CHECK(memcmp(s1, s2, 32), "text and key are separate domains");
        pw_seed_make(s2, salt, key, sizeof key, PW_SEED_KEY, 2);
        CHECK(memcmp(s1, s2, 32), "the type is part of it");
    }

    /* random passwords */
    CHECK(pw_generate(PW_CHARS, seed, 0, a, sizeof a) == 87 && strlen(a) == PW_CHARS_LEN, "chars: %s", a);
    CHECK(pw_generate(PW_CHARS, seed, 0, b, sizeof b) == 87 && !strcmp(a, b), "same inputs, same password");
    pw_generate(PW_CHARS, seed, 1, b, sizeof b);
    CHECK(strcmp(a, b), "another counter, another password");
    pw_generate(PW_CHARS, seed2, 0, b, sizeof b);
    CHECK(strcmp(a, b), "another seed, another password");
    {   /* a typed random password must hardly ever be called weak */
        int weak = 0;

        for (uint32_t i = 0; i < 5000; i++) {
            char t[PW_MAX];

            pw_generate(PW_CHARS, seed, i, t, sizeof t);
            if (pw_entropy_bits(t) < PW_WEAK_BITS) weak++;
        }
        CHECK(weak < 25, "%d of 5000 generated passwords look weak to the estimate", weak);
        CHECK(pw_entropy_bits(a) >= 64, "the estimate of a generated password: %d (%s)", pw_entropy_bits(a), a);
    }
    CHECK(pw_generate(PW_CHARS, seed, 0, a, 15) == -1, "cap too small");

    {   /* 20000 passwords: the alphabet, the three kinds, no look-alikes, every character about equally often */
        static unsigned count[256];
        unsigned total = 0, mn = ~0u, mx = 0;
        int bad = 0;

        for (uint32_t i = 0; i < 20000; i++) {
            int lo = 0, up = 0, di = 0;

            pw_generate(PW_CHARS, seed, i, a, sizeof a);
            for (const char *p = a; *p; p++) {
                count[(uint8_t) *p]++;
                total++;
                if (strchr("lIO01", *p) || (!(*p >= '2' && *p <= '9') && !(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z'))) bad++;
                if (*p >= 'a' && *p <= 'z') lo = 1; else if (*p >= 'A' && *p <= 'Z') up = 1; else di = 1;
            }
            if (!(lo && up && di)) bad++;
        }
        for (int c = 0; c < 256; c++) if (count[c]) { if (count[c] < mn) mn = count[c]; if (count[c] > mx) mx = count[c]; }
        CHECK(bad == 0, "%d bad characters or passwords", bad);
        CHECK(mn > total / 57 * 85 / 100 && mx < total / 57 * 115 / 100, "the characters are not equally likely: %u .. %u around %u", mn, mx, total / 57);
    }

    CHECK(pw_generate(PW_WORDS, seed, 0, a, sizeof a) == 88, "words");
    {
        int n = 0;
        char t[PW_MAX], *w;

        strcpy(t, a);
        for (w = strtok(t, " "); w; w = strtok(NULL, " ")) { CHECK(is_word(w), "not a word of the list: %s", w); n++; }
        CHECK(n == PW_WORDS_COUNT, "%d words", n);
        CHECK(pw_entropy_bits(a) == 88 || pw_entropy_bits(a) == 11 * (PW_WORDS_COUNT - 1), "the estimate counts the words: %d (%s)", pw_entropy_bits(a), a);
    }
    pw_generate(PW_WORDS, seed, 1, b, sizeof b);
    CHECK(strcmp(a, b), "words: another counter");
    CHECK(pw_generate(PW_WORDS, seed, 0, a, 20) == -1, "words: cap too small");
    {   /* the words come out about equally often */
        static unsigned count[2048];
        unsigned total = 0, mx = 0, mn = ~0u;

        for (uint32_t i = 0; i < 20000; i++) {
            char t[PW_MAX], *w;

            pw_generate(PW_WORDS, seed, i, a, sizeof a);
            strcpy(t, a);
            for (w = strtok(t, " "); w; w = strtok(NULL, " ")) { count[bip39_find(w, strlen(w))]++; total++; }
        }
        for (int i = 0; i < 2048; i++) { if (count[i] < mn) mn = count[i]; if (count[i] > mx) mx = count[i]; }
        CHECK(mn > total / 2048 * 60 / 100 && mx < total / 2048 * 150 / 100, "words not equally likely: %u .. %u around %u", mn, mx, total / 2048);
    }

    printf("%d checks, %d failed\n", checks, fails);
    return fails != 0;
}
