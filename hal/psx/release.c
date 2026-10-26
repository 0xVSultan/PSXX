#include "release.h"

const psxx_release psxx_release_info __attribute__((section(".psxx_release"), used, aligned(4))) = {
    .magic = {'P', 'S', 'X', 'X', 'R', 'E', 'L', '1'},
};
