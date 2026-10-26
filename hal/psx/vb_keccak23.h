#pragma once
#include <stdint.h>

/* the last 20 bytes of keccak256(pub64): an Ethereum address */
void vk_eth_address(const uint8_t pub64[64], uint8_t out20[20]);
