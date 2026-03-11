#pragma once

#include <cstddef>
#include <cstdint>

int AES128_Encrypt(const uint8_t* key, uint8_t* input, size_t in_size, uint8_t* output, size_t out_size);
int AES128_Decrypt(const uint8_t* key, const uint8_t* input, size_t in_size, uint8_t* output, size_t out_size);
