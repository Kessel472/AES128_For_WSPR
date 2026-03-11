#pragma once

#include <cstdint>
#include <string>
#include <vector>

int AES128_EncryptStringPKCS7(const uint8_t* key, const std::string& plaintext, std::vector<uint8_t>& ciphertext);
int AES128_DecryptStringPKCS7(const uint8_t* key, const std::vector<uint8_t>& ciphertext, std::string& plaintext);
