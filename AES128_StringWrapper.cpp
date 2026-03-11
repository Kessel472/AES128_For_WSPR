#include "AES128_StringWrapper.h"

#include "AES128_Encrypt.h"

int AES128_EncryptStringPKCS7(const uint8_t* key, const std::string& plaintext, std::vector<uint8_t>& ciphertext) {
    if (key == nullptr) {
        return -1;
    }

    constexpr size_t block_size = 16;
    const size_t pad_len = block_size - (plaintext.size() % block_size);

    std::vector<uint8_t> padded(plaintext.begin(), plaintext.end());
    padded.insert(padded.end(), pad_len, static_cast<uint8_t>(pad_len));

    ciphertext.resize(padded.size());

    return AES128_Encrypt(
        key,
        padded.data(),
        padded.size(),
        ciphertext.data(),
        ciphertext.size()
    );
}

int AES128_DecryptStringPKCS7(const uint8_t* key, const std::vector<uint8_t>& ciphertext, std::string& plaintext) {
    if (key == nullptr) {
        return -1;
    }

    constexpr size_t block_size = 16;
    if (ciphertext.empty() || (ciphertext.size() % block_size != 0)) {
        return -1;
    }

    std::vector<uint8_t> padded_plaintext(ciphertext.size());
    const int status = AES128_Decrypt(
        key,
        ciphertext.data(),
        ciphertext.size(),
        padded_plaintext.data(),
        padded_plaintext.size()
    );

    if (status != 0) {
        return status;
    }

    const uint8_t pad_len = padded_plaintext.back();
    if (pad_len == 0 || pad_len > block_size || pad_len > padded_plaintext.size()) {
        return -1;
    }

    const size_t data_size = padded_plaintext.size() - pad_len;
    for (size_t i = data_size; i < padded_plaintext.size(); i++) {
        if (padded_plaintext[i] != pad_len) {
            return -1;
        }
    }

    plaintext.assign(
        reinterpret_cast<const char*>(padded_plaintext.data()),
        data_size
    );

    return 0;
}
