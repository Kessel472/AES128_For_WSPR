#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include "../../AES128_Encrypt.h"

void PrintHex(const uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(bytes[i]);
    }
    std::cout << std::dec;
}

bool TestMultiBlockKnownAnswer() {
    const uint8_t key[16] = {
        0x2B, 0x7E, 0x15, 0x16,
        0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88,
        0x09, 0xCF, 0x4F, 0x3C
    };

    uint8_t plaintext[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };

    const uint8_t expected[32] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
        0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf
    };

    uint8_t output[32] = {0};
    int status = AES128_Encrypt(key, plaintext, sizeof(plaintext), output, sizeof(output));
    if (status != 0) {
        std::cout << "[FAIL] Multi-block KAT returned status " << status << "\n";
        return false;
    }

    bool ok = std::memcmp(output, expected, sizeof(output)) == 0;
    std::cout << (ok ? "[PASS]" : "[FAIL]") << " Multi-block known-answer test\n";
    return ok;
}

bool TestInvalidInputLength() {
    const uint8_t key[16] = {0};
    uint8_t plaintext[15] = {0};
    uint8_t output[16] = {0};

    int status = AES128_Encrypt(key, plaintext, sizeof(plaintext), output, sizeof(output));
    bool ok = (status == -1);
    std::cout << (ok ? "[PASS]" : "[FAIL]") << " Reject non-16-byte-aligned input\n";
    return ok;
}

bool TestInsufficientOutputBuffer() {
    const uint8_t key[16] = {0};
    uint8_t plaintext[16] = {0};
    uint8_t output[8] = {0};

    int status = AES128_Encrypt(key, plaintext, sizeof(plaintext), output, sizeof(output));
    bool ok = (status == -1);
    std::cout << (ok ? "[PASS]" : "[FAIL]") << " Reject too-small output buffer\n";
    return ok;
}

bool TestInPlaceEncryption() {
    const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t buffer[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const uint8_t expected[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };

    int status = AES128_Encrypt(key, buffer, sizeof(buffer), buffer, sizeof(buffer));
    if (status != 0) {
        std::cout << "[FAIL] In-place encryption returned status " << status << "\n";
        return false;
    }

    bool ok = std::memcmp(buffer, expected, sizeof(buffer)) == 0;
    if (!ok) {
        std::cout << "[FAIL] In-place encryption mismatch\n  actual: ";
        PrintHex(buffer, sizeof(buffer));
        std::cout << "\n";
    } else {
        std::cout << "[PASS] In-place encryption\n";
    }
    return ok;
}

bool TestEncryptDecryptRoundTrip() {
    const uint8_t key[16] = {
        0x2B, 0x7E, 0x15, 0x16,
        0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88,
        0x09, 0xCF, 0x4F, 0x3C
    };

    uint8_t plaintext[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };

    uint8_t ciphertext[32] = {0};
    uint8_t recovered[32] = {0};

    const int enc_status = AES128_Encrypt(
        key,
        plaintext,
        sizeof(plaintext),
        ciphertext,
        sizeof(ciphertext)
    );
    if (enc_status != 0) {
        std::cout << "[FAIL] Encrypt/decrypt round-trip -> encrypt returned status " << enc_status << "\n";
        return false;
    }

    const int dec_status = AES128_Decrypt(key, ciphertext, sizeof(ciphertext), recovered, sizeof(recovered));
    if (dec_status != 0) {
        std::cout << "[FAIL] Encrypt/decrypt round-trip -> decrypt returned status " << dec_status << "\n";
        return false;
    }

    const bool ok = std::memcmp(recovered, plaintext, sizeof(plaintext)) == 0;
    std::cout << (ok ? "[PASS]" : "[FAIL]") << " Encrypt/decrypt round-trip\n";
    return ok;
}

int main() {
    int passed = 0;
    const int total = 5;

    std::cout << "Running AES system tests\n";
    if (TestMultiBlockKnownAnswer()) passed++;
    if (TestInvalidInputLength()) passed++;
    if (TestInsufficientOutputBuffer()) passed++;
    if (TestInPlaceEncryption()) passed++;
    if (TestEncryptDecryptRoundTrip()) passed++;

    std::cout << "Summary: " << passed << "/" << total << " passed\n";
    return (passed == total) ? 0 : 1;
}
