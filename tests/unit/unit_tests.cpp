#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include "../../AES128_Encrypt.h"
#include "../../AES128_StringWrapper.h"

struct UnitVector {
    const char* name;
    uint8_t key[16];
    uint8_t plaintext[16];
    uint8_t expected[16];
};

void PrintHex(const uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(bytes[i]);
    }
    std::cout << std::dec;
}

bool RunVector(const UnitVector& vector) {
    uint8_t input[16];
    std::memcpy(input, vector.plaintext, sizeof(input));

    uint8_t output[16] = {0};
    int status = AES128_Encrypt(vector.key, input, sizeof(input), output, sizeof(output));

    if (status != 0) {
        std::cout << "[FAIL] " << vector.name << " -> AES128_Encrypt returned " << status << "\n";
        return false;
    }

    bool passed = std::memcmp(output, vector.expected, sizeof(output)) == 0;
    if (!passed) {
        std::cout << "[FAIL] " << vector.name << "\n  expected: ";
        PrintHex(vector.expected, sizeof(output));
        std::cout << "\n  actual:   ";
        PrintHex(output, sizeof(output));
        std::cout << "\n";
    } else {
        std::cout << "[PASS] " << vector.name << "\n";
    }

    return passed;
}

bool RunDecryptVector(const UnitVector& vector) {
    uint8_t output[16] = {0};
    int status = AES128_Decrypt(vector.key, vector.expected, sizeof(vector.expected), output, sizeof(output));

    if (status != 0) {
        std::cout << "[FAIL] " << vector.name << " decrypt -> AES128_Decrypt returned " << status << "\n";
        return false;
    }

    bool passed = std::memcmp(output, vector.plaintext, sizeof(output)) == 0;
    if (!passed) {
        std::cout << "[FAIL] " << vector.name << " decrypt\n  expected: ";
        PrintHex(vector.plaintext, sizeof(output));
        std::cout << "\n  actual:   ";
        PrintHex(output, sizeof(output));
        std::cout << "\n";
    } else {
        std::cout << "[PASS] " << vector.name << " decrypt\n";
    }

    return passed;
}

bool RunWrapperPKCS7Test() {
    const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

    const std::string plaintext = "1234567890abcde";
    std::vector<uint8_t> wrapped_output;

    const int wrapped_status = AES128_EncryptStringPKCS7(key, plaintext, wrapped_output);
    if (wrapped_status != 0) {
        std::cout << "[FAIL] Wrapper PKCS#7 15-byte input -> AES128_EncryptStringPKCS7 returned "
                  << wrapped_status << "\n";
        return false;
    }

    if (wrapped_output.size() != 16) {
        std::cout << "[FAIL] Wrapper PKCS#7 15-byte input -> expected ciphertext size 16, got "
                  << wrapped_output.size() << "\n";
        return false;
    }

    uint8_t padded_input[16] = {0};
    std::memcpy(padded_input, plaintext.data(), plaintext.size());
    padded_input[15] = 0x01;

    uint8_t expected_output[16] = {0};
    const int direct_status = AES128_Encrypt(
        key,
        padded_input,
        sizeof(padded_input),
        expected_output,
        sizeof(expected_output)
    );

    if (direct_status != 0) {
        std::cout << "[FAIL] Wrapper PKCS#7 15-byte input -> AES128_Encrypt returned "
                  << direct_status << "\n";
        return false;
    }

    const bool passed = std::memcmp(wrapped_output.data(), expected_output, sizeof(expected_output)) == 0;
    if (!passed) {
        std::cout << "[FAIL] Wrapper PKCS#7 15-byte input\n  expected: ";
        PrintHex(expected_output, sizeof(expected_output));
        std::cout << "\n  actual:   ";
        PrintHex(wrapped_output.data(), wrapped_output.size());
        std::cout << "\n";
    } else {
        std::cout << "[PASS] Wrapper PKCS#7 15-byte input\n";
    }

    return passed;
}

bool RunWrapperNullKeyTest() {
    std::vector<uint8_t> output;
    const int status = AES128_EncryptStringPKCS7(nullptr, "hello", output);

    const bool passed = (status == -1);
    if (!passed) {
        std::cout << "[FAIL] Wrapper rejects null key -> expected -1, got " << status << "\n";
    } else {
        std::cout << "[PASS] Wrapper rejects null key\n";
    }

    return passed;
}

bool RunWrapperDecryptRoundTripTest() {
    const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

    const std::string original = "round trip wrapper test";
    std::vector<uint8_t> ciphertext;
    std::string recovered;

    const int enc_status = AES128_EncryptStringPKCS7(key, original, ciphertext);
    if (enc_status != 0) {
        std::cout << "[FAIL] Wrapper decrypt round-trip -> encrypt returned " << enc_status << "\n";
        return false;
    }

    const int dec_status = AES128_DecryptStringPKCS7(key, ciphertext, recovered);
    if (dec_status != 0) {
        std::cout << "[FAIL] Wrapper decrypt round-trip -> decrypt returned " << dec_status << "\n";
        return false;
    }

    const bool passed = (recovered == original);
    if (!passed) {
        std::cout << "[FAIL] Wrapper decrypt round-trip -> recovered text mismatch\n";
    } else {
        std::cout << "[PASS] Wrapper decrypt round-trip\n";
    }

    return passed;
}

bool RunWrapperDecryptInvalidPaddingTest() {
    const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

    std::vector<uint8_t> ciphertext;
    std::string recovered;

    const int enc_status = AES128_EncryptStringPKCS7(key, "pad-check", ciphertext);
    if (enc_status != 0) {
        std::cout << "[FAIL] Wrapper decrypt invalid padding -> encrypt returned " << enc_status << "\n";
        return false;
    }

    ciphertext.back() = 0x00;
    const int dec_status = AES128_DecryptStringPKCS7(key, ciphertext, recovered);

    const bool passed = (dec_status == -1);
    if (!passed) {
        std::cout << "[FAIL] Wrapper decrypt invalid padding -> expected -1, got " << dec_status << "\n";
    } else {
        std::cout << "[PASS] Wrapper decrypt invalid padding\n";
    }

    return passed;
}

int main() {
    const UnitVector vectors[] = {
        {
            "NIST FIPS-197 single block",
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
            {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
             0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}
        },
        {
            "All-zero key and plaintext",
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
             0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e}
        }
    };

    int passed = 0;
    const int vector_total = static_cast<int>(sizeof(vectors) / sizeof(vectors[0]));
    const int decrypt_vector_total = vector_total;
    const int wrapper_total = 4;
    const int total = vector_total + decrypt_vector_total + wrapper_total;

    std::cout << "Running AES unit tests (" << total << " vectors)\n";
    for (const UnitVector& vector : vectors) {
        if (RunVector(vector)) {
            passed++;
        }
    }

    for (const UnitVector& vector : vectors) {
        if (RunDecryptVector(vector)) {
            passed++;
        }
    }

    if (RunWrapperPKCS7Test()) {
        passed++;
    }

    if (RunWrapperNullKeyTest()) {
        passed++;
    }

    if (RunWrapperDecryptRoundTripTest()) {
        passed++;
    }

    if (RunWrapperDecryptInvalidPaddingTest()) {
        passed++;
    }

    std::cout << "Summary: " << passed << "/" << total << " passed\n";
    return (passed == total) ? 0 : 1;
}
