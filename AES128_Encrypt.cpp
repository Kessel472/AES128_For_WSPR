#include <cstddef>
#include <cstdint>
#include <cstring>
#include "AES128_Encrypt.h"

namespace {
// Round constants used during AES-128 key expansion.
// rcon[i] is XORed into the first byte of the transformed word every 16 bytes.
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

uint8_t xtime(uint8_t x) {
    // Multiply by x (i.e., by 2) in GF(2^8) with AES irreducible polynomial 0x11B.
    return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

uint8_t gmul(uint8_t a, uint8_t b) {
    // Generic GF(2^8) multiplication used by MixColumns and inversion.
    // Uses the "Russian peasant" multiply method with modular reduction via xtime().
    uint8_t product = 0;
    uint8_t multiplicand = a;
    uint8_t multiplier = b;

    for (int bit = 0; bit < 8; bit++) {
        if (multiplier & 1) {
            product ^= multiplicand;
        }
        multiplicand = xtime(multiplicand);
        multiplier >>= 1;
    }

    return product;
}

uint8_t rotl8(uint8_t value, int shift) {
    // Rotate an 8-bit value left; used by S-box affine transform.
    return static_cast<uint8_t>((value << shift) | (value >> (8 - shift)));
}

uint8_t gf_inverse(uint8_t value) {
    // Multiplicative inverse in GF(2^8): value^(254).
    // Zero has no multiplicative inverse, and AES defines S-box(0) through affine step.
    if (value == 0) {
        return 0;
    }

    uint8_t result = 1;
    uint8_t base = value;
    int exponent = 254;

    while (exponent > 0) {
        if (exponent & 1) {
            result = gmul(result, base);
        }
        base = gmul(base, base);
        exponent >>= 1;
    }

    return result;
}

void BuildSBox(uint8_t sbox[256]) {
    // Build AES S-box dynamically from finite-field inversion and affine transform:
    // S(x) = 0x63 ^ x ^ ROTL(x,1) ^ ROTL(x,2) ^ ROTL(x,3) ^ ROTL(x,4), where x = inverse(input).
    for (int i = 0; i < 256; i++) {
        uint8_t inv = gf_inverse(static_cast<uint8_t>(i));
        sbox[i] = static_cast<uint8_t>(
            0x63 ^ inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4)
        );
    }
}

void AddRoundKey(uint8_t state[16], const uint8_t* round_key) {
    // Combine the state with a 16-byte round key (bitwise XOR).
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

void SubBytes(uint8_t state[16], const uint8_t sbox[256]) {
    // Byte-wise nonlinear substitution using the AES S-box.
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

void BuildInvSBox(const uint8_t sbox[256], uint8_t inv_sbox[256]) {
    // Build inverse S-box so InvSubBytes can map substituted bytes back to originals.
    for (int i = 0; i < 256; i++) {
        inv_sbox[sbox[i]] = static_cast<uint8_t>(i);
    }
}

void InvSubBytes(uint8_t state[16], const uint8_t inv_sbox[256]) {
    // Byte-wise inverse substitution using inverse AES S-box.
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

void ShiftRows(uint8_t state[16]) {
    // State is arranged column-major (AES standard layout).
    // Row 0 unchanged, row 1 left-rotate by 1, row 2 by 2, row 3 by 3.
    uint8_t temp;

    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

void InvShiftRows(uint8_t state[16]) {
    // Inverse row shifts for AES state (right rotations by row index).
    uint8_t temp;

    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

void MixColumns(uint8_t state[16]) {
    // Apply AES fixed matrix multiplication to each state column in GF(2^8):
    // [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2] * column.
    for (int col = 0; col < 4; col++) {
        int base = col * 4;
        uint8_t s0 = state[base + 0];
        uint8_t s1 = state[base + 1];
        uint8_t s2 = state[base + 2];
        uint8_t s3 = state[base + 3];

        state[base + 0] = static_cast<uint8_t>(gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3);
        state[base + 1] = static_cast<uint8_t>(s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3);
        state[base + 2] = static_cast<uint8_t>(s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3));
        state[base + 3] = static_cast<uint8_t>(gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2));
    }
}

void InvMixColumns(uint8_t state[16]) {
    // Apply inverse AES fixed matrix multiplication to each state column in GF(2^8):
    // [14 11 13 9; 9 14 11 13; 13 9 14 11; 11 13 9 14] * column.
    for (int col = 0; col < 4; col++) {
        int base = col * 4;
        uint8_t s0 = state[base + 0];
        uint8_t s1 = state[base + 1];
        uint8_t s2 = state[base + 2];
        uint8_t s3 = state[base + 3];

        state[base + 0] = static_cast<uint8_t>(gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9));
        state[base + 1] = static_cast<uint8_t>(gmul(s0, 9) ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13));
        state[base + 2] = static_cast<uint8_t>(gmul(s0, 13) ^ gmul(s1, 9) ^ gmul(s2, 14) ^ gmul(s3, 11));
        state[base + 3] = static_cast<uint8_t>(gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9) ^ gmul(s3, 14));
    }
}

void KeyExpansion(const uint8_t* key, uint8_t expanded[176], const uint8_t sbox[256]) {
    // Expand 16-byte key into 11 round keys (176 bytes total).
    // AES-128 key schedule: every 16th byte group applies RotWord, SubWord, and rcon.
    std::memcpy(expanded, key, 16);

    int bytes_generated = 16;
    int rcon_idx = 1;
    uint8_t temp[4];

    while (bytes_generated < 176) {
        temp[0] = expanded[bytes_generated - 4];
        temp[1] = expanded[bytes_generated - 3];
        temp[2] = expanded[bytes_generated - 2];
        temp[3] = expanded[bytes_generated - 1];

        if (bytes_generated % 16 == 0) {
            // RotWord: rotate previous 4-byte word left by one byte.
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord: apply S-box to each byte.
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            // Add round constant to first byte.
            temp[0] ^= rcon[rcon_idx++];
        }

        for (int i = 0; i < 4; i++) {
            // Each new byte is XOR of byte 16 positions earlier and transformed temp byte.
            expanded[bytes_generated] = expanded[bytes_generated - 16] ^ temp[i];
            bytes_generated++;
        }
    }
}

void EncryptBlock(const uint8_t in[16], uint8_t out[16], const uint8_t expanded_key[176], const uint8_t sbox[256]) {
    // AES-128 block encryption: 10 rounds total.
    // Round 0: AddRoundKey only; rounds 1-9: full rounds; round 10: no MixColumns.
    uint8_t state[16];
    std::memcpy(state, in, 16);

    AddRoundKey(state, expanded_key);

    for (int round = 1; round <= 9; round++) {
        SubBytes(state, sbox);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expanded_key + round * 16);
    }

    SubBytes(state, sbox);
    ShiftRows(state);
    AddRoundKey(state, expanded_key + 160);

    std::memcpy(out, state, 16);
}

void DecryptBlock(const uint8_t in[16], uint8_t out[16], const uint8_t expanded_key[176], const uint8_t inv_sbox[256]) {
    // AES-128 block decryption: inverse order of round operations.
    uint8_t state[16];
    std::memcpy(state, in, 16);

    AddRoundKey(state, expanded_key + 160);

    for (int round = 9; round >= 1; round--) {
        InvShiftRows(state);
        InvSubBytes(state, inv_sbox);
        AddRoundKey(state, expanded_key + round * 16);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state, inv_sbox);
    AddRoundKey(state, expanded_key);

    std::memcpy(out, state, 16);
}
}

int AES128_Encrypt(const uint8_t* key, uint8_t* input, size_t in_size, uint8_t* output, size_t out_size) {
    // ECB-style encryption across all complete 16-byte blocks in input.
    // Returns 0 on success, -1 on invalid pointers/size constraints.
    if (key == nullptr || input == nullptr || output == nullptr) {
        return -1;
    }

    // AES operates on 16-byte blocks. Caller is responsible for padding.
    if (in_size % 16 != 0 || out_size < in_size) {
        return -1;
    }

    uint8_t sbox[256];
    BuildSBox(sbox);

    uint8_t expanded_key[176];
    KeyExpansion(key, expanded_key, sbox);

    // Encrypt each block independently (ECB behavior).
    for (size_t block = 0; block < in_size; block += 16) {
        EncryptBlock(input + block, output + block, expanded_key, sbox);
    }

    return 0;
}

int AES128_Decrypt(const uint8_t* key, const uint8_t* input, size_t in_size, uint8_t* output, size_t out_size) {
    // ECB-style decryption across all complete 16-byte blocks in input.
    // Returns 0 on success, -1 on invalid pointers/size constraints.
    if (key == nullptr || input == nullptr || output == nullptr) {
        return -1;
    }

    if (in_size % 16 != 0 || out_size < in_size) {
        return -1;
    }

    uint8_t sbox[256];
    BuildSBox(sbox);

    uint8_t inv_sbox[256];
    BuildInvSBox(sbox, inv_sbox);

    uint8_t expanded_key[176];
    KeyExpansion(key, expanded_key, sbox);

    for (size_t block = 0; block < in_size; block += 16) {
        DecryptBlock(input + block, output + block, expanded_key, inv_sbox);
    }

    return 0;
}
