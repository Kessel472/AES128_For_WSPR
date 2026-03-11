#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "AES128_StringWrapper.h"

int main() {
	const uint8_t key[16] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B,
		0x0C, 0x0D, 0x0E, 0x0F
	};

	const std::string plaintext = "I am raphael, this is a test of AES-128 property";
	std::vector<uint8_t> ciphertext;
	std::string recovered;

	const int result = AES128_EncryptStringPKCS7(key, plaintext, ciphertext);
	if (result != 0) {
		std::cerr << "Encryption failed.\n";
		return 1;
	}

	const int decrypt_result = AES128_DecryptStringPKCS7(key, ciphertext, recovered);
	if (decrypt_result != 0) {
		std::cerr << "Decryption failed.\n";
		return 1;
	}
	
	std::cout << "Plaintext: " << plaintext << "\n";
	std::cout << "Plaintext length: " << plaintext.size() << " bytes\n";
	std::cout << "Ciphertext length: " << ciphertext.size() << " bytes\n";
	std::cout << "Ciphertext (hex): ";
	for (uint8_t byte : ciphertext) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
	}
	std::cout << "\n";
	std::cout << std::dec << "Recovered: " << recovered << "\n";
	std::cout << "Match: " << ((recovered == plaintext) ? "YES" : "NO") << "\n";

	return 0;
}
