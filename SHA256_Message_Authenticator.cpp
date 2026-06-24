#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

// ---------------------------------------------------------
// 1. Custom SHA-256 Engine (Adapted for binary data)
// ---------------------------------------------------------
class SHA256Engine {
private:
    uint32_t state[8];
    const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static inline uint32_t Sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static inline uint32_t Sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static inline uint32_t sigma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static inline uint32_t sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    void compress(const uint8_t block[64]) {
        uint32_t W[64];
        for (int t = 0; t < 16; ++t) {
            W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) | (block[t * 4 + 2] << 8) | (block[t * 4 + 3]);
        }
        for (int t = 16; t < 64; ++t) {
            W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
        }

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int t = 0; t < 64; ++t) {
            uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
            uint32_t T2 = Sigma0(a) + Maj(a, b, c);
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void reset() {
        state[0] = 0x6a09e667; state[1] = 0xbb67ae85; state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
        state[4] = 0x510e527f; state[5] = 0x9b05688c; state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
    }

public:
    // Hashes a byte array and returns a 32-byte digest
    std::vector<uint8_t> hashBytes(const std::vector<uint8_t>& data) {
        reset();
        std::vector<uint8_t> padded = data;
        uint64_t total_bits = padded.size() * 8;

        padded.push_back(0x80);
        while ((padded.size() * 8) % 512 != 448) { padded.push_back(0x00); }

        for (int i = 7; i >= 0; --i) {
            padded.push_back(static_cast<uint8_t>((total_bits >> (i * 8)) & 0xFF));
        }

        for (size_t i = 0; i < padded.size(); i += 64) {
            compress(&padded[i]);
        }

        std::vector<uint8_t> digest(32);
        for (int i = 0; i < 8; ++i) {
            digest[i * 4]     = (state[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (state[i] >> 8)  & 0xFF;
            digest[i * 4 + 3] =  state[i]        & 0xFF;
        }
        return digest;
    }
};

// ---------------------------------------------------------
// 2. HMAC-SHA256 Authenticator
// ---------------------------------------------------------
class HMAC_SHA256 {
private:
    SHA256Engine sha256;
    std::vector<uint8_t> k_ipad;
    std::vector<uint8_t> k_opad;
    const size_t BLOCK_SIZE = 64; // SHA-256 block size is 64 bytes

public:
    // Initialize HMAC with a shared secret key
    HMAC_SHA256(const std::vector<uint8_t>& key) {
        std::vector<uint8_t> processed_key = key;

        // 1. If key is longer than block size, hash it down to 32 bytes
        if (processed_key.size() > BLOCK_SIZE) {
            processed_key = sha256.hashBytes(processed_key);
        }

        // 2. If key is shorter than block size, pad with zeros
        if (processed_key.size() < BLOCK_SIZE) {
            processed_key.resize(BLOCK_SIZE, 0x00);
        }

        // 3. Create the inner and outer pads via bitwise XOR
        k_ipad.assign(BLOCK_SIZE, 0x00);
        k_opad.assign(BLOCK_SIZE, 0x00);

        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            k_ipad[i] = processed_key[i] ^ 0x36; // Inner pad constant
            k_opad[i] = processed_key[i] ^ 0x5C; // Outer pad constant
        }
    }

    // Generate the HMAC signature for a given message
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) {
        // Inner Hash = H(K_ipad || message)
        std::vector<uint8_t> inner_data = k_ipad;
        inner_data.insert(inner_data.end(), message.begin(), message.end());
        std::vector<uint8_t> inner_hash = sha256.hashBytes(inner_data);

        // Outer Hash = H(K_opad || Inner Hash)
        std::vector<uint8_t> outer_data = k_opad;
        outer_data.insert(outer_data.end(), inner_hash.begin(), inner_hash.end());
        return sha256.hashBytes(outer_data);
    }

    // Verify a message against a provided MAC tag in constant time
    bool verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& mac_to_check) {
        std::vector<uint8_t> generated_mac = sign(message);

        if (generated_mac.size() != mac_to_check.size()) return false;

        // Constant-time comparison to prevent timing attacks
        uint8_t result = 0;
        for (size_t i = 0; i < generated_mac.size(); ++i) {
            result |= generated_mac[i] ^ mac_to_check[i];
        }
        return result == 0;
    }
};

// --- Utility: Convert Byte Vector to Hex String ---
std::string toHex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (uint8_t b : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return ss.str();
}

// ---------------------------------------------------------
// 3. Main Execution and Demonstration
// ---------------------------------------------------------
int main() {
    std::string secret_key_str = "SuperSecretSharedKey123!";
    std::vector<uint8_t> key(secret_key_str.begin(), secret_key_str.end());

    std::string message_str = "Transfer $1,000,000 to Bob.";
    std::vector<uint8_t> message(message_str.begin(), message_str.end());

    std::cout << "--- HMAC-SHA256 Authenticator ---\n" << std::endl;

    // Initialize HMAC engine with shared secret
    HMAC_SHA256 hmac(key);

    // 1. Sign the message
    std::vector<uint8_t> valid_mac = hmac.sign(message);
    std::cout << "[+] Message:     \"" << message_str << "\"" << std::endl;
    std::cout << "[+] Generated MAC: " << toHex(valid_mac) << "\n" << std::endl;

    // 2. Verify the valid message
    bool isValid = hmac.verify(message, valid_mac);
    std::cout << "[*] Verification (Unaltered Message): " << (isValid ? "SUCCESS" : "FAILED") << std::endl;

    // 3. Demonstrate Tampering (Change "Bob" to "Eve")
    std::string tampered_message_str = "Transfer $1,000,000 to Eve.";
    std::vector<uint8_t> tampered_message(tampered_message_str.begin(), tampered_message_str.end());

    bool isTamperedValid = hmac.verify(tampered_message, valid_mac);
    std::cout << "[*] Verification (Tampered Message):  " << (isTamperedValid ? "SUCCESS" : "FAILED (Tampering Detected!)") << std::endl;

    std::cout << "\n--- Conceptual Note ---" << std::endl;
    std::cout << "While ASCON incorporates authentication directly into its state permutation (AEAD),\n"
              << "HMAC wraps a standalone hashing algorithm (SHA-256) inside two layers of padded keys\n"
              << "to achieve the same goal: proving data integrity and authenticity." << std::endl;

    return 0;
}