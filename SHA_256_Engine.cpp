#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

class SHA256Engine {
private:
    // SHA-256 Initial Hash Values (First 32 bits of the fractional parts of the square roots of the first 8 primes)
    uint32_t state[8];

    // SHA-256 Constants (First 32 bits of the fractional parts of the cube roots of the first 64 primes)
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

    // Bitwise Right Rotation Helper
    static inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    // SHA-256 Logical Functions
    static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)  { return (x & y) ^ (~x & z); }
    static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

    static inline uint32_t Sigma0(uint32_t x) { return rotr(x, 2)  ^ rotr(x, 13) ^ rotr(x, 22); }
    static inline uint32_t Sigma1(uint32_t x) { return rotr(x, 6)  ^ rotr(x, 11) ^ rotr(x, 25); }
    static inline uint32_t sigma0(uint32_t x) { return rotr(x, 7)  ^ rotr(x, 18) ^ (x >> 3); }
    static inline uint32_t sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    // Core 64-Round Compression Step
    void compress(const uint8_t block[64]) {
        uint32_t W[64];

        // 1. Prepare message schedule (W) from the 512-bit block
        for (int t = 0; t < 16; ++t) {
            W[t] = (static_cast<uint32_t>(block[t * 4])     << 24) |
                   (static_cast<uint32_t>(block[t * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[t * 4 + 2]) << 8)  |
                   (static_cast<uint32_t>(block[t * 4 + 3]));
        }
        for (int t = 16; t < 64; ++t) {
            W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
        }

        // 2. Initialize working variables with current state
        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        // 3. The 64 Compression Rounds
        for (int t = 0; t < 64; ++t) {
            uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
            uint32_t T2 = Sigma0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // 4. Compute intermediate state values
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    void reset() {
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
    }

public:
    SHA256Engine() {
        reset();
    }

    // Main Hash generation routine incorporating message padding
    std::string hash(const std::string& input) {
        reset();

        // Copy original input to dynamic byte array
        std::vector<uint8_t> data(input.begin(), input.end());
        uint64_t total_bits = static_cast<uint64_t>(data.size()) * 8;

        // --- Message Padding Steps ---
        // 1. Append a single '1' bit (0x80 byte)
        data.push_back(0x80);

        // 2. Append '0' bits until remaining space is precisely matching the block requirements
        // We need the message size to be 448 bits modulo 512 (leaving 64 bits for the length field)
        while ((data.size() * 8) % 512 != 448) {
            data.push_back(0x00);
        }

        // 3. Append original message length as a 64-bit Big-Endian integer
        for (int i = 7; i >= 0; --i) {
            data.push_back(static_cast<uint8_t>((total_bits >> (i * 8)) & 0xFF));
        }

        // --- Compression Block Iteration ---
        // Process data in 512-bit blocks (64 bytes each)
        for (size_t i = 0; i < data.size(); i += 64) {
            compress(&data[i]);
        }

        // --- Build 256-bit Output Digest ---
        std::stringstream ss;
        for (int i = 0; i < 8; ++i) {
            ss << std::hex << std::setw(8) << std::setfill('0') << state[i];
        }

        return ss.str();
    }
};

// ---------------------------------------------------------
// Execution Entry Point
// ---------------------------------------------------------
int main() {
    SHA256Engine sha;

    // Test cases to verify accurate functionality
    std::string message1 = "abc";
    std::string message2 = "The quick brown fox jumps over the lazy dog";
    std::string message3 = ""; // Empty string check

    std::cout << "=========================================" << std::endl;
    std::cout << "       SHA-256 Custom Hash Engine        " << std::endl;
    std::cout << "=========================================\n" << std::endl;

    std::cout << "Input:  \"" << message1 << "\"" << std::endl;
    std::cout << "Digest: " << sha.hash(message1) << "\n" << std::endl;

    std::cout << "Input:  \"" << message2 << "\"" << std::endl;
    std::cout << "Digest: " << sha.hash(message2) << "\n" << std::endl;

    std::cout << "Input:  \"\" (Empty String)" << std::endl;
    std::cout << "Digest: " << sha.hash(message3) << std::endl;

    return 0;
}