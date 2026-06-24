#include <iostream>
#include <vector>
#include <iomanip>
#include <cstdint>
#include <string>

// ---------------------------------------------------------
// ASCON Keystream Generator (PRNG Core)
// ---------------------------------------------------------
class AsconKeystream {
private:
    uint64_t state[5];
    uint8_t buffer[8];
    size_t buffer_index;

    // Helper: Right bitwise rotation
    static inline uint64_t rotr(uint64_t x, int n) {
        return (x >> n) | (x << (64 - n));
    }

    // Helper: Load 8 bytes into a 64-bit word (Big Endian)
    static uint64_t load64_be(const uint8_t* p) {
        return (static_cast<uint64_t>(p[0]) << 56) | (static_cast<uint64_t>(p[1]) << 48) |
               (static_cast<uint64_t>(p[2]) << 40) | (static_cast<uint64_t>(p[3]) << 32) |
               (static_cast<uint64_t>(p[4]) << 24) | (static_cast<uint64_t>(p[5]) << 16) |
               (static_cast<uint64_t>(p[6]) << 8)  | (static_cast<uint64_t>(p[7]));
    }

    // The core ASCON Permutation State Machine
    void ascon_permutation(int rounds) {
        const uint64_t constants[12] = {
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
            0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
        };
        int start_round = 12 - rounds;

        for (int r = start_round; r < 12; ++r) {
            // 1. Addition of Constants
            state[2] ^= constants[r];

            // 2. Substitution Layer (Bit-sliced 5-bit S-box)
            state[0] ^= state[4]; state[4] ^= state[3]; state[2] ^= state[1];
            uint64_t T[5];
            T[0] = state[0] ^ (~state[1] & state[2]);
            T[1] = state[1] ^ (~state[2] & state[3]);
            T[2] = state[2] ^ (~state[3] & state[4]);
            T[3] = state[3] ^ (~state[4] & state[0]);
            T[4] = state[4] ^ (~state[0] & state[1]);
            T[1] ^= T[0]; T[0] ^= T[4]; T[3] ^= T[2]; T[2] ^= ~T[1];
            state[0] = T[0]; state[1] = T[1]; state[2] = T[2]; state[3] = T[3]; state[4] = T[4];

            // 3. Linear Diffusion Layer
            state[0] ^= rotr(state[0], 19) ^ rotr(state[0], 28);
            state[1] ^= rotr(state[1], 61) ^ rotr(state[1], 39);
            state[2] ^= rotr(state[2],  1) ^ rotr(state[2],  6);
            state[3] ^= rotr(state[3], 10) ^ rotr(state[3], 17);
            state[4] ^= rotr(state[4],  7) ^ rotr(state[4], 41);
        }
    }

    // Squeeze the sponge to extract pseudorandom bytes
    void squeeze_block() {
        uint64_t keystream_block = state[0]; // Extract rate (64 bits for Ascon-128)

        // Store 64-bit block into 8-byte buffer
        for(int i = 0; i < 8; ++i) {
            buffer[i] = static_cast<uint8_t>((keystream_block >> (56 - 8 * i)) & 0xFF);
        }

        // Permute state for the next extraction (p_b = 6 rounds)
        ascon_permutation(6);
        buffer_index = 0;
    }

public:
    // Initialize the generator with a Seed Key and Nonce
    AsconKeystream(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
        if (key.size() != 16 || nonce.size() != 16) {
            throw std::invalid_argument("Key and Nonce must be 16 bytes (128 bits) each.");
        }

        // Ascon-128 Initialization Vector
        state[0] = 0x80400c0600000000ULL;

        // Load Key and Nonce into state
        state[1] = load64_be(key.data());
        state[2] = load64_be(key.data() + 8);
        state[3] = load64_be(nonce.data());
        state[4] = load64_be(nonce.data() + 8);

        // Initial Permutation (p_a = 12 rounds)
        ascon_permutation(12);

        // XOR Key back into state to finalize initialization
        state[3] ^= load64_be(key.data());
        state[4] ^= load64_be(key.data() + 8);

        // Prepare the first block of keystream
        squeeze_block();
    }

    // Fetch the next PRNG byte from the infinite stream
    uint8_t getNextByte() {
        if (buffer_index == 8) {
            squeeze_block();
        }
        return buffer[buffer_index++];
    }

    // Bitwise XOR process (Symmetric for Encryption and Decryption)
    std::vector<uint8_t> process(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> output(data.size());
        for (size_t i = 0; i < data.size(); ++i) {
            output[i] = data[i] ^ getNextByte();
        }
        return output;
    }
};

// ---------------------------------------------------------
// Main Function: Demonstration
// ---------------------------------------------------------
int main() {
    // 1. Setup our small secret state (Seed Key and Nonce)
    std::vector<uint8_t> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    std::vector<uint8_t> nonce = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    std::string plaintext_str = "ASCON state machine active. Infinite PRNG stream generated!";
    std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());

    std::cout << "--- ASCON XOR Keystream Generator ---" << std::endl;
    std::cout << "Original Text: " << plaintext_str << "\n\n";

    // 2. Encrypt (Bitwise XOR plaintext with keystream)
    AsconKeystream encryptor(key, nonce);
    std::vector<uint8_t> ciphertext = encryptor.process(plaintext);

    std::cout << "Ciphertext (Hex): ";
    for (uint8_t byte : ciphertext) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << std::dec << "\n\n";

    // 3. Decrypt (Bitwise XOR ciphertext with a fresh keystream initialized identically)
    AsconKeystream decryptor(key, nonce);
    std::vector<uint8_t> decrypted = decryptor.process(ciphertext);
    std::string decrypted_str(decrypted.begin(), decrypted.end());

    std::cout << "Decrypted Text: " << decrypted_str << std::endl;

    return 0;
}