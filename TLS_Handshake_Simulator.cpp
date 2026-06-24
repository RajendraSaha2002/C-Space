#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <random>
#include <cstdint>
#include <algorithm>

// ============================================================================
// 1. ASCON Lightweight Cryptography Engine (Permutation & Encryption)
// ============================================================================
class ASCON {
private:
    // 64-bit right rotation helper
    static inline uint64_t rotr(uint64_t x, int n) {
        return (x >> n) | (x << (64 - n));
    }

    // The core ASCON Permutation (p12 and p6)
    static void permutation(uint64_t S[5], int rounds) {
        int start = 12 - rounds;
        for (int i = start; i < 12; i++) {
            // 1. Addition of Round Constants
            S[2] ^= ((uint64_t)(0xf - i) << 4) | i;

            // 2. Substitution Layer (5-bit S-box applied across registers)
            S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1];
            uint64_t T[5];
            for (int j = 0; j < 5; j++) {
                T[j] = ~S[j] & S[(j + 1) % 5];
            }
            for (int j = 0; j < 5; j++) {
                S[j] ^= T[(j + 1) % 5];
            }
            S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= ~0ULL;

            // 3. Linear Diffusion Layer
            S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28);
            S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39);
            S[2] ^= rotr(S[2], 1)  ^ rotr(S[2], 6);
            S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17);
            S[4] ^= rotr(S[4], 7)  ^ rotr(S[4], 41);
        }
    }

public:
    // Encrypts a message using the ASCON permutation in a sponge construction
    static std::vector<uint8_t> encrypt(const std::string& message, uint64_t key0, uint64_t key1, uint64_t nonce) {
        // Initialize 320-bit state
        uint64_t S[5] = { key0, key1, nonce, 0, 0 };
        permutation(S, 12); // Initialization uses p12

        std::vector<uint8_t> pt(message.begin(), message.end());
        std::vector<uint8_t> ct;
        ct.reserve(pt.size());

        size_t offset = 0;
        while (offset < pt.size()) {
            uint64_t pt_block = 0;
            int bytes = std::min((size_t)8, pt.size() - offset);

            // Pack bytes into 64-bit block (Big-Endian)
            for (int i = 0; i < bytes; i++) {
                pt_block |= (static_cast<uint64_t>(pt[offset + i]) << (56 - 8 * i));
            }

            // ASCON absorbs plaintext and spits out ciphertext
            S[0] ^= pt_block;
            uint64_t ct_block = S[0];

            // Extract ciphertext bytes
            for (int i = 0; i < bytes; i++) {
                ct.push_back(static_cast<uint8_t>((ct_block >> (56 - 8 * i)) & 0xFF));
            }

            permutation(S, 6); // Intermediate updates use p6
            offset += bytes;
        }
        return ct;
    }

    // Decrypts a message using the ASCON permutation
    static std::string decrypt(const std::vector<uint8_t>& ct, uint64_t key0, uint64_t key1, uint64_t nonce) {
        uint64_t S[5] = { key0, key1, nonce, 0, 0 };
        permutation(S, 12);

        std::string pt = "";
        size_t offset = 0;

        while (offset < ct.size()) {
            uint64_t ct_block = 0;
            int bytes = std::min((size_t)8, ct.size() - offset);

            for (int i = 0; i < bytes; i++) {
                ct_block |= (static_cast<uint64_t>(ct[offset + i]) << (56 - 8 * i));
            }

            // To decrypt: PT = State ^ CT. Then update state with CT.
            uint64_t pt_block = S[0] ^ ct_block;
            S[0] = ct_block;

            for (int i = 0; i < bytes; i++) {
                pt += static_cast<char>((pt_block >> (56 - 8 * i)) & 0xFF);
            }

            permutation(S, 6);
            offset += bytes;
        }
        return pt;
    }
};

// ============================================================================
// 2. Network Node (Client / Server) & Handshake Structures
// ============================================================================
uint64_t generate_random_uint64() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    return dis(gen);
}

// Simulated Diffie-Hellman Shared Generator (Known to both parties)
const uint64_t DH_GENERATOR = 0x9E3779B97F4A7C15;

struct ClientHello {
    uint64_t nonce;
    uint64_t public_key;
};

struct ServerHello {
    uint64_t nonce;
    uint64_t public_key;
};

// --- Execution Entry Point ---
int main() {
    std::cout << "===================================================" << std::endl;
    std::cout << "    TLS-Like Handshake & ASCON Communication       " << std::endl;
    std::cout << "===================================================\n" << std::endl;

    // ---------------------------------------------------------
    // Phase 1: Client Initialization & Hello
    // ---------------------------------------------------------
    std::cout << "[CLIENT] Initiating connection..." << std::endl;
    uint64_t client_private_key = generate_random_uint64();

    ClientHello client_msg;
    client_msg.nonce = generate_random_uint64();
    // Simulated DH Public Key Generation: a ^ G
    client_msg.public_key = client_private_key ^ DH_GENERATOR;

    std::cout << "   -> Sending ClientHello (Nonce, PubKey)" << std::endl;

    // ---------------------------------------------------------
    // Phase 2: Server Hello & Key Derivation
    // ---------------------------------------------------------
    std::cout << "\n[SERVER] Received ClientHello. Processing..." << std::endl;
    uint64_t server_private_key = generate_random_uint64();

    ServerHello server_msg;
    server_msg.nonce = generate_random_uint64();
    // Simulated DH Public Key Generation: b ^ G
    server_msg.public_key = server_private_key ^ DH_GENERATOR;

    // Server derives shared secret: ClientPubKey ^ ServerPrivKey
    uint64_t server_shared_secret = client_msg.public_key ^ server_private_key;

    std::cout << "   -> Sending ServerHello (Nonce, PubKey)" << std::endl;

    // ---------------------------------------------------------
    // Phase 3: Client Key Derivation
    // ---------------------------------------------------------
    std::cout << "\n[CLIENT] Received ServerHello." << std::endl;

    // Client derives shared secret: ServerPubKey ^ ClientPrivKey
    uint64_t client_shared_secret = server_msg.public_key ^ client_private_key;

    std::cout << "\n--- Handshake Verification ---" << std::endl;
    std::cout << "Client Calculated Secret: 0x" << std::hex << client_shared_secret << std::endl;
    std::cout << "Server Calculated Secret: 0x" << std::hex << server_shared_secret << std::dec << std::endl;

    if (client_shared_secret != server_shared_secret) {
        std::cerr << "[-] Handshake Failed: Shared secrets do not match!" << std::endl;
        return 1;
    }
    std::cout << "[+] Handshake Successful! Symmetric keys aligned.\n" << std::endl;

    // ---------------------------------------------------------
    // Phase 4: Derive ASCON Session Keys
    // ---------------------------------------------------------
    // We combine the shared secret with both nonces to prevent replay attacks
    // and generate a 128-bit key (K0, K1) for ASCON.
    uint64_t session_k0 = client_shared_secret ^ client_msg.nonce;
    uint64_t session_k1 = client_shared_secret ^ server_msg.nonce;
    uint64_t session_nonce = client_msg.nonce ^ server_msg.nonce; // ASCON Initialization Nonce

    // ---------------------------------------------------------
    // Phase 5: Secure ASCON-Encrypted Communication
    // ---------------------------------------------------------
    std::string secret_message = "Mission target coordinates updated. Proceed to extraction zone alpha.";
    std::cout << "[CLIENT] Securing payload: \"" << secret_message << "\"" << std::endl;

    // Switch to ASCON encryption
    std::vector<uint8_t> encrypted_payload = ASCON::encrypt(secret_message, session_k0, session_k1, session_nonce);

    std::cout << "   -> Encrypted Ciphertext (Hex): ";
    for (uint8_t b : encrypted_payload) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    std::cout << std::dec << "\n" << std::endl;

    // Server receives and decrypts
    std::string decrypted_message = ASCON::decrypt(encrypted_payload, session_k0, session_k1, session_nonce);

    std::cout << "[SERVER] Payload Decrypted: \"" << decrypted_message << "\"" << std::endl;

    return 0;
}