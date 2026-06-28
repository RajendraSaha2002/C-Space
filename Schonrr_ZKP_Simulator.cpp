#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstdint>
#include <random>

// ============================================================================
// 1. SHA-256 Engine (Used as the Random Oracle for Cryptographic Challenges)
// ============================================================================
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
    std::vector<uint8_t> hash(const std::string& input) {
        reset();
        std::vector<uint8_t> padded(input.begin(), input.end());
        uint64_t total_bits = padded.size() * 8;

        padded.push_back(0x80);
        while ((padded.size() * 8) % 512 != 448) padded.push_back(0x00);
        for (int i = 7; i >= 0; --i) padded.push_back(static_cast<uint8_t>((total_bits >> (i * 8)) & 0xFF));
        for (size_t i = 0; i < padded.size(); i += 64) compress(&padded[i]);

        std::vector<uint8_t> digest(32);
        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = (state[i] >> 24) & 0xFF; digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (state[i] >> 8) & 0xFF; digest[i * 4 + 3] = state[i] & 0xFF;
        }
        return digest;
    }
};

// ============================================================================
// 2. Modular Arithmetic & Prime Generation Engine
// ============================================================================
namespace MathUtils {
    // Generate a random 64-bit integer within a range
    uint64_t rand64(uint64_t min, uint64_t max) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist(min, max);
        return dist(gen);
    }

    // Modular Exponentiation: (base^exp) % mod
    uint64_t modExp(uint64_t base, uint64_t exp, uint64_t mod) {
        uint64_t res = 1;
        base %= mod;
        while (exp > 0) {
            if (exp % 2 == 1) res = (res * base) % mod; // Safe within 64-bit limits if mod <= 2*10^9
            base = (base * base) % mod;
            exp /= 2;
        }
        return res;
    }

    // Simple deterministic primality test
    bool isPrime(uint64_t n) {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;
        for (uint64_t i = 5; i * i <= n; i += 6) {
            if (n % i == 0 || n % (i + 2) == 0) return false;
        }
        return true;
    }

    // Generator for a Safe Prime (p = 2q + 1)
    void generateSafePrime(uint64_t& p, uint64_t& q) {
        while (true) {
            // Constrained to 10^9 to ensure (p-1)*(p-1) multiplication safely fits in uint64_t
            q = rand64(100000000, 1000000000);
            if (isPrime(q)) {
                p = 2 * q + 1;
                if (isPrime(p)) break;
            }
        }
    }

    // Finds a generator for the subgroup of order q
    uint64_t findGenerator(uint64_t p, uint64_t q) {
        for (uint64_t h = 2; h < p - 1; ++h) {
            uint64_t g = modExp(h, 2, p);
            if (g != 1) return g; // Because p=2q+1, g^q = 1 mod p, making it a generator.
        }
        return 2;
    }
}

// ============================================================================
// 3. Schnorr Protocol Classes
// ============================================================================
struct ZKP_Params {
    uint64_t p; // Safe Prime
    uint64_t q; // Prime order of subgroup
    uint64_t g; // Subgroup Generator
};

class Prover {
private:
    ZKP_Params params;
    uint64_t secret_x; // The Secret we are proving knowledge of
    uint64_t public_y; // Public Key: y = g^x mod p
    uint64_t random_r; // Ephemeral random value per-session

public:
    Prover(ZKP_Params p) : params(p) {
        secret_x = MathUtils::rand64(1, params.q - 1);
        public_y = MathUtils::modExp(params.g, secret_x, params.p);
    }

    uint64_t getPublicKey() const { return public_y; }
    uint64_t getSecretForDemo() const { return secret_x; } // STRICTLY FOR DEMONSTRATION

    // Step 1: Generate Commitment (t = g^r mod p)
    uint64_t generateCommitment() {
        random_r = MathUtils::rand64(1, params.q - 1);
        return MathUtils::modExp(params.g, random_r, params.p);
    }

    // Step 3: Calculate Response (s = r + c * x mod q)
    uint64_t calculateResponse(uint64_t challenge_c) {
        uint64_t cx = (challenge_c * secret_x) % params.q;
        uint64_t s = (random_r + cx) % params.q;
        return s;
    }
};

class Verifier {
private:
    ZKP_Params params;
    uint64_t public_y; // Prover's Public Key
    SHA256Engine sha256;

public:
    Verifier(ZKP_Params p, uint64_t y) : params(p), public_y(y) {}

    // Step 2: Generate Challenge utilizing SHA-256 (Random Oracle Model)
    uint64_t generateChallenge(uint64_t commitment_t) {
        // Hash the commitment and public key to enforce unpredictability
        std::string input = std::to_string(commitment_t) + std::to_string(public_y) + std::to_string(params.g);
        std::vector<uint8_t> hashBytes = sha256.hash(input);

        // Truncate first 8 bytes of hash into a 64-bit challenge
        uint64_t challenge_c = 0;
        for (int i = 0; i < 8; ++i) {
            challenge_c = (challenge_c << 8) | hashBytes[i];
        }
        return challenge_c % params.q; // Challenge must be in Z_q
    }

    // Step 4: Verify the response
    bool verify(uint64_t s, uint64_t t, uint64_t c) {
        // Verification Equation: g^s == t * y^c mod p
        uint64_t left_side = MathUtils::modExp(params.g, s, params.p);

        uint64_t y_to_c = MathUtils::modExp(public_y, c, params.p);
        uint64_t right_side = (t * y_to_c) % params.p;

        std::cout << "      [Verifier CPU] Checking g^s mod p   = " << left_side << std::endl;
        std::cout << "      [Verifier CPU] Checking t*y^c mod p = " << right_side << std::endl;

        return left_side == right_side;
    }
};

// ============================================================================
// 4. Main Interactive Execution Loop
// ============================================================================
int main() {
    std::cout << "===========================================================" << std::endl;
    std::cout << "      Schnorr Zero-Knowledge Proof (ZKP) Simulator         " << std::endl;
    std::cout << "===========================================================\n" << std::endl;

    std::cout << "[SYSTEM] Initializing Mathematical Parameters..." << std::endl;
    ZKP_Params params;
    MathUtils::generateSafePrime(params.p, params.q);
    params.g = MathUtils::findGenerator(params.p, params.q);

    std::cout << "   -> Safe Prime (p): " << params.p << std::endl;
    std::cout << "   -> Subgroup order (q): " << params.q << std::endl;
    std::cout << "   -> Generator (g): " << params.g << "\n" << std::endl;

    // Initialize Network Parties
    Prover prover(params);
    Verifier verifier(params, prover.getPublicKey());

    std::cout << "[PROVER] I have a secret (x)! \n   -> Let me prove it. My Public Key (y) is: " << prover.getPublicKey() << std::endl;
    std::cout << "   -> (For Demo Purposes, the true secret x is: " << prover.getSecretForDemo() << ")\n" << std::endl;

    // --- The Interactive Protocol ---

    // 1. Commitment Phase
    std::cout << "[INTERACTION: Step 1] Prover generates a random commitment (t)." << std::endl;
    uint64_t t = prover.generateCommitment();
    std::cout << "   -> Prover sends 't' to Verifier: " << t << "\n" << std::endl;

    // 2. Challenge Phase (Via Random Oracle)
    std::cout << "[INTERACTION: Step 2] Verifier generates cryptographic challenge (c)." << std::endl;
    std::cout << "   -> Verifier uses SHA-256 Random Oracle on 't' & 'y' to prevent cheating." << std::endl;
    uint64_t c = verifier.generateChallenge(t);
    std::cout << "   -> Verifier sends 'c' to Prover: " << c << "\n" << std::endl;

    // 3. Response Phase
    std::cout << "[INTERACTION: Step 3] Prover calculates the response (s)." << std::endl;
    uint64_t s = prover.calculateResponse(c);
    std::cout << "   -> Prover sends 's' to Verifier: " << s << "\n" << std::endl;

    // 4. Verification Phase
    std::cout << "[INTERACTION: Step 4] Verifier analyzes response." << std::endl;
    bool isValid = verifier.verify(s, t, c);

    std::cout << "\n===========================================================" << std::endl;
    if (isValid) {
        std::cout << "[+] ZERO-KNOWLEDGE PROOF VALIDATED." << std::endl;
        std::cout << "[+] Verifier confirms Prover knows the secret 'x', but learned absolutely nothing about what 'x' actually is!" << std::endl;
    } else {
        std::cout << "[-] ZKP FAILED. Prover is an imposter." << std::endl;
    }
    std::cout << "===========================================================" << std::endl;

    return 0;
}