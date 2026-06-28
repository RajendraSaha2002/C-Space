#include <iostream>
#include <vector>
#include <random>
#include <cstdint>
#include <iomanip>

// ============================================================================
// 1. Post-Quantum Global Parameters (Kyber-like)
// ============================================================================
const int N = 256;          // Polynomial degree (X^256 + 1)
const int Q = 3329;         // Prime modulus

// Helper to ensure mathematical modulo (handling negative numbers correctly)
int safe_mod(int val, int mod) {
    int r = val % mod;
    return r < 0 ? r + mod : r;
}

// ============================================================================
// 2. Polynomial Ring Arithmetic: Z_q[X] / (X^N + 1)
// ============================================================================
struct Poly {
    std::vector<int> coeffs;

    Poly() : coeffs(N, 0) {}

    // Polynomial Addition mod Q
    Poly operator+(const Poly& other) const {
        Poly res;
        for (int i = 0; i < N; ++i) {
            res.coeffs[i] = safe_mod(this->coeffs[i] + other.coeffs[i], Q);
        }
        return res;
    }

    // Polynomial Subtraction mod Q
    Poly operator-(const Poly& other) const {
        Poly res;
        for (int i = 0; i < N; ++i) {
            res.coeffs[i] = safe_mod(this->coeffs[i] - other.coeffs[i], Q);
        }
        return res;
    }

    // Polynomial Multiplication in Z_q[X] / (X^N + 1)
    // Note: In production Kyber, this is done using NTT (Number Theoretic Transform)
    // for O(N log N) speed. We use standard O(N^2) convolution for educational clarity.
    Poly operator*(const Poly& other) const {
        Poly res;
        for (int i = 0; i < N; ++i) {
            for (int j = 0; j < N; ++j) {
                int index = i + j;
                int sign = 1;
                // Anti-cyclic property: X^N = -1 mod (X^N + 1)
                if (index >= N) {
                    index -= N;
                    sign = -1;
                }
                long long term = (long long)this->coeffs[i] * other.coeffs[j] * sign;
                res.coeffs[index] = safe_mod(res.coeffs[index] + term, Q);
            }
        }
        return res;
    }
};

// ============================================================================
// 3. Cryptographic Samplers (Noise and Uniformity)
// ============================================================================
class Sampler {
private:
    std::mt19937 gen;
    std::uniform_int_distribution<int> uniform_dist;
    std::uniform_int_distribution<int> coin_flip;

public:
    Sampler() : gen(std::random_device{}()), uniform_dist(0, Q - 1), coin_flip(0, 1) {}

    // Generates a polynomial with uniformly random coefficients in [0, Q-1]
    Poly sample_uniform() {
        Poly p;
        for (int i = 0; i < N; ++i) {
            p.coeffs[i] = uniform_dist(gen);
        }
        return p;
    }

    // Simulates a Centered Binomial Distribution (CBD) for small error noise
    Poly sample_noise() {
        Poly p;
        for (int i = 0; i < N; ++i) {
            // eta = 2: noise is bounded between [-2, 2]
            int a = coin_flip(gen) + coin_flip(gen);
            int b = coin_flip(gen) + coin_flip(gen);
            p.coeffs[i] = safe_mod(a - b, Q);
        }
        return p;
    }

    // Generates 32 random bytes (256 bits) for our shared symmetric key
    std::vector<uint8_t> generate_random_key() {
        std::vector<uint8_t> key(32);
        std::uniform_int_distribution<int> byte_dist(0, 255);
        for (int i = 0; i < 32; ++i) {
            key[i] = byte_dist(gen);
        }
        return key;
    }
};

// ============================================================================
// 4. Data Encoding (Mapping 256-bit keys to Polynomials)
// ============================================================================
// Encodes a 32-byte (256-bit) key into a polynomial.
// Bit 1 -> Q/2 (approx 1664). Bit 0 -> 0.
Poly encode_key(const std::vector<uint8_t>& key) {
    Poly p;
    for (int i = 0; i < 32; ++i) {
        for (int j = 0; j < 8; ++j) {
            int bit = (key[i] >> j) & 1;
            p.coeffs[i * 8 + j] = bit ? (Q / 2) : 0;
        }
    }
    return p;
}

// Decodes a polynomial back into a 32-byte key using thresholding.
// If a coefficient is closer to Q/2, it's a 1. If closer to 0 or Q, it's a 0.
std::vector<uint8_t> decode_key(const Poly& p) {
    std::vector<uint8_t> key(32, 0);
    for (int i = 0; i < 32; ++i) {
        for (int j = 0; j < 8; ++j) {
            int coeff = p.coeffs[i * 8 + j];
            // Calculate distance to Q/2 and 0
            int dist_to_half = std::abs(coeff - (Q / 2));
            int dist_to_zero = std::min(coeff, Q - coeff);

            if (dist_to_half < dist_to_zero) {
                key[i] |= (1 << j);
            }
        }
    }
    return key;
}

// ============================================================================
// 5. Main Execution: Alice and Bob KEM Simulation
// ============================================================================
int main() {
    std::cout << "===================================================" << std::endl;
    std::cout << "  Post-Quantum KEM Simulator (Kyber-Inspired)      " << std::endl;
    std::cout << "===================================================\n" << std::endl;

    Sampler sampler;

    // ---------------------------------------------------------
    // Phase 1: Alice generates Keypair
    // ---------------------------------------------------------
    std::cout << "[ALICE] Generating public/private keypair..." << std::endl;
    Poly a = sampler.sample_uniform();      // Public random matrix/polynomial (a)
    Poly s = sampler.sample_noise();        // Secret key (s)
    Poly e = sampler.sample_noise();        // Small error (e)

    // Public Key calculation: t = a*s + e
    Poly t = (a * s) + e;

    std::cout << "   -> Public Key (pk) created: (a, t)" << std::endl;
    std::cout << "   -> Secret Key (sk) securely stored: (s)\n" << std::endl;

    // ---------------------------------------------------------
    // Phase 2: Bob encapsulates a shared secret
    // ---------------------------------------------------------
    std::cout << "[BOB] Generating 256-bit symmetric session key..." << std::endl;
    std::vector<uint8_t> bob_secret = sampler.generate_random_key();

    std::cout << "   -> Bob's Secret Key (Hex): ";
    for (uint8_t b : bob_secret) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << std::dec << "\n" << std::endl;

    std::cout << "[BOB] Encapsulating secret using Alice's Public Key..." << std::endl;
    Poly m = encode_key(bob_secret);        // Encode message into polynomial
    Poly r = sampler.sample_noise();        // Random noise (r)
    Poly e1 = sampler.sample_noise();       // Error 1
    Poly e2 = sampler.sample_noise();       // Error 2

    // Ciphertext generation
    Poly u = (a * r) + e1;                  // ct part 1: u = a*r + e1
    Poly v = (t * r) + e2 + m;              // ct part 2: v = t*r + e2 + m

    std::cout << "   -> Sending Ciphertext (ct = u, v) to Alice.\n" << std::endl;

    // ---------------------------------------------------------
    // Phase 3: Alice decapsulates the ciphertext
    // ---------------------------------------------------------
    std::cout << "[ALICE] Receiving Ciphertext. Decapsulating using Secret Key..." << std::endl;

    // Decapsulation formula: noisy_message = v - u*s
    Poly noisy_message = v - (u * s);

    // Decode the noisy polynomial back into raw bytes via thresholding
    std::vector<uint8_t> alice_secret = decode_key(noisy_message);

    std::cout << "   -> Alice's Recovered Key (Hex): ";
    for (uint8_t b : alice_secret) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << std::dec << "\n" << std::endl;

    // ---------------------------------------------------------
    // Phase 4: Verification
    // ---------------------------------------------------------
    if (bob_secret == alice_secret) {
        std::cout << "[+] SUCCESS: Quantum-Resistant Key Exchange Complete." << std::endl;
    } else {
        std::cerr << "[-] FAILURE: Shared secrets do not match." << std::endl;
    }

    return 0;
}