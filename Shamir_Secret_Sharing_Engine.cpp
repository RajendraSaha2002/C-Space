#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <sstream>
#include <iomanip>
#include <functional>
#include <stdexcept>

// ==========================================
// 1. Galois Field GF(2^8) Arithmetic
// ==========================================
class GF256 {
public:
    static uint8_t add(uint8_t a, uint8_t b) { return a ^ b; }
    static uint8_t sub(uint8_t a, uint8_t b) { return a ^ b; } // Subtraction is XOR in GF(2^n)

    // Peasant multiplication modulo x^8 + x^4 + x^3 + x + 1 (0x11B)
    static uint8_t mul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) p ^= a;
            uint8_t hi_bit_set = (a & 0x80);
            a <<= 1;
            if (hi_bit_set) a ^= 0x1B;
            b >>= 1;
        }
        return p;
    }

    // Fermat's Little Theorem for inverse: a^(255-2) = a^254
    static uint8_t inv(uint8_t a) {
        if (a == 0) throw std::invalid_argument("No inverse for 0");
        uint8_t res = 1;
        uint8_t base = a;
        for (int exp = 254; exp > 0; exp >>= 1) {
            if (exp & 1) res = mul(res, base);
            base = mul(base, base);
        }
        return res;
    }

    static uint8_t div(uint8_t a, uint8_t b) {
        return mul(a, inv(b));
    }
};

// ==========================================
// 2. Data Structures & Simulators
// ==========================================
struct Share {
    uint8_t x;
    std::vector<uint8_t> y_data;
    std::string commitment_hash; // Simulated SHA-256
};

// Simulated SHA-256 for Share Verification
std::string simulate_sha256(uint8_t x, const std::vector<uint8_t>& y_data) {
    std::hash<std::string> hasher;
    std::string input = std::to_string(x);
    for (uint8_t byte : y_data) input += std::to_string(byte);

    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << hasher(input)
       << std::setw(16) << std::setfill('0') << hasher(input + "salt");
    return ss.str();
}

// ==========================================
// 3. Dealer & Combiner Logic
// ==========================================
class ShamirSecretSharing {
private:
    int n, k;
    std::mt19937 rng;

public:
    ShamirSecretSharing(int total_shares, int threshold) : n(total_shares), k(threshold) {
        std::random_device rd;
        rng = std::mt19937(rd());
    }

    // --- DEALER ---
    std::vector<Share> split_secret(const std::string& secret) {
        std::cout << "[Dealer] Splitting " << secret.length() * 8 << "-bit secret into " << n << " shares (Threshold: " << k << ")...\n";
        std::vector<Share> shares(n);
        for (int i = 0; i < n; i++) {
            shares[i].x = i + 1; // x coordinates: 1, 2, ..., n
            shares[i].y_data.resize(secret.length(), 0);
        }

        std::uniform_int_distribution<int> dist(0, 255);

        // Process byte-by-byte
        for (size_t byte_idx = 0; byte_idx < secret.length(); ++byte_idx) {
            uint8_t S = secret[byte_idx];

            // Generate random polynomial of degree k-1: P(x) = S + a1*x + a2*x^2 + ... + ak-1*x^(k-1)
            std::vector<uint8_t> coeffs(k);
            coeffs[0] = S;
            for (int i = 1; i < k; ++i) coeffs[i] = dist(rng);

            // Evaluate polynomial for each share
            for (int i = 0; i < n; ++i) {
                uint8_t x_val = shares[i].x;
                uint8_t y_val = 0;
                uint8_t x_pow = 1;

                for (int c = 0; c < k; ++c) {
                    y_val = GF256::add(y_val, GF256::mul(coeffs[c], x_pow));
                    x_pow = GF256::mul(x_pow, x_val);
                }
                shares[i].y_data[byte_idx] = y_val;
            }
        }

        // Generate Commitments
        for (int i = 0; i < n; i++) {
            shares[i].commitment_hash = simulate_sha256(shares[i].x, shares[i].y_data);
        }

        return shares;
    }

    // --- COMBINER ---
    std::string reconstruct_secret(const std::vector<Share>& provided_shares) {
        if (provided_shares.size() < k) {
            throw std::runtime_error("Insufficient shares to reconstruct secret.");
        }

        std::cout << "[Combiner] Verifying commitments and reconstructing...\n";

        // 1. Verify Commitments
        for (int i = 0; i < k; ++i) {
            std::string expected_hash = simulate_sha256(provided_shares[i].x, provided_shares[i].y_data);
            if (expected_hash != provided_shares[i].commitment_hash) {
                throw std::runtime_error("Tamper Alert: Share commitment mismatch at x=" + std::to_string(provided_shares[i].x));
            }
        }

        // 2. Lagrange Interpolation at x = 0
        size_t secret_len = provided_shares[0].y_data.size();
        std::string secret = "";

        for (size_t byte_idx = 0; byte_idx < secret_len; ++byte_idx) {
            uint8_t reconstructed_byte = 0;

            for (int i = 0; i < k; ++i) {
                uint8_t num = 1;
                uint8_t den = 1;
                uint8_t x_i = provided_shares[i].x;

                for (int j = 0; j < k; ++j) {
                    if (i != j) {
                        uint8_t x_j = provided_shares[j].x;
                        num = GF256::mul(num, x_j); // 0 - x_j = x_j in GF(2^n)
                        den = GF256::mul(den, GF256::sub(x_i, x_j));
                    }
                }

                uint8_t basis_val = GF256::div(num, den);
                uint8_t term = GF256::mul(provided_shares[i].y_data[byte_idx], basis_val);
                reconstructed_byte = GF256::add(reconstructed_byte, term);
            }
            secret += (char)reconstructed_byte;
        }
        return secret;
    }
};

// ==========================================
// 4. Main Execution
// ==========================================
int main() {
    std::cout << "=== Shamir Secret Sharing over GF(2^8) ===\n\n";

    // 256-bit Key (32 bytes)
    std::string ascon_key = "ASCON_SECRET_KEY_EXACTLY_32BYTES";

    // Setup (5 shares total, 3 needed to reconstruct)
    int n = 5;
    int k = 3;
    ShamirSecretSharing sss(n, k);

    // 1. Dealer splits the secret
    std::vector<Share> all_shares = sss.split_secret(ascon_key);

    std::cout << "\n[Generated Shares]\n";
    for(const auto& s : all_shares) {
        std::cout << "  Share " << (int)s.x << " | Hash: " << s.commitment_hash.substr(0, 16) << "...\n";
    }

    // 2. Simulate distributing shares and gathering a subset
    std::vector<Share> subset = { all_shares[0], all_shares[2], all_shares[4] }; // x=1, x=3, x=5
    std::cout << "\n[Action] Gathered Share 1, Share 3, and Share 5 for reconstruction.\n";

    // 3. Combiner reconstructs the secret
    try {
        std::string recovered = sss.reconstruct_secret(subset);
        std::cout << "\n[SUCCESS] Recovered Secret: " << recovered << "\n";

        if (recovered == ascon_key) {
            std::cout << "  -> Secret matches original 256-bit key exactly.\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "\n[ERROR] " << e.what() << "\n";
    }

    return 0;
}