#include <iostream>
#include <vector>
#include <random>
#include <cmath>
#include <cassert>
#include <iomanip>

// --- FHE Parameters ---
// For a production system, N is typically 4096+, Q is a 100+ bit integer.
// We use small parameters for this toy engine to keep it understandable.
const int N = 16;                 // Polynomial degree (must be power of 2)
const int64_t Q = 1048576;        // Ciphertext modulus (2^20)
const int64_t T = 7;              // Plaintext modulus
const int64_t DELTA = Q / T;      // Scaling factor

// --- Mathematical Helpers ---
// Proper mathematical modulo (handles negative numbers)
int64_t modQ(int64_t v) {
    int64_t r = v % Q;
    return r < 0 ? r + Q : r;
}

// Centered modulo: maps to [-Q/2, Q/2)
int64_t centerModQ(int64_t v) {
    int64_t r = modQ(v);
    if (r > Q / 2) return r - Q;
    return r;
}

// --- Polynomial Ring Z_q[x]/(x^N+1) ---
struct Poly {
    std::vector<int64_t> coeffs;

    Poly() : coeffs(N, 0) {}

    // Uniform sampling for A
    static Poly random_uniform() {
        Poly p;
        for (int i = 0; i < N; ++i) p.coeffs[i] = rand() % Q;
        return p;
    }

    // Small error sampling {-1, 0, 1} for Secret Key and Noise
    static Poly random_small() {
        Poly p;
        for (int i = 0; i < N; ++i) p.coeffs[i] = (rand() % 3) - 1;
        return p;
    }

    Poly operator+(const Poly& other) const {
        Poly res;
        for (int i = 0; i < N; ++i) res.coeffs[i] = modQ(coeffs[i] + other.coeffs[i]);
        return res;
    }

    Poly operator-(const Poly& other) const {
        Poly res;
        for (int i = 0; i < N; ++i) res.coeffs[i] = modQ(coeffs[i] - other.coeffs[i]);
        return res;
    }

    // Polynomial multiplication mod (x^N + 1) and mod Q
    Poly operator*(const Poly& other) const {
        Poly res;
        for (int i = 0; i < N; ++i) {
            for (int j = 0; j < N; ++j) {
                if (i + j < N) {
                    res.coeffs[i + j] = modQ(res.coeffs[i + j] + coeffs[i] * other.coeffs[j]);
                } else {
                    // x^N = -1 (Cyclotomic reduction)
                    res.coeffs[i + j - N] = modQ(res.coeffs[i + j - N] - coeffs[i] * other.coeffs[j]);
                }
            }
        }
        return res;
    }
};

// --- FHE Engine ---
struct Ciphertext {
    std::vector<Poly> c; // c[0] + c[1]*s + c[2]*s^2 ...
    Ciphertext(Poly c0, Poly c1) { c.push_back(c0); c.push_back(c1); }
};

class BFVEngine {
private:
    Poly sk; // Secret Key
    Poly pk0, pk1; // Public Key

    // Helper for tensor product multiplication
    std::vector<int64_t> mul_unreduced(const Poly& a, const Poly& b) {
        std::vector<int64_t> res(N, 0);
        for(int i=0; i<N; ++i) {
            for(int j=0; j<N; ++j) {
                if (i+j < N) res[i+j] += a.coeffs[i] * b.coeffs[j];
                else res[i+j-N] -= a.coeffs[i] * b.coeffs[j];
            }
        }
        return res;
    }

    Poly scale_and_mod(const std::vector<int64_t>& unreduced) {
        Poly res;
        for(int i=0; i<N; ++i) {
            double val = (double)unreduced[i] * T / (double)Q;
            res.coeffs[i] = modQ((int64_t)std::round(val));
        }
        return res;
    }

public:
    BFVEngine() {
        srand(1337); // Fixed seed for reproducible simulation

        // 1. KeyGen
        sk = Poly::random_small();
        Poly a = Poly::random_uniform();
        Poly e = Poly::random_small();

        pk1 = a;
        // pk0 = -(a*s + e)
        Poly as = a * sk;
        pk0 = (as + e);
        for(int i=0; i<N; ++i) pk0.coeffs[i] = modQ(-pk0.coeffs[i]);
    }

    Ciphertext encrypt(int64_t message) {
        Poly m;
        m.coeffs[0] = message % T; // Encode scalar integer into polynomial

        Poly u = Poly::random_small();
        Poly e1 = Poly::random_small();
        Poly e2 = Poly::random_small();

        // c0 = pk0 * u + e1 + Delta * m
        Poly delta_m;
        delta_m.coeffs[0] = modQ(m.coeffs[0] * DELTA);
        Poly c0 = (pk0 * u) + e1 + delta_m;

        // c1 = pk1 * u + e2
        Poly c1 = (pk1 * u) + e2;

        return Ciphertext(c0, c1);
    }

    int64_t decrypt(const Ciphertext& ct) {
        // p = c0 + c1*s + c2*s^2 ...
        Poly p = ct.c[0];
        Poly s_pow = sk;
        for(size_t i = 1; i < ct.c.size(); ++i) {
            p = p + (ct.c[i] * s_pow);
            s_pow = s_pow * sk;
        }

        // m = round((p * T) / Q) mod T
        int64_t p0_centered = centerModQ(p.coeffs[0]);
        int64_t m = (int64_t)std::round((double)p0_centered * T / (double)Q);
        return (m % T + T) % T;
    }

    Ciphertext add(const Ciphertext& ct1, const Ciphertext& ct2) {
        return Ciphertext(ct1.c[0] + ct2.c[0], ct1.c[1] + ct2.c[1]);
    }

    // Simplified Homomorphic Multiplication (Outputs degree-2 ciphertext)
    Ciphertext multiply(const Ciphertext& ct1, const Ciphertext& ct2) {
        std::vector<int64_t> v0_unred = mul_unreduced(ct1.c[0], ct2.c[0]);

        std::vector<int64_t> v1_unred1 = mul_unreduced(ct1.c[0], ct2.c[1]);
        std::vector<int64_t> v1_unred2 = mul_unreduced(ct1.c[1], ct2.c[0]);
        std::vector<int64_t> v1_unred(N, 0);
        for(int i=0; i<N; ++i) v1_unred[i] = v1_unred1[i] + v1_unred2[i];

        std::vector<int64_t> v2_unred = mul_unreduced(ct1.c[1], ct2.c[1]);

        Ciphertext res(scale_and_mod(v0_unred), scale_and_mod(v1_unred));
        res.c.push_back(scale_and_mod(v2_unred)); // Size expands to 3
        return res;
    }

    // Diagnostic tool to analyze noise budget depletion
    double calculate_noise_bits(const Ciphertext& ct, int64_t expected_m) {
        Poly p = ct.c[0];
        Poly s_pow = sk;
        for(size_t i = 1; i < ct.c.size(); ++i) {
            p = p + (ct.c[i] * s_pow);
            s_pow = s_pow * sk;
        }

        int64_t max_noise = 0;
        for(int i=0; i<N; ++i) {
            int64_t expected_val = (i == 0) ? (expected_m * DELTA) : 0;
            int64_t noise = centerModQ(p.coeffs[i] - expected_val);
            if(std::abs(noise) > max_noise) max_noise = std::abs(noise);
        }

        if (max_noise == 0) return 0;
        return std::log2(max_noise);
    }
};

// --- Execution & Demonstration ---
int main() {
    std::cout << "=== BFV Homomorphic Encryption Toy Engine ===" << std::endl;
    std::cout << "Parameters: N=" << N << ", Q=" << Q << ", T=" << T << std::endl;
    double max_budget = std::log2(DELTA / 2.0);
    std::cout << "Max Noise Budget before failure: ~" << std::fixed << std::setprecision(2) << max_budget << " bits\n\n";

    BFVEngine fhe;

    int64_t m1 = 3;
    int64_t m2 = 2;

    std::cout << "[*] Encrypting m1 = " << m1 << " and m2 = " << m2 << std::endl;
    Ciphertext c1 = fhe.encrypt(m1);
    Ciphertext c2 = fhe.encrypt(m2);

    std::cout << "  -> c1 initial noise: " << fhe.calculate_noise_bits(c1, m1) << " bits" << std::endl;

    std::cout << "\n[*] Homomorphic Addition (c_add = c1 + c2)" << std::endl;
    Ciphertext c_add = fhe.add(c1, c2);
    int64_t dec_add = fhe.decrypt(c_add);
    std::cout << "  -> Decrypted result: " << dec_add << " (Expected: 5)" << std::endl;
    std::cout << "  -> Noise level: " << fhe.calculate_noise_bits(c_add, 5) << " bits (Linear, minimal growth)" << std::endl;

    std::cout << "\n[*] Homomorphic Multiplication (c_mult = c1 * c2)" << std::endl;
    Ciphertext c_mult = fhe.multiply(c1, c2);
    int64_t dec_mult = fhe.decrypt(c_mult);
    std::cout << "  -> Decrypted result: " << dec_mult << " (Expected: 6)" << std::endl;
    std::cout << "  -> Noise level: " << fhe.calculate_noise_bits(c_mult, 6) << " bits (Quadratic, large growth!)" << std::endl;

    std::cout << "\n[*] Demonstrating Circuit Depth Failure (Noise Budget Depletion)" << std::endl;
    Ciphertext current = c1;
    int64_t expected = m1;
    for(int depth = 1; depth <= 3; ++depth) {
        current = fhe.multiply(current, c1);
        expected = (expected * m1) % T;

        int64_t decrypted = fhe.decrypt(current);
        double noise = fhe.calculate_noise_bits(current, expected);

        std::cout << "  [Depth " << depth << "] Multiply by c1 again. Noise: " << noise << " bits.";
        if (noise > max_budget) {
            std::cout << " -> DECRYPTION FAILED! Result: " << decrypted << " (Expected: " << expected << ")\n";
            break;
        } else {
            std::cout << " -> Success. Result: " << decrypted << "\n";
        }
    }

    return 0;
}