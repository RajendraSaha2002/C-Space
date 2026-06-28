#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <mutex>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <random>

// ==========================================
// 1. BLAKE2b Core (Argon2 Compression)
// ==========================================
// Argon2 operates on 1024-byte blocks (128 uint64_t words)
struct Block {
    uint64_t v[128];
    Block() { std::memset(v, 0, sizeof(v)); }

    // XOR two blocks
    Block operator^(const Block& other) const {
        Block res;
        for (int i = 0; i < 128; ++i) res.v[i] = v[i] ^ other.v[i];
        return res;
    }
};

class Blake2bMixer {
private:
    static inline uint64_t rotr64(uint64_t x, int c) {
        return (x >> c) | (x << (64 - c));
    }

    // The core BLAKE2b G function used by Argon2
    static void G(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d) {
        a = a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF);
        d = rotr64(d ^ a, 32);
        c = c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF);
        b = rotr64(b ^ c, 24);
        a = a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF);
        d = rotr64(d ^ a, 16);
        c = c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF);
        b = rotr64(b ^ c, 63);
    }

    static void P(uint64_t state[8]) {
        G(state[0], state[4], state[8], state[12]);
        G(state[1], state[5], state[9], state[13]);
        G(state[2], state[6], state[10], state[14]);
        G(state[3], state[7], state[11], state[15]);
        G(state[0], state[5], state[10], state[15]);
        G(state[1], state[6], state[11], state[12]);
        G(state[2], state[7], state[8], state[13]);
        G(state[3], state[4], state[9], state[14]);
    }

public:
    // Argon2 block compression function
    static Block compress(const Block& x, const Block& y) {
        Block r = x ^ y;
        Block z = r;

        // Process rows
        for (int i = 0; i < 8; ++i) {
            uint64_t state[16];
            for(int j=0; j<16; j++) state[j] = z.v[i * 16 + j];
            P(state);
            for(int j=0; j<16; j++) z.v[i * 16 + j] = state[j];
        }

        // Process columns
        for (int i = 0; i < 8; ++i) {
            uint64_t state[16];
            for(int j=0; j<16; j++) state[j] = z.v[i + j * 8];
            P(state);
            for(int j=0; j<16; j++) z.v[i + j * 8] = state[j];
        }

        return z ^ r;
    }
};

// ==========================================
// 2. Argon2id Simulator Engine
// ==========================================
class Argon2idSimulator {
private:
    uint32_t memory_cost; // in KB (number of 1KB blocks)
    uint32_t time_cost;   // number of passes
    uint32_t lanes;       // degree of parallelism

    // Simulates the initialization of the first two blocks per lane
    void fill_first_blocks(std::vector<Block>& memory) {
        for (uint32_t l = 0; l < lanes; ++l) {
            memory[l * (memory_cost / lanes) + 0].v[0] = 0x11111111 * (l + 1);
            memory[l * (memory_cost / lanes) + 1].v[0] = 0x22222222 * (l + 1);
        }
    }

public:
    Argon2idSimulator(uint32_t m_cost, uint32_t t_cost, uint32_t p_lanes)
        : memory_cost(m_cost), time_cost(t_cost), lanes(p_lanes) {
        // Ensure memory is divisible by lanes
        if (memory_cost % lanes != 0) memory_cost += (lanes - (memory_cost % lanes));
    }

    void hash(const std::string& password, const std::string& salt) {
        std::vector<Block> memory(memory_cost);
        fill_first_blocks(memory);

        uint32_t lane_length = memory_cost / lanes;

        // Time cost passes
        for (uint32_t t = 0; t < time_cost; ++t) {
            std::vector<std::thread> threads;

            // Thread-parallel lanes
            for (uint32_t l = 0; l < lanes; ++l) {
                threads.emplace_back([&, l, t]() {
                    for (uint32_t i = 2; i < lane_length; ++i) {
                        uint32_t curr_idx = l * lane_length + i;
                        uint32_t prev_idx = curr_idx - 1;

                        // Hybrid Addressing Simulation (Argon2id trait)
                        // Uses data-independent (Argon2i) for first half, data-dependent (Argon2d) for second
                        uint32_t ref_idx;
                        if (t == 0 && i < lane_length / 2) {
                            // Data-independent (resists side-channel attacks)
                            ref_idx = l * lane_length + ((i * 13) % i);
                        } else {
                            // Data-dependent (resists GPU cracking)
                            uint64_t pseudo_rand = memory[prev_idx].v[0];
                            ref_idx = l * lane_length + (pseudo_rand % i);
                        }

                        memory[curr_idx] = Blake2bMixer::compress(memory[prev_idx], memory[ref_idx]);
                    }
                });
            }

            for (auto& th : threads) th.join();
        }

        // Final extraction (XORing the last block of each lane)
        Block final_hash;
        for (uint32_t l = 0; l < lanes; ++l) {
            final_hash = final_hash ^ memory[l * lane_length + (lane_length - 1)];
        }
    }
};

// ==========================================
// 3. Dummy PBKDF2 (For GPU Weakness Demo)
// ==========================================
class MockPBKDF2 {
public:
    // Purely compute bound, zero memory overhead
    static void hash(uint32_t iterations) {
        volatile uint64_t hash_val = 0;
        for (uint32_t i = 0; i < iterations; ++i) {
            hash_val ^= Blake2bMixer::compress(Block(), Block()).v[0] * i;
        }
    }
};

// ==========================================
// 4. Execution & Tradeoff Benchmarks
// ==========================================
int main() {
    std::cout << "=== Argon2id PBKDF Engine & Benchmarks ===\n\n";

    std::string pwd = "super_secret_password";
    std::string salt = "random_salt_123";

    std::cout << "[*] Running Time-Memory Tradeoff Benchmarks...\n";
    std::cout << "    (Demonstrating how memory hardness scales)\n\n";

    // Test configurations: {Memory (KB), Time (Passes), Lanes (Threads)}
    std::vector<std::vector<uint32_t>> configs = {
        {1024 * 16, 1, 4},   // 16 MB, 1 pass, 4 lanes
        {1024 * 32, 1, 4},   // 32 MB, 1 pass, 4 lanes
        {1024 * 64, 1, 4},   // 64 MB, 1 pass, 4 lanes
        {1024 * 64, 3, 4}    // 64 MB, 3 passes, 4 lanes
    };

    std::cout << std::left << std::setw(12) << "Memory"
              << std::setw(10) << "Passes"
              << std::setw(10) << "Threads"
              << "Execution Time\n";
    std::cout << "--------------------------------------------------\n";

    for (const auto& cfg : configs) {
        Argon2idSimulator argon2(cfg[0], cfg[1], cfg[2]);

        auto start = std::chrono::high_resolution_clock::now();
        argon2.hash(pwd, salt);
        auto end = std::chrono::high_resolution_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        std::cout << std::left << std::setw(12) << std::to_string(cfg[0] / 1024) + " MB"
                  << std::setw(10) << cfg[1]
                  << std::setw(10) << cfg[2]
                  << duration.count() << " ms\n";
    }

    std::cout << "\n=== Architectural Security Analysis ===\n";
    std::cout << "Why PBKDF2 and Bcrypt are weaker against GPUs:\n";

    auto start_pbkdf2 = std::chrono::high_resolution_clock::now();
    MockPBKDF2::hash(10000); // 10k iterations
    auto end_pbkdf2 = std::chrono::high_resolution_clock::now();
    auto dur_pbkdf2 = std::chrono::duration_cast<std::chrono::milliseconds>(end_pbkdf2 - start_pbkdf2);

    std::cout << "-> PBKDF2 simulated 10,000 iterations in " << dur_pbkdf2.count() << " ms.\n";
    std::cout << "-> PBKDF2 uses almost 0 RAM. A modern GPU with 10,000 ALUs can run 10,000 \n"
              << "   PBKDF2 instances in parallel entirely inside its L1 cache.\n";
    std::cout << "-> Argon2id requires (e.g.) 64MB PER THREAD. To run 10,000 Argon2id instances \n"
              << "   in parallel requires 640 GB of extremely fast RAM. GPUs do not have this \n"
              << "   capacity or memory bandwidth, destroying their parallel advantage.\n";

    return 0;
}