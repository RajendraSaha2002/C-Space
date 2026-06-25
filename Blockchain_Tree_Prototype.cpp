// ============================================================
// Project: Blockchain / Merkle Tree Prototype
// Platform: Windows/Linux/Mac — CLion / GCC / Clang / C++17
// ============================================================
// Features:
//   - Full SHA-256 engine from scratch (no OpenSSL)
//   - Merkle tree builder over arbitrary data blocks
//   - Merkle proof generator and verifier
//   - Blockchain with blocks containing Merkle roots
//   - Proof-of-Work mining (adjustable difficulty)
//   - Chain integrity validator
//   - Tamper detection demo
//   - Interactive CLI menu
// ============================================================

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <array>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <functional>
#include <cassert>

using u32 = uint32_t;
using u64 = uint64_t;
using u8  = uint8_t;

// ============================================================
// ============================================================
//   SECTION 1 — SHA-256 ENGINE (from scratch)
// ============================================================
// ============================================================
// SHA-256 processes input in 512-bit (64-byte) chunks.
// Each chunk goes through 64 rounds of mixing using:
//   - bitwise rotations and shifts
//   - addition modulo 2^32
//   - 8 working registers (a..h) initialized from hash state
// Output is 256 bits = 32 bytes = 8 x u32 words.
// ============================================================

// SHA-256 initial hash values (first 32 bits of fractional
// parts of the square roots of the first 8 primes)
static constexpr u32 SHA256_H0[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

// SHA-256 round constants (first 32 bits of fractional parts
// of the cube roots of the first 64 primes)
static constexpr u32 SHA256_K[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,
    0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,
    0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,
    0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,
    0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,
    0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,
    0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,
    0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,
    0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

// ============================================================
// SHA-256 BIT OPERATIONS
// ============================================================
static inline u32 rotr32(u32 x, int n) {
    return (x >> n) | (x << (32 - n));
}

// Sigma functions (message schedule expansion)
static inline u32 sig0(u32 x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}
static inline u32 sig1(u32 x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

// Capital Sigma functions (compression round mixing)
static inline u32 Sig0(u32 x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}
static inline u32 Sig1(u32 x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

// Choice: if bit in e is 1, take from f; else from g
static inline u32 Ch(u32 e, u32 f, u32 g) {
    return (e & f) ^ (~e & g);
}

// Majority: take the bit that appears in majority of a,b,c
static inline u32 Maj(u32 a, u32 b, u32 c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

// ============================================================
// SHA-256 DIGEST TYPE — 32 bytes
// ============================================================
struct SHA256Digest {
    u8 bytes[32] = {};

    // Convert to hex string
    std::string hex() const {
        std::ostringstream oss;
        for (int i = 0; i < 32; i++)
            oss << std::hex << std::setw(2)
                << std::setfill('0') << static_cast<int>(bytes[i]);
        return oss.str();
    }

    // Short 8-char prefix for display
    std::string short_hex() const {
        return hex().substr(0, 8) + "...";
    }

    bool operator==(const SHA256Digest& o) const {
        return std::memcmp(bytes, o.bytes, 32) == 0;
    }
    bool operator!=(const SHA256Digest& o) const {
        return !(*this == o);
    }

    // Return as vector for concatenation
    std::vector<u8> to_vec() const {
        return std::vector<u8>(bytes, bytes + 32);
    }
};

// ============================================================
// SHA-256 CORE — process one 512-bit block
// 'h' = current 8-word hash state (modified in-place)
// 'block' = 64 bytes of message data
// ============================================================
static void sha256_process_block(u32 h[8], const u8 block[64]) {

    // Message schedule array W[0..63]
    // W[0..15] loaded directly from block (big-endian u32)
    // W[16..63] expanded from W[i-2], W[i-7], W[i-15], W[i-16]
    u32 W[64];
    for (int i = 0; i < 16; i++) {
        W[i] = (static_cast<u32>(block[i*4+0]) << 24)
             | (static_cast<u32>(block[i*4+1]) << 16)
             | (static_cast<u32>(block[i*4+2]) <<  8)
             | (static_cast<u32>(block[i*4+3])      );
    }
    for (int i = 16; i < 64; i++) {
        W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];
    }

    // Initialize working variables from current hash state
    u32 a=h[0], b=h[1], c=h[2], d=h[3];
    u32 e=h[4], f=h[5], g=h[6], hh=h[7];

    // 64 rounds of compression
    for (int i = 0; i < 64; i++) {
        u32 T1 = hh + Sig1(e) + Ch(e,f,g) + SHA256_K[i] + W[i];
        u32 T2 = Sig0(a) + Maj(a,b,c);
        hh = g; g = f; f = e; e = d + T1;
        d  = c; c = b; b = a; a = T1 + T2;
    }

    // Add compressed chunk to current hash state
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
    h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

// ============================================================
// SHA-256 MAIN FUNCTION
// Pads the message, splits into 512-bit blocks, processes each.
// Padding rule:
//   1. Append 0x80 byte after message
//   2. Append zero bytes until length ≡ 56 (mod 64)
//   3. Append original message length as big-endian u64
// ============================================================
static SHA256Digest sha256(const u8* data, size_t len) {
    // Initialize hash state
    u32 h[8];
    std::memcpy(h, SHA256_H0, sizeof(SHA256_H0));

    // Total padded length: next multiple of 64 after (len+9)
    size_t padded_len = ((len + 9 + 63) / 64) * 64;
    std::vector<u8> msg(padded_len, 0);
    std::memcpy(msg.data(), data, len);

    // Padding: 0x80 bit
    msg[len] = 0x80;

    // Append original length in bits as big-endian u64
    u64 bit_len = static_cast<u64>(len) * 8;
    for (int i = 7; i >= 0; i--) {
        msg[padded_len - 8 + (7 - i)] =
            static_cast<u8>((bit_len >> (i * 8)) & 0xFF);
    }

    // Process each 64-byte block
    for (size_t offset = 0; offset < padded_len; offset += 64) {
        sha256_process_block(h, msg.data() + offset);
    }

    // Produce final digest (big-endian u32 words → bytes)
    SHA256Digest digest;
    for (int i = 0; i < 8; i++) {
        digest.bytes[i*4+0] = static_cast<u8>((h[i] >> 24) & 0xFF);
        digest.bytes[i*4+1] = static_cast<u8>((h[i] >> 16) & 0xFF);
        digest.bytes[i*4+2] = static_cast<u8>((h[i] >>  8) & 0xFF);
        digest.bytes[i*4+3] = static_cast<u8>((h[i]      ) & 0xFF);
    }
    return digest;
}

// Convenience overloads
static SHA256Digest sha256(const std::string& s) {
    return sha256(reinterpret_cast<const u8*>(s.data()), s.size());
}
static SHA256Digest sha256(const std::vector<u8>& v) {
    return sha256(v.data(), v.size());
}

// SHA-256 of two concatenated digests (used for Merkle nodes)
static SHA256Digest sha256_pair(const SHA256Digest& L,
                                 const SHA256Digest& R) {
    std::vector<u8> combined;
    combined.reserve(64);
    auto lv = L.to_vec();
    auto rv = R.to_vec();
    combined.insert(combined.end(), lv.begin(), lv.end());
    combined.insert(combined.end(), rv.begin(), rv.end());
    return sha256(combined);
}

// ============================================================
// ============================================================
//   SECTION 2 — MERKLE TREE
// ============================================================
// ============================================================
// A Merkle tree is a binary tree where:
//   - Leaf nodes    = SHA-256(data_block)
//   - Internal nodes = SHA-256(left_child || right_child)
//   - Root           = single hash summarizing ALL leaves
//
// Property: changing any single data block changes the root.
// Proof:    a Merkle proof is a path of sibling hashes from
//           the leaf up to the root — O(log N) hashes, not N.
// ============================================================

struct MerkleProofStep {
    SHA256Digest sibling;
    bool         is_left;   // true = sibling is on the left
};

struct MerkleProof {
    size_t                      leaf_index;
    SHA256Digest                leaf_hash;
    std::vector<MerkleProofStep> steps;
    SHA256Digest                claimed_root;

    bool is_valid() const {
        SHA256Digest current = leaf_hash;
        for (const auto& step : steps) {
            if (step.is_left)
                current = sha256_pair(step.sibling, current);
            else
                current = sha256_pair(current, step.sibling);
        }
        return current == claimed_root;
    }
};

class MerkleTree {
public:
    // Layers of the tree.
    // layers[0] = leaf hashes
    // layers[k] = level k above leaves
    // layers.back() = root (single element)
    std::vector<std::vector<SHA256Digest>> layers;

    // Build tree from raw data blocks
    void build(const std::vector<std::string>& data_blocks) {
        layers.clear();
        if (data_blocks.empty()) return;

        // Layer 0: hash each data block
        std::vector<SHA256Digest> leaves;
        leaves.reserve(data_blocks.size());
        for (const auto& d : data_blocks)
            leaves.push_back(sha256(d));
        layers.push_back(leaves);

        // Build upward until we reach the root
        while (layers.back().size() > 1) {
            const auto& prev = layers.back();
            std::vector<SHA256Digest> next;
            next.reserve((prev.size() + 1) / 2);

            for (size_t i = 0; i + 1 < prev.size(); i += 2)
                next.push_back(sha256_pair(prev[i], prev[i+1]));

            // Odd number of nodes: duplicate last (Bitcoin convention)
            if (prev.size() % 2 == 1)
                next.push_back(sha256_pair(prev.back(),
                                            prev.back()));

            layers.push_back(next);
        }
    }

    // Root hash of the tree
    SHA256Digest root() const {
        if (layers.empty()) {
            SHA256Digest empty{};
            return empty;
        }
        return layers.back()[0];
    }

    // Number of leaf nodes
    size_t leaf_count() const {
        return layers.empty() ? 0 : layers[0].size();
    }

    // Tree depth (number of levels including root)
    size_t depth() const { return layers.size(); }

    // Generate Merkle proof for leaf at given index
    MerkleProof generate_proof(size_t leaf_idx) const {
        MerkleProof proof;
        proof.leaf_index  = leaf_idx;
        proof.leaf_hash   = layers[0][leaf_idx];
        proof.claimed_root = root();

        size_t idx = leaf_idx;
        for (size_t level = 0; level + 1 < layers.size(); level++) {
            const auto& layer = layers[level];
            bool is_right = (idx % 2 == 1);

            MerkleProofStep step;
            if (is_right) {
                // Current is right child: sibling is to the left
                step.sibling = layer[idx - 1];
                step.is_left = true;
            } else {
                // Current is left child: sibling is to the right
                // (or duplicate if last odd node)
                size_t sib_idx = (idx + 1 < layer.size())
                                     ? idx + 1 : idx;
                step.sibling = layer[sib_idx];
                step.is_left = false;
            }
            proof.steps.push_back(step);
            idx /= 2;
        }
        return proof;
    }

    // Print tree structure to console
    void print(const std::string& title = "Merkle Tree") const {
        std::cout << "\n";
        sep('=');
        std::cout << "  " << title << "\n";
        sep('=');
        if (layers.empty()) {
            std::cout << "  (empty)\n";
            return;
        }

        // Print from root down to leaves
        for (int level = static_cast<int>(layers.size()) - 1;
             level >= 0; level--) {
            std::string label;
            if (level == static_cast<int>(layers.size()) - 1)
                label = "ROOT    ";
            else if (level == 0)
                label = "LEAVES  ";
            else
                label = "LEVEL " + std::to_string(level) + " ";

            std::cout << "  " << label << ": ";
            for (size_t i = 0; i < layers[level].size(); i++) {
                std::cout << layers[level][i].short_hex();
                if (i + 1 < layers[level].size())
                    std::cout << "  |  ";
            }
            std::cout << "\n";
        }
        sep();
        std::cout << "  Leaves : " << leaf_count() << "\n";
        std::cout << "  Depth  : " << depth() << " levels\n";
        std::cout << "  Root   : " << root().hex() << "\n";
        sep();
    }

private:
    static void sep(char c = '-', int w = 64) {
        std::cout << std::string(w, c) << "\n";
    }
};

// ============================================================
// ============================================================
//   SECTION 3 — BLOCKCHAIN
// ============================================================
// ============================================================
// Each Block contains:
//   - index           : position in the chain
//   - timestamp       : Unix time of creation
//   - transactions    : vector of string data entries
//   - merkle_root     : Merkle root of transactions
//   - previous_hash   : hash of the preceding block
//   - nonce           : proof-of-work counter
//   - block_hash      : SHA-256(all fields above)
//
// Chain is valid if:
//   1. Every block's merkle_root matches its transactions
//   2. Every block's previous_hash matches the prior block hash
//   3. Every block_hash starts with 'difficulty' zero nibbles
// ============================================================

struct Block {
    u64                      index          = 0;
    u64                      timestamp      = 0;
    std::vector<std::string> transactions;
    SHA256Digest             merkle_root;
    SHA256Digest             previous_hash;
    u64                      nonce          = 0;
    SHA256Digest             block_hash;
    u32                      difficulty     = 0;

    // Compute the canonical string representation of this block
    // (everything except block_hash itself)
    std::string header_string() const {
        std::ostringstream oss;
        oss << index
            << timestamp;
        for (const auto& tx : transactions)
            oss << tx;
        oss << merkle_root.hex()
            << previous_hash.hex()
            << nonce
            << difficulty;
        return oss.str();
    }

    // Compute block hash from current fields
    SHA256Digest compute_hash() const {
        return sha256(header_string());
    }

    // Check if hash meets difficulty target (leading zero nibbles)
    static bool meets_difficulty(const SHA256Digest& h, u32 diff) {
        std::string hex_str = h.hex();
        for (u32 i = 0; i < diff && i < 64; i++)
            if (hex_str[i] != '0') return false;
        return true;
    }

    // Mine this block: increment nonce until hash meets difficulty
    void mine(u32 diff) {
        difficulty = diff;
        nonce = 0;
        do {
            nonce++;
            block_hash = compute_hash();
        } while (!meets_difficulty(block_hash, diff));
    }

    // Print block summary
    void print() const {
        auto ts = [](u64 t) -> std::string {
            time_t tt = static_cast<time_t>(t);
            char buf[32];
            struct tm tm_info;
#ifdef _WIN32
            localtime_s(&tm_info, &tt);
#else
            localtime_r(&tt, &tm_info);
#endif
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_info);
            return std::string(buf);
        };

        std::cout << "  Index       : " << index << "\n"
                  << "  Timestamp   : " << ts(timestamp) << "\n"
                  << "  Difficulty  : " << difficulty
                  << " (leading zero nibbles)\n"
                  << "  Nonce       : " << nonce << "\n"
                  << "  Tx count    : " << transactions.size() << "\n"
                  << "  Merkle root : " << merkle_root.hex() << "\n"
                  << "  Prev hash   : " << previous_hash.hex() << "\n"
                  << "  Block hash  : " << block_hash.hex() << "\n";
        std::cout << "  Transactions:\n";
        for (size_t i = 0; i < transactions.size(); i++)
            std::cout << "    [" << i << "] " << transactions[i] << "\n";
    }
};

class Blockchain {
public:
    std::vector<Block> chain;
    u32                difficulty;

    explicit Blockchain(u32 diff = 3) : difficulty(diff) {
        // Create genesis block
        Block genesis;
        genesis.index     = 0;
        genesis.timestamp = static_cast<u64>(
                                std::time(nullptr));
        genesis.transactions = {"Genesis Block — "
                                 "ASCON Blockchain v1.0"};

        // Build Merkle tree for genesis transactions
        MerkleTree mt;
        mt.build(genesis.transactions);
        genesis.merkle_root = mt.root();

        // Genesis has no previous block — use zero hash
        std::memset(genesis.previous_hash.bytes, 0, 32);

        std::cout << "[CHAIN] Mining genesis block "
                     "(difficulty=" << difficulty << ")...\n";
        auto t0 = std::chrono::high_resolution_clock::now();
        genesis.mine(difficulty);
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double,
                    std::milli>(t1 - t0).count();

        chain.push_back(genesis);
        std::cout << "[CHAIN] Genesis mined in "
                  << std::fixed << std::setprecision(1)
                  << ms << " ms | nonce=" << genesis.nonce
                  << " | hash=" << genesis.block_hash.short_hex()
                  << "\n";
    }

    // Add a new block with the given transactions
    Block& add_block(std::vector<std::string> txs) {
        Block blk;
        blk.index     = chain.size();
        blk.timestamp = static_cast<u64>(std::time(nullptr));
        blk.transactions = std::move(txs);

        // Build Merkle tree
        MerkleTree mt;
        mt.build(blk.transactions);
        blk.merkle_root   = mt.root();
        blk.previous_hash = chain.back().block_hash;

        std::cout << "[CHAIN] Mining block #" << blk.index
                  << " (difficulty=" << difficulty << ")...\n";
        auto t0 = std::chrono::high_resolution_clock::now();
        blk.mine(difficulty);
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double,
                    std::milli>(t1 - t0).count();

        chain.push_back(blk);
        std::cout << "[CHAIN] Block #" << blk.index
                  << " mined in "
                  << std::fixed << std::setprecision(1)
                  << ms << " ms | nonce="
                  << blk.nonce << " | hash="
                  << blk.block_hash.short_hex() << "\n";
        return chain.back();
    }

    // Validate entire chain — returns true if valid
    bool validate(bool verbose = true) const {
        if (verbose) {
            sep('=');
            std::cout << "  CHAIN VALIDATION\n";
            sep('=');
        }

        bool all_valid = true;

        for (size_t i = 0; i < chain.size(); i++) {
            const Block& blk = chain[i];
            bool blk_ok = true;
            std::vector<std::string> errors;

            // Check 1: block hash is correctly computed
            SHA256Digest expected = blk.compute_hash();
            if (expected != blk.block_hash) {
                blk_ok = false;
                errors.push_back("block hash mismatch");
            }

            // Check 2: hash meets difficulty
            if (!Block::meets_difficulty(blk.block_hash,
                                          blk.difficulty)) {
                blk_ok = false;
                errors.push_back("difficulty not met");
            }

            // Check 3: previous hash links correctly
            if (i > 0) {
                if (blk.previous_hash !=
                    chain[i-1].block_hash) {
                    blk_ok = false;
                    errors.push_back("previous_hash broken");
                }
            }

            // Check 4: Merkle root matches transactions
            MerkleTree mt;
            mt.build(blk.transactions);
            if (mt.root() != blk.merkle_root) {
                blk_ok = false;
                errors.push_back("merkle root mismatch");
            }

            if (verbose) {
                std::cout << "  Block #" << i << " : "
                          << (blk_ok ? "VALID  " : "INVALID")
                          << "  " << blk.block_hash.short_hex();
                if (!blk_ok) {
                    std::cout << "  [ERRORS: ";
                    for (size_t e = 0; e < errors.size(); e++) {
                        std::cout << errors[e];
                        if (e+1 < errors.size())
                            std::cout << ", ";
                    }
                    std::cout << "]";
                }
                std::cout << "\n";
            }

            if (!blk_ok) all_valid = false;
        }

        if (verbose) {
            sep();
            std::cout << "  Chain length : "
                      << chain.size() << " blocks\n";
            std::cout << "  Overall      : "
                      << (all_valid ? "CHAIN VALID" : "CHAIN INVALID")
                      << "\n";
            sep('=');
        }
        return all_valid;
    }

    // Print the full chain
    void print_chain() const {
        sep('=');
        std::cout << "  FULL BLOCKCHAIN ("
                  << chain.size() << " blocks)\n";
        sep('=');
        for (const auto& blk : chain) {
            sep();
            std::cout << "  BLOCK #" << blk.index << "\n";
            sep();
            blk.print();
        }
        sep('=');
    }

    // Demonstrate Merkle proof for a transaction in a block
    void demo_merkle_proof(size_t block_idx,
                            size_t tx_idx) const {
        if (block_idx >= chain.size()) {
            std::cout << "[PROOF] Block index out of range.\n";
            return;
        }
        const Block& blk = chain[block_idx];
        if (tx_idx >= blk.transactions.size()) {
            std::cout << "[PROOF] Transaction index "
                         "out of range.\n";
            return;
        }

        MerkleTree mt;
        mt.build(blk.transactions);
        MerkleProof proof = mt.generate_proof(tx_idx);

        sep('=');
        std::cout << "  MERKLE PROOF\n";
        sep('=');
        std::cout << "  Block     : #" << block_idx << "\n";
        std::cout << "  Tx index  : " << tx_idx << "\n";
        std::cout << "  Tx data   : \""
                  << blk.transactions[tx_idx] << "\"\n";
        std::cout << "  Leaf hash : "
                  << proof.leaf_hash.hex() << "\n";
        std::cout << "  Steps     : "
                  << proof.steps.size() << "\n\n";

        SHA256Digest current = proof.leaf_hash;
        std::cout << "  Start : " << current.short_hex() << "\n";
        for (size_t s = 0; s < proof.steps.size(); s++) {
            const auto& step = proof.steps[s];
            std::string dir = step.is_left ? "LEFT " : "RIGHT";
            SHA256Digest combined;
            if (step.is_left)
                combined = sha256_pair(step.sibling, current);
            else
                combined = sha256_pair(current, step.sibling);

            std::cout << "  Step " << (s+1) << ": SHA256("
                      << dir << "="
                      << step.sibling.short_hex()
                      << " || " << current.short_hex()
                      << ") = " << combined.short_hex() << "\n";
            current = combined;
        }

        std::cout << "\n  Computed root  : "
                  << proof.claimed_root.hex() << "\n";
        std::cout << "  Stored root    : "
                  << blk.merkle_root.hex() << "\n";
        sep();
        std::cout << "  Proof result   : "
                  << (proof.is_valid() ? "VALID — tx is in block"
                                       : "INVALID — tx not found")
                  << "\n";
        sep('=');
    }

    // Tamper with a transaction in a block (for demo)
    void tamper_transaction(size_t block_idx,
                             size_t tx_idx,
                             const std::string& new_data) {
        if (block_idx >= chain.size() ||
            tx_idx >= chain[block_idx].transactions.size())
            return;

        std::cout << "\n[TAMPER] Modifying block #" << block_idx
                  << " tx[" << tx_idx << "]\n";
        std::cout << "[TAMPER] Old: \""
                  << chain[block_idx].transactions[tx_idx] << "\"\n";

        chain[block_idx].transactions[tx_idx] = new_data;

        std::cout << "[TAMPER] New: \"" << new_data << "\"\n";
        std::cout << "[TAMPER] Note: block hash and Merkle root "
                     "NOT updated (simulating attack).\n\n";
    }

private:
    static void sep(char c = '-', int w = 64) {
        std::cout << std::string(w, c) << "\n";
    }
};

// ============================================================
// ============================================================
//   SECTION 4 — SHA-256 SELF-TEST
// ============================================================
// ============================================================
// Known-answer tests from NIST FIPS 180-4 test vectors.
// These verify our SHA-256 implementation is correct.
// ============================================================

struct SHA256TestVector {
    std::string input;
    std::string expected_hex;
    std::string description;
};

static const std::vector<SHA256TestVector> SHA256_TESTS = {
    {
        "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "empty string"
    },
    {
        "abc",
        "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469fa72a7f8c7b"
        "a9ac8",
        "NIST vector: abc"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419"
        "db06c1",
        "NIST vector: 448-bit message"
    },
    {
        "The quick brown fox jumps over the lazy dog",
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c"
        "9e592",
        "pangram"
    },
    {
        "hello world",
        "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576dce35d3"
        "d3c3e7d5a",
        "hello world"
    }
};

static void run_sha256_tests() {
    std::cout << "\n";
    std::string sep64(64, '=');
    std::cout << sep64 << "\n";
    std::cout << "  SHA-256 SELF-TEST (NIST vectors)\n";
    std::cout << sep64 << "\n";

    int pass = 0, fail = 0;
    for (const auto& tv : SHA256_TESTS) {
        SHA256Digest got = sha256(tv.input);
        // Normalize expected (remove spaces, lowercase)
        std::string exp = tv.expected_hex;
        exp.erase(std::remove(exp.begin(), exp.end(), ' '),
                  exp.end());
        bool ok = (got.hex() == exp);
        std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] "
                  << tv.description << "\n";
        if (!ok) {
            std::cout << "    Expected : " << exp << "\n";
            std::cout << "    Got      : " << got.hex() << "\n";
            fail++;
        } else {
            pass++;
        }
    }
    std::string sep64m(64, '-');
    std::cout << sep64m << "\n";
    std::cout << "  Results: " << pass << " passed, "
              << fail << " failed.\n";
    std::cout << sep64 << "\n";
}

// ============================================================
// ============================================================
//   SECTION 5 — INTERACTIVE DEMO
// ============================================================
// ============================================================

static void sep(char c = '-', int w = 64) {
    std::cout << std::string(w, c) << "\n";
}

static void print_banner() {
    sep('=');
    std::cout << "\n";
    std::cout << "  ██████╗ ██╗      ██████╗  ██████╗██╗  ██╗\n";
    std::cout << "  ██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝\n";
    std::cout << "  ██████╔╝██║     ██║   ██║██║     █████╔╝ \n";
    std::cout << "  ██╔══██╗██║     ██║   ██║██║     ██╔═██╗ \n";
    std::cout << "  ██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗\n";
    std::cout << "  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝\n";
    std::cout << "\n";
    std::cout << "  Blockchain + Merkle Tree Prototype\n";
    std::cout << "  SHA-256 from scratch | No external libs\n";
    std::cout << "\n";
    sep('=');
}

static void print_menu() {
    std::cout << "\n";
    sep();
    std::cout << "  MAIN MENU\n";
    sep();
    std::cout << "  1. Run SHA-256 self-tests\n";
    std::cout << "  2. Build and display a Merkle tree\n";
    std::cout << "  3. Generate + verify a Merkle proof\n";
    std::cout << "  4. Show full blockchain\n";
    std::cout << "  5. Add a new block\n";
    std::cout << "  6. Validate blockchain\n";
    std::cout << "  7. Demo tamper detection\n";
    std::cout << "  8. Hash any string with SHA-256\n";
    std::cout << "  0. Exit\n";
    sep();
    std::cout << "  Choice: ";
}

int main() {
    print_banner();

    // Build initial blockchain (difficulty=2 for speed in demo)
    std::cout << "\n[INIT] Building demo blockchain...\n";
    Blockchain chain(2);

    chain.add_block({
        "Alice -> Bob   : 5.00 BTC",
        "Bob   -> Carol : 2.50 BTC",
        "Carol -> Dave  : 1.25 BTC",
        "Dave  -> Eve   : 0.75 BTC"
    });

    chain.add_block({
        "Eve   -> Frank : 3.00 BTC",
        "Frank -> Grace : 1.00 BTC",
        "Grace -> Heidi : 0.50 BTC"
    });

    chain.add_block({
        "Heidi -> Ivan  : 2.00 BTC",
        "Ivan  -> Judy  : 1.50 BTC",
        "Judy  -> Karl  : 0.25 BTC",
        "Karl  -> Leo   : 4.00 BTC",
        "Leo   -> Mia   : 0.10 BTC"
    });

    std::cout << "[INIT] Demo blockchain ready ("
              << chain.chain.size() << " blocks).\n";

    // ============================================================
    // INTERACTIVE LOOP
    // ============================================================
    int choice = -1;
    while (choice != 0) {
        print_menu();
        std::cin >> choice;
        std::cin.ignore();
        std::cout << "\n";

        // --------------------------------------------------------
        if (choice == 1) {
            run_sha256_tests();
        }

        // --------------------------------------------------------
        else if (choice == 2) {
            std::cout << "How many data blocks? (2-16): ";
            int n; std::cin >> n; std::cin.ignore();
            n = std::max(2, std::min(n, 16));

            std::vector<std::string> blocks;
            for (int i = 0; i < n; i++) {
                std::cout << "  Block[" << i << "]: ";
                std::string s; std::getline(std::cin, s);
                if (s.empty()) s = "Block_" + std::to_string(i);
                blocks.push_back(s);
            }

            MerkleTree mt;
            mt.build(blocks);
            mt.print("Your Merkle Tree");

            std::cout << "\n  Leaf hashes:\n";
            for (size_t i = 0; i < blocks.size(); i++) {
                std::cout << "  [" << i << "] \""
                          << blocks[i] << "\"\n"
                          << "       "
                          << sha256(blocks[i]).hex() << "\n";
            }
        }

        // --------------------------------------------------------
        else if (choice == 3) {
            std::cout << "  Block index (0-"
                      << chain.chain.size()-1 << "): ";
            size_t bi; std::cin >> bi; std::cin.ignore();
            if (bi >= chain.chain.size()) {
                std::cout << "  Invalid block index.\n";
                continue;
            }
            size_t tc = chain.chain[bi].transactions.size();
            std::cout << "  Tx index (0-" << tc-1 << "): ";
            size_t ti; std::cin >> ti; std::cin.ignore();
            chain.demo_merkle_proof(bi, ti);
        }

        // --------------------------------------------------------
        else if (choice == 4) {
            chain.print_chain();
        }

        // --------------------------------------------------------
        else if (choice == 5) {
            std::cout << "  How many transactions? (1-10): ";
            int n; std::cin >> n; std::cin.ignore();
            n = std::max(1, std::min(n, 10));

            std::vector<std::string> txs;
            for (int i = 0; i < n; i++) {
                std::cout << "  Tx[" << i << "]: ";
                std::string s; std::getline(std::cin, s);
                if (s.empty())
                    s = "Tx_" + std::to_string(i)
                        + "_at_"
                        + std::to_string(std::time(nullptr));
                txs.push_back(s);
            }
            chain.add_block(txs);
            std::cout << "  Block added. Chain now has "
                      << chain.chain.size() << " blocks.\n";
        }

        // --------------------------------------------------------
        else if (choice == 6) {
            chain.validate(true);
        }

        // --------------------------------------------------------
        else if (choice == 7) {
            sep('=');
            std::cout << "  TAMPER DETECTION DEMO\n";
            sep('=');

            std::cout << "\n  Step 1: Validate chain BEFORE tampering.\n";
            bool before = chain.validate(false);
            std::cout << "  Chain valid: "
                      << (before ? "YES" : "NO") << "\n\n";

            // Tamper with block 1, transaction 0
            chain.tamper_transaction(1, 0,
                "Alice -> HACKER : 5.00 BTC  [TAMPERED]");

            std::cout << "  Step 2: Validate chain AFTER tampering.\n";
            chain.validate(true);

            std::cout << "\n  Step 3: Restore original transaction.\n";
            chain.tamper_transaction(1, 0,
                "Alice -> Bob   : 5.00 BTC");
            std::cout << "  Chain after restore:\n";
            chain.validate(true);
        }

        // --------------------------------------------------------
        else if (choice == 8) {
            std::cout << "  Enter string to hash: ";
            std::string s; std::getline(std::cin, s);
            SHA256Digest d = sha256(s);
            sep();
            std::cout << "  Input  : \"" << s << "\"\n";
            std::cout << "  Length : " << s.size() << " bytes\n";
            std::cout << "  SHA-256: " << d.hex() << "\n";
            sep();

            // Also show avalanche effect
            if (!s.empty()) {
                std::string s2 = s;
                s2[0] ^= 1;   // flip one bit of first char
                SHA256Digest d2 = sha256(s2);
                std::cout << "  Avalanche effect (1 bit flip):\n";
                std::cout << "  Input2 : \"" << s2 << "\"\n";
                std::cout << "  SHA-256: " << d2.hex() << "\n";

                // Count differing bits
                int diff_bits = 0;
                for (int i = 0; i < 32; i++) {
                    u8 x = d.bytes[i] ^ d2.bytes[i];
                    while (x) { diff_bits += x & 1; x >>= 1; }
                }
                std::cout << "  Bits changed: " << diff_bits
                          << " / 256 ("
                          << std::fixed << std::setprecision(1)
                          << (diff_bits * 100.0 / 256.0)
                          << "%) — ideal ~50%\n";
                sep();
            }
        }

        // --------------------------------------------------------
        else if (choice == 0) {
            sep('=');
            std::cout << "  Goodbye. Chain had "
                      << chain.chain.size()
                      << " blocks.\n";
            sep('=');
        }

        else {
            std::cout << "  Unknown option. Try again.\n";
        }
    }

    return 0;
}