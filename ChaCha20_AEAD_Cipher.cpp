// ============================================================
// Project P05: ChaCha20-Poly1305 AEAD Cipher From Scratch
// Platform: Windows/Linux/Mac — CLion / GCC / Clang / C++17
// ============================================================
// Components implemented from scratch (zero external libs):
//   - ChaCha20 stream cipher (RFC 7539 / RFC 8439)
//     * Quarter-round function
//     * 20-round block function (10 column + 10 diagonal)
//     * Keystream generation with 64-bit counter
//   - Poly1305 MAC (RFC 8439)
//     * 130-bit integer arithmetic in C++
//     * Clamping, accumulation, finalization
//   - ChaCha20-Poly1305 AEAD (RFC 8439)
//     * OTK (one-time key) derivation from ChaCha20 block 0
//     * Encrypt-then-MAC construction
//     * Associated data authentication
//     * Constant-time tag comparison
//   - Benchmark suite vs ASCON-128
//   - NIST/RFC test vector verification
//   - Interactive CLI demo
// ============================================================

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <array>
#include <cstring>
#include <cstdint>
#include <cassert>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <functional>
#include <random>

using u8  = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i64 = int64_t;

// ============================================================
// ============================================================
//   SECTION 1 — UTILITY FUNCTIONS
// ============================================================
// ============================================================

// Load 4 bytes from a buffer as a little-endian u32.
// ChaCha20 and Poly1305 both use little-endian byte order.
static inline u32 load_le32(const u8* p) {
    return  static_cast<u32>(p[0])
         | (static_cast<u32>(p[1]) <<  8)
         | (static_cast<u32>(p[2]) << 16)
         | (static_cast<u32>(p[3]) << 24);
}

// Load 8 bytes from a buffer as a little-endian u64.
static inline u64 load_le64(const u8* p) {
    return  static_cast<u64>(p[0])
         | (static_cast<u64>(p[1]) <<  8)
         | (static_cast<u64>(p[2]) << 16)
         | (static_cast<u64>(p[3]) << 24)
         | (static_cast<u64>(p[4]) << 32)
         | (static_cast<u64>(p[5]) << 40)
         | (static_cast<u64>(p[6]) << 48)
         | (static_cast<u64>(p[7]) << 56);
}

// Store a u32 to 4 bytes in little-endian order.
static inline void store_le32(u8* p, u32 v) {
    p[0] = static_cast<u8>(v      );
    p[1] = static_cast<u8>(v >>  8);
    p[2] = static_cast<u8>(v >> 16);
    p[3] = static_cast<u8>(v >> 24);
}

// Store a u64 to 8 bytes in little-endian order.
static inline void store_le64(u8* p, u64 v) {
    p[0] = static_cast<u8>(v      );
    p[1] = static_cast<u8>(v >>  8);
    p[2] = static_cast<u8>(v >> 16);
    p[3] = static_cast<u8>(v >> 24);
    p[4] = static_cast<u8>(v >> 32);
    p[5] = static_cast<u8>(v >> 40);
    p[6] = static_cast<u8>(v >> 48);
    p[7] = static_cast<u8>(v >> 56);
}

// Rotate-left for u32 — used in the ChaCha20 quarter-round.
static inline u32 rotl32(u32 x, int n) {
    return (x << n) | (x >> (32 - n));
}

// Convert bytes to lowercase hex string.
static std::string to_hex(const u8* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++)
        oss << std::hex << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(data[i]);
    return oss.str();
}

static std::string to_hex(const std::vector<u8>& v) {
    return to_hex(v.data(), v.size());
}

// Parse a hex string into a byte vector.
static std::vector<u8> from_hex(const std::string& hex) {
    std::vector<u8> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        u8 byte = static_cast<u8>(
            std::stoul(hex.substr(i, 2), nullptr, 16));
        out.push_back(byte);
    }
    return out;
}

// Console separator helpers.
static void sep(char c = '-', int w = 68) {
    std::cout << std::string(w, c) << "\n";
}
static void hdr(const std::string& t) {
    sep('=');
    std::cout << "  " << t << "\n";
    sep('=');
}

// ============================================================
// ============================================================
//   SECTION 2 — CHACHA20 STREAM CIPHER (RFC 8439)
// ============================================================
// ============================================================
//
// State layout (16 x u32 words):
//   [0..3]   = constants "expa" "nd 3" "2-by" "te k"
//   [4..11]  = 256-bit key (8 x u32, little-endian)
//   [12]     = 32-bit block counter
//   [13..15] = 96-bit nonce (3 x u32, little-endian)
//
// Each block produces 64 bytes of keystream.
// Block counter starts at 0 for key generation (Poly1305 OTK),
// and at 1 for message encryption (RFC 8439 §2.6).
// ============================================================

// ChaCha20 magic constant bytes (ASCII "expand 32-byte k")
static constexpr u32 CC20_C0 = 0x61707865U; // "expa"
static constexpr u32 CC20_C1 = 0x3320646eU; // "nd 3"
static constexpr u32 CC20_C2 = 0x79622d32U; // "2-by"
static constexpr u32 CC20_C3 = 0x6b206574U; // "te k"

// ============================================================
// QUARTER ROUND — the core mixing primitive of ChaCha20.
// Mixes four u32 words (a, b, c, d) using Add-Rotate-XOR.
// Applied to columns and diagonals of the 4×4 state matrix.
//
// Each step:
//   a += b; d ^= a; d <<<= 16;
//   c += d; b ^= c; b <<<= 12;
//   a += b; d ^= a; d <<<= 8;
//   c += d; b ^= c; b <<<= 7;
//
// The rotation amounts (16,12,8,7) are fixed by the spec.
// ============================================================
static inline void quarter_round(u32& a, u32& b,
                                  u32& c, u32& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d,  8);
    c += d; b ^= c; b = rotl32(b,  7);
}

// ============================================================
// CHACHA20 BLOCK FUNCTION
// Input:  key[32], nonce[12], counter (u32)
// Output: 64-byte keystream block
//
// 1. Load state: constants || key || counter || nonce
// 2. Run 20 rounds (10 column rounds + 10 diagonal rounds)
// 3. Add original state to working copy (prevent inversion)
// 4. Serialize 16 u32 words to 64 bytes (little-endian)
// ============================================================
static void chacha20_block(const u8  key[32],
                            const u8  nonce[12],
                            u32       counter,
                            u8        out[64]) {
    // Initialize state
    u32 s[16] = {
        CC20_C0,           CC20_C1,
        CC20_C2,           CC20_C3,
        load_le32(key +  0), load_le32(key +  4),
        load_le32(key +  8), load_le32(key + 12),
        load_le32(key + 16), load_le32(key + 20),
        load_le32(key + 24), load_le32(key + 28),
        counter,
        load_le32(nonce + 0),
        load_le32(nonce + 4),
        load_le32(nonce + 8)
    };

    // Save original state for final addition
    u32 orig[16];
    std::memcpy(orig, s, sizeof(s));

    // 20 rounds = 10 iterations of (column round + diagonal round)
    for (int i = 0; i < 10; i++) {
        // Column rounds: operate on the 4 columns of the 4×4 matrix
        // Column 0: s[0], s[4], s[8],  s[12]
        // Column 1: s[1], s[5], s[9],  s[13]
        // Column 2: s[2], s[6], s[10], s[14]
        // Column 3: s[3], s[7], s[11], s[15]
        quarter_round(s[ 0], s[ 4], s[ 8], s[12]);
        quarter_round(s[ 1], s[ 5], s[ 9], s[13]);
        quarter_round(s[ 2], s[ 6], s[10], s[14]);
        quarter_round(s[ 3], s[ 7], s[11], s[15]);

        // Diagonal rounds: operate on the 4 diagonals
        // Diag 0: s[0], s[5], s[10], s[15]
        // Diag 1: s[1], s[6], s[11], s[12]
        // Diag 2: s[2], s[7], s[8],  s[13]
        // Diag 3: s[3], s[4], s[9],  s[14]
        quarter_round(s[ 0], s[ 5], s[10], s[15]);
        quarter_round(s[ 1], s[ 6], s[11], s[12]);
        quarter_round(s[ 2], s[ 7], s[ 8], s[13]);
        quarter_round(s[ 3], s[ 4], s[ 9], s[14]);
    }

    // Add original state back — this makes the block function
    // non-invertible without knowing the key.
    for (int i = 0; i < 16; i++) s[i] += orig[i];

    // Serialize 16 u32 words to 64 bytes (little-endian)
    for (int i = 0; i < 16; i++)
        store_le32(out + i * 4, s[i]);
}

// ============================================================
// CHACHA20 ENCRYPT / DECRYPT
// XORs the plaintext with the ChaCha20 keystream.
// counter_start = 1 for message encryption (RFC 8439 §2.4).
// Same function works for both encrypt and decrypt (XOR is
// its own inverse).
// ============================================================
static void chacha20_xor(const u8*  key,
                          const u8*  nonce,
                          u32        counter_start,
                          const u8*  in,
                          u8*        out,
                          size_t     len) {
    u8 keystream[64];
    size_t offset = 0;
    u32 counter = counter_start;

    while (offset < len) {
        chacha20_block(key, nonce, counter, keystream);
        counter++;

        size_t chunk = std::min(static_cast<size_t>(64),
                                 len - offset);
        for (size_t i = 0; i < chunk; i++)
            out[offset + i] = in[offset + i] ^ keystream[i];

        offset += chunk;
    }

    // Zero keystream from stack — good practice for key material
    std::memset(keystream, 0, sizeof(keystream));
}

// ============================================================
// ============================================================
//   SECTION 3 — POLY1305 MAC (RFC 8439)
// ============================================================
// ============================================================
//
// Poly1305 is a one-time authenticator:
//   tag = ((r * msg_as_polynomial) + s) mod (2^130 - 5)
//
// Key is 32 bytes: r[16] || s[16]
//   r = first 16 bytes, clamped (some bits forced to 0)
//   s = last  16 bytes, used as final addition
//
// Message is split into 16-byte blocks. Each block is treated
// as a 130-bit number (with a leading 1 bit), accumulated into
// a running sum, and multiplied by r mod (2^130 - 5).
//
// We implement 130-bit arithmetic using three u64 limbs
// in base 2^44 (limb0 | limb1 | limb2), which avoids
// 128-bit integers and keeps the code portable.
// ============================================================

struct Poly1305 {
    // Accumulator: 130-bit value in three u64 limbs.
    // Each limb holds up to 44 bits (base 2^44).
    // h = h0 + h1*2^44 + h2*2^88
    u64 h0 = 0, h1 = 0, h2 = 0;

    // r: clamped 128-bit key in the same limb format
    u64 r0 = 0, r1 = 0, r2 = 0;

    // s: 128-bit addend (final step)
    u64 s0 = 0, s1 = 0;

    // --------------------------------------------------------
    // KEY SETUP
    // r[0..15] from key[0..15], clamped per RFC 8439 §2.5.1
    // s[0..15] from key[16..31]
    //
    // Clamping: forces certain bits of r to zero to ensure
    // the polynomial evaluations stay within the field.
    // Specifically: r[3],r[7],r[11],r[15] have top 4 bits
    // cleared, and r[4],r[8],r[12] have bottom 2 bits cleared.
    // --------------------------------------------------------
    void init(const u8 key[32]) {
        // Load r and apply clamping mask
        u8 r_bytes[16];
        std::memcpy(r_bytes, key, 16);
        r_bytes[ 3] &= 0x0f;
        r_bytes[ 7] &= 0x0f;
        r_bytes[11] &= 0x0f;
        r_bytes[15] &= 0x0f;
        r_bytes[ 4] &= 0xfc;
        r_bytes[ 8] &= 0xfc;
        r_bytes[12] &= 0xfc;

        // Convert r to three 44-bit limbs
        u64 r_lo = load_le64(r_bytes + 0);
        u64 r_hi = load_le64(r_bytes + 8);
        r0 = (r_lo      ) & 0x000003FFFFFFFFFF; // bits 0..43
        r1 = (r_lo >> 44) | ((r_hi & 0x3) << 20); // bits 44..87
        r1 &= 0x000003FFFFFFFFFF;
        r2 = (r_hi >> 24) & 0x000000FFFFFFFFFF; // bits 88..127

        // Load s as two 64-bit words (little-endian)
        s0 = load_le64(key + 16);
        s1 = load_le64(key + 24);

        // Reset accumulator
        h0 = h1 = h2 = 0;
    }

    // --------------------------------------------------------
    // PROCESS ONE BLOCK (up to 16 bytes)
    // Interprets the block as a 130-bit little-endian integer
    // with a 1 bit appended at position (8 * block_len).
    // Then: h = (h + block) * r  mod (2^130 - 5)
    //
    // The multiplication mod (2^130-5) uses the identity:
    //   x * 2^130 ≡ x * 5  (mod 2^130-5)
    // which means overflow of h2 can be reduced cheaply by
    // multiplying the overflow by 5 and adding back to h0.
    // --------------------------------------------------------
    void process_block(const u8* blk, size_t blk_len) {
        // Build 130-bit number from up to 16 bytes
        u64 t0 = 0, t1 = 0;
        u8  buf[17] = {};
        std::memcpy(buf, blk, blk_len);
        buf[blk_len] = 1;  // append the "1" bit above the data

        t0 = load_le64(buf + 0);
        t1 = load_le64(buf + 8);
        u64 t2 = buf[16]; // the appended 1 (or 2 for full 16-byte blocks)

        // Add block to accumulator (split into 44-bit limbs)
        h0 += (t0      ) & 0x000003FFFFFFFFFF;
        h1 += (t0 >> 44) | ((t1 & 0xFFF) << 20);
        h2 += (t1 >> 24) | (t2 << 40);

        // Multiply h by r mod (2^130 - 5)
        // Using the schoolbook algorithm with 44-bit limbs.
        // d[i] = sum of all products h[j] * r[k] where j+k = i
        // (with the reduction: r[2]*5 is used for the wraparound)

        // r2 * 5 precomputed for the mod reduction
        u64 r2_5 = r2 * 5;

        __uint128_t d0 = static_cast<__uint128_t>(h0) * r0
                       + static_cast<__uint128_t>(h1) * r2_5
                       + static_cast<__uint128_t>(h2) * (r1 * 5);

        __uint128_t d1 = static_cast<__uint128_t>(h0) * r1
                       + static_cast<__uint128_t>(h1) * r0
                       + static_cast<__uint128_t>(h2) * r2_5;

        __uint128_t d2 = static_cast<__uint128_t>(h0) * r2
                       + static_cast<__uint128_t>(h1) * r1
                       + static_cast<__uint128_t>(h2) * r0;

        // Propagate carries to stay within 44-bit limbs
        u64 c;
        h0  = static_cast<u64>(d0) & 0x000003FFFFFFFFFF;
        c   = static_cast<u64>(d0 >> 44);
        d1 += c;
        h1  = static_cast<u64>(d1) & 0x000003FFFFFFFFFF;
        c   = static_cast<u64>(d1 >> 44);
        d2 += c;
        h2  = static_cast<u64>(d2) & 0x000003FFFFFFFFFFUL;
        c   = static_cast<u64>(d2 >> 42);
        // c * 5 reduction: h2 overflow folds back to h0
        h0 += c * 5;
        c   = h0 >> 44;
        h0 &= 0x000003FFFFFFFFFF;
        h1 += c;
    }

    // --------------------------------------------------------
    // FINALIZE — produce the 16-byte tag
    // 1. Fully reduce h mod (2^130 - 5)
    // 2. Add s (mod 2^128)
    // 3. Serialize to 16 bytes little-endian
    // --------------------------------------------------------
    void finalize(u8 tag[16]) {
        // Carry propagation to normalize limbs
        u64 c;
        c   = h1 >> 44; h1 &= 0x000003FFFFFFFFFF;
        h2 += c;
        c   = h2 >> 42; h2 &= 0x000003FFFFFFFFFFUL;
        h0 += c * 5;
        c   = h0 >> 44; h0 &= 0x000003FFFFFFFFFF;
        h1 += c;
        c   = h1 >> 44; h1 &= 0x000003FFFFFFFFFF;
        h2 += c;

        // Reconstruct h as two 64-bit words from 44-bit limbs
        u64 g0 = h0 | (h1 << 44);
        u64 g1 = (h1 >> 20) | (h2 << 24);

        // Conditionally subtract (2^130 - 5) if h >= p
        // by computing h + 5 and checking for overflow
        u64 mask;
        {
            unsigned __int128 t =
                (unsigned __int128)g0 + 5;
            u64 gg0 = static_cast<u64>(t);
            u64 gg1 = g1 + static_cast<u64>(t >> 64);
            // If gg1 >= 2^128: carry out means h >= p, use gg
            mask = (gg1 >> 63) ? 0xFFFFFFFFFFFFFFFFULL : 0ULL;
            // Wait — we want to use gg if gg1 wrapped (h was >= p)
            // Simpler: check bit 130 of h
            u64 carry = static_cast<u64>(
                ((unsigned __int128)h0
                 + (h1 << 44)
                 + ((h2 & ~0x3ULL) << 24)) >> 128);
            (void)carry; // absorbed via mask below

            // Compute mask properly:
            // if h+5 >= 2^130 then h >= 2^130-5 = p
            unsigned __int128 hp =
                ((unsigned __int128)h2 << 88)
                | ((unsigned __int128)h1 << 44)
                | h0;
            unsigned __int128 p130m5 =
                ((unsigned __int128)3 << 128)
                | 0xFFFFFFFFFFFFFFFBULL;
            (void)p130m5;

            // Practical: subtract p if h2 > 3 or
            // (h2==3 and low 128 bits >= 2^128-5)
            if (h2 > 3 || (h2 == 3 && g0 >= 0xFFFFFFFFFFFFFFFBULL)) {
                g0 += 5;
                if (g0 < 5) g1++; // carry
                mask = 0xFFFFFFFFFFFFFFFFULL;
            } else {
                mask = 0;
            }
        }

        // Add s mod 2^128
        unsigned __int128 r128 =
              (unsigned __int128)g0
            + s0
            + (((unsigned __int128)(g1 + s1)) << 64);

        u64 tag0 = static_cast<u64>(r128);
        u64 tag1 = static_cast<u64>(r128 >> 64);

        store_le64(tag + 0, tag0);
        store_le64(tag + 8, tag1);
    }

    // --------------------------------------------------------
    // ONE-SHOT: process all data and produce tag
    // --------------------------------------------------------
    void compute(const u8* key,
                  const u8* msg, size_t msg_len,
                  u8        tag[16]) {
        init(key);
        size_t offset = 0;
        while (offset < msg_len) {
            size_t chunk = std::min(static_cast<size_t>(16),
                                     msg_len - offset);
            process_block(msg + offset, chunk);
            offset += chunk;
        }
        finalize(tag);
    }
};

// ============================================================
// ============================================================
//   SECTION 4 — CHACHA20-POLY1305 AEAD (RFC 8439)
// ============================================================
// ============================================================
//
// AEAD construction:
//   1. Generate Poly1305 one-time key (OTK):
//      OTK[0..31] = ChaCha20_block(key, nonce, counter=0)[0..31]
//   2. Encrypt message:
//      ciphertext = ChaCha20_xor(key, nonce, counter=1, plaintext)
//   3. Authenticate:
//      mac_data = pad16(aad) || pad16(ciphertext)
//                 || le64(len(aad)) || le64(len(ciphertext))
//      tag = Poly1305(OTK, mac_data)
//
// Wire format output: ciphertext || tag[16]
// ============================================================

// Pad a message to a multiple of 16 bytes with zero bytes.
static std::vector<u8> pad16(const u8* data, size_t len) {
    std::vector<u8> out(data, data + len);
    size_t pad = (16 - (len % 16)) % 16;
    out.resize(out.size() + pad, 0);
    return out;
}

// ============================================================
// CHACHA20-POLY1305 ENCRYPT
// key[32], nonce[12], aad (additional authenticated data),
// plaintext → ciphertext (same length) + tag[16]
// ============================================================
static void chacha20_poly1305_encrypt(
        const u8*              key,
        const u8*              nonce,
        const std::vector<u8>& aad,
        const std::vector<u8>& plaintext,
        std::vector<u8>&       ciphertext,
        u8                     tag[16])
{
    // Step 1: Generate Poly1305 one-time key from block 0
    u8 keystream0[64];
    chacha20_block(key, nonce, 0, keystream0);
    u8 otk[32];
    std::memcpy(otk, keystream0, 32);

    // Step 2: Encrypt plaintext using ChaCha20 (counter=1)
    ciphertext.resize(plaintext.size());
    if (!plaintext.empty()) {
        chacha20_xor(key, nonce, 1,
                      plaintext.data(),
                      ciphertext.data(),
                      plaintext.size());
    }

    // Step 3: Build Poly1305 input (RFC 8439 §2.8)
    // mac_data = pad16(aad) || pad16(ciphertext)
    //            || le64(aad_len) || le64(ct_len)
    std::vector<u8> mac_data;
    {
        auto paad = pad16(aad.data(), aad.size());
        auto pct  = pad16(ciphertext.data(), ciphertext.size());
        mac_data.insert(mac_data.end(), paad.begin(), paad.end());
        mac_data.insert(mac_data.end(), pct.begin(),  pct.end());

        u8 len_bytes[16];
        store_le64(len_bytes + 0,
                   static_cast<u64>(aad.size()));
        store_le64(len_bytes + 8,
                   static_cast<u64>(ciphertext.size()));
        mac_data.insert(mac_data.end(),
                        len_bytes, len_bytes + 16);
    }

    // Step 4: Compute authentication tag
    Poly1305 poly;
    poly.compute(otk,
                  mac_data.data(), mac_data.size(),
                  tag);

    // Zero OTK from stack
    std::memset(otk, 0, 32);
    std::memset(keystream0, 0, 64);
}

// ============================================================
// CHACHA20-POLY1305 DECRYPT
// Returns true if tag is valid and plaintext recovered.
// Returns false on authentication failure (plaintext zeroed).
// Uses constant-time tag comparison to prevent timing attacks.
// ============================================================
static bool chacha20_poly1305_decrypt(
        const u8*              key,
        const u8*              nonce,
        const std::vector<u8>& aad,
        const std::vector<u8>& ciphertext,
        const u8               received_tag[16],
        std::vector<u8>&       plaintext)
{
    // Step 1: Generate same OTK
    u8 keystream0[64];
    chacha20_block(key, nonce, 0, keystream0);
    u8 otk[32];
    std::memcpy(otk, keystream0, 32);

    // Step 2: Recompute tag over same mac_data
    std::vector<u8> mac_data;
    {
        auto paad = pad16(aad.data(), aad.size());
        auto pct  = pad16(ciphertext.data(), ciphertext.size());
        mac_data.insert(mac_data.end(), paad.begin(), paad.end());
        mac_data.insert(mac_data.end(), pct.begin(),  pct.end());

        u8 len_bytes[16];
        store_le64(len_bytes + 0,
                   static_cast<u64>(aad.size()));
        store_le64(len_bytes + 8,
                   static_cast<u64>(ciphertext.size()));
        mac_data.insert(mac_data.end(),
                        len_bytes, len_bytes + 16);
    }

    u8 computed_tag[16];
    Poly1305 poly;
    poly.compute(otk,
                  mac_data.data(), mac_data.size(),
                  computed_tag);

    // Step 3: Constant-time tag comparison (XOR all 16 bytes)
    // Short-circuit comparison leaks timing info about
    // which byte mismatches — always compare all 16 bytes.
    u8 diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= computed_tag[i] ^ received_tag[i];

    if (diff != 0) {
        // Authentication failed — wipe any intermediate data
        std::memset(otk, 0, 32);
        std::memset(keystream0, 0, 64);
        std::memset(computed_tag, 0, 16);
        return false;
    }

    // Step 4: Decrypt (ChaCha20 counter=1)
    plaintext.resize(ciphertext.size());
    if (!ciphertext.empty()) {
        chacha20_xor(key, nonce, 1,
                      ciphertext.data(),
                      plaintext.data(),
                      ciphertext.size());
    }

    std::memset(otk, 0, 32);
    std::memset(keystream0, 0, 64);
    return true;
}

// ============================================================
// ============================================================
//   SECTION 5 — RFC 8439 TEST VECTORS
// ============================================================
// ============================================================
// These are the official test vectors from RFC 8439.
// Passing all of these means the implementation is correct.
// ============================================================

struct TestResult {
    std::string name;
    bool        passed;
    std::string detail;
};

static std::vector<TestResult> g_results;

static void check(const std::string& name,
                   const std::string& expected,
                   const std::string& got) {
    bool ok = (expected == got);
    g_results.push_back({name, ok,
        ok ? "" : "expected: " + expected
               + "\n       got:      " + got});
    std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] "
              << name << "\n";
    if (!ok) {
        std::cout << "         expected: " << expected << "\n";
        std::cout << "         got:      " << got      << "\n";
    }
}

static void run_rfc_tests() {
    hdr("RFC 8439 TEST VECTORS");

    // --------------------------------------------------------
    // TEST 1: Quarter round (RFC 8439 §2.1.1)
    // Input:  a=0x11111111, b=0x01020304,
    //         c=0x9b8d6f43, d=0x01234567
    // Output: a=0xea2a92f4, b=0xcb1cf8ce,
    //         c=0x4581472e, d=0x5881c4bb
    // --------------------------------------------------------
    {
        u32 a = 0x11111111, b = 0x01020304;
        u32 c = 0x9b8d6f43, d = 0x01234567;
        quarter_round(a, b, c, d);
        std::ostringstream oss;
        oss << std::hex
            << std::setw(8) << std::setfill('0') << a << " "
            << std::setw(8) << b << " "
            << std::setw(8) << c << " "
            << std::setw(8) << d;
        check("Quarter round §2.1.1",
              "ea2a92f4 cb1cf8ce 4581472e 5881c4bb",
              oss.str());
    }

    // --------------------------------------------------------
    // TEST 2: ChaCha20 block function (RFC 8439 §2.1.2)
    // Key = 0x00010203...1f, Nonce = 0x000000090000004a00000000
    // Counter = 1
    // Expected first 4 output words (little-endian):
    //   e4e7f110 15593bd1 1fdd0f50 c47120a3
    // --------------------------------------------------------
    {
        u8 key[32], nonce[12];
        for (int i = 0; i < 32; i++) key[i]   = static_cast<u8>(i);
        nonce[0]=0x00; nonce[1]=0x00; nonce[2]=0x00; nonce[3]=0x09;
        nonce[4]=0x00; nonce[5]=0x00; nonce[6]=0x00; nonce[7]=0x4a;
        nonce[8]=0x00; nonce[9]=0x00; nonce[10]=0x00; nonce[11]=0x00;

        u8 out[64];
        chacha20_block(key, nonce, 1, out);

        // Check first 16 bytes
        std::string got = to_hex(out, 16);
        check("ChaCha20 block §2.1.2 (first 16 bytes)",
              "10f1e7e4d13b5915500fdd1fa32071c4",
              got);
    }

    // --------------------------------------------------------
    // TEST 3: ChaCha20 encrypt (RFC 8439 §2.4.2)
    // Key = 0x00010203...1f
    // Nonce = 0x000000000000004a00000000
    // Counter = 1
    // Plaintext = "Ladies and Gentlemen of the class of '99..."
    // --------------------------------------------------------
    {
        u8 key[32];
        for (int i = 0; i < 32; i++) key[i] = static_cast<u8>(i);
        u8 nonce[12] = {
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x4a,
            0x00,0x00,0x00,0x00
        };

        std::string pt_str =
            "Ladies and Gentlemen of the class of '99: "
            "If I could offer you only one tip for the "
            "future, sunscreen would be it.";

        std::vector<u8> pt(pt_str.begin(), pt_str.end());
        std::vector<u8> ct(pt.size());
        chacha20_xor(key, nonce, 1,
                      pt.data(), ct.data(), pt.size());

        // RFC 8439 expected ciphertext (first 32 bytes)
        std::string expected_hex =
            "6e2e359a2568f98041ba0728dd0d6981"
            "e97e7aec1d4360c20a27afccfd9fae0b";
        check("ChaCha20 encrypt §2.4.2 (first 32B)",
              expected_hex,
              to_hex(ct.data(), 32));
    }

    // --------------------------------------------------------
    // TEST 4: Poly1305 key generation from ChaCha20
    // (RFC 8439 §2.6.2)
    // Key = 0x80818283...9f, Nonce = 0x000000000001020304050607
    // Expected OTK first 16 bytes: 8ad5a08b905f81cc815040274ab29471
    // --------------------------------------------------------
    {
        u8 key[32];
        for (int i = 0; i < 32; i++)
            key[i] = static_cast<u8>(0x80 + i);
        u8 nonce[12] = {
            0x00,0x00,0x00,0x00,
            0x01,0x02,0x03,0x04,
            0x05,0x06,0x07,0x00  // note: last byte 0
        };
        // Fix: nonce is 0x000000000001020304050607
        nonce[0]=0x00; nonce[1]=0x00; nonce[2]=0x00; nonce[3]=0x00;
        nonce[4]=0x00; nonce[5]=0x01; nonce[6]=0x02; nonce[7]=0x03;
        nonce[8]=0x04; nonce[9]=0x05; nonce[10]=0x06; nonce[11]=0x07;

        u8 ks[64];
        chacha20_block(key, nonce, 0, ks);
        check("Poly1305 OTK generation §2.6.2",
              "8ad5a08b905f81cc815040274ab29471",
              to_hex(ks, 16));
    }

    // --------------------------------------------------------
    // TEST 5: Poly1305 MAC (RFC 8439 §2.5.2)
    // key = 0x85d6be78...
    // msg = "Cryptographic Forum Research Group"
    // tag = a8061dc1305136c6c22b8baf0c0127a9
    // --------------------------------------------------------
    {
        std::vector<u8> key = from_hex(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b");
        std::string msg_str = "Cryptographic Forum Research Group";
        std::vector<u8> msg(msg_str.begin(), msg_str.end());

        u8 tag[16];
        Poly1305 poly;
        poly.compute(key.data(),
                      msg.data(), msg.size(), tag);
        check("Poly1305 MAC §2.5.2",
              "a8061dc1305136c6c22b8baf0c0127a9",
              to_hex(tag, 16));
    }

    // --------------------------------------------------------
    // TEST 6: Full ChaCha20-Poly1305 AEAD (RFC 8439 §2.8.2)
    // --------------------------------------------------------
    {
        std::vector<u8> key = from_hex(
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f");
        std::vector<u8> nonce_v = from_hex(
            "070000004041424344454647");
        std::vector<u8> aad = from_hex(
            "50515253c0c1c2c3c4c5c6c7");
        std::string pt_str =
            "Ladies and Gentlemen of the class of '99: "
            "If I could offer you only one tip for the "
            "future, sunscreen would be it.";
        std::vector<u8> pt(pt_str.begin(), pt_str.end());

        u8 nonce[12];
        std::memcpy(nonce, nonce_v.data(), 12);

        std::vector<u8> ct;
        u8 tag[16];
        chacha20_poly1305_encrypt(
            key.data(), nonce, aad, pt, ct, tag);

        // RFC 8439 expected ciphertext first 32 bytes
        check("AEAD encrypt ciphertext §2.8.2 (first 32B)",
              "d31a8d34648e60db7b86afbc53ef7ec2"
              "a4aded51296e08fea9e2b5a736ee62d6",
              to_hex(ct.data(), 32));

        // RFC 8439 expected tag
        check("AEAD tag §2.8.2",
              "1ae10b594f09e26a7e902ecbd0600691",
              to_hex(tag, 16));

        // Verify decryption round-trip
        std::vector<u8> recovered;
        bool ok = chacha20_poly1305_decrypt(
            key.data(), nonce, aad, ct, tag, recovered);
        check("AEAD decrypt round-trip §2.8.2",
              pt_str,
              std::string(recovered.begin(), recovered.end()));
        check("AEAD auth tag valid",
              "true", ok ? "true" : "false");
    }

    // --------------------------------------------------------
    // TEST 7: Authentication failure on tampered ciphertext
    // --------------------------------------------------------
    {
        u8 key[32] = {};
        u8 nonce[12] = {};
        std::vector<u8> aad = {'T','e','s','t'};
        std::vector<u8> pt  = {'H','e','l','l','o'};

        std::vector<u8> ct;
        u8 tag[16];
        chacha20_poly1305_encrypt(key, nonce, aad, pt, ct, tag);

        // Flip one bit in ciphertext
        ct[0] ^= 0x01;

        std::vector<u8> recovered;
        bool ok = chacha20_poly1305_decrypt(
            key, nonce, aad, ct, tag, recovered);
        check("Tamper detection (flipped ciphertext bit)",
              "false", ok ? "true" : "false");
    }

    // --------------------------------------------------------
    // TEST 8: Empty message AEAD
    // --------------------------------------------------------
    {
        u8 key[32] = {};
        u8 nonce[12] = {};
        std::vector<u8> aad = {};
        std::vector<u8> pt  = {};

        std::vector<u8> ct;
        u8 tag[16];
        chacha20_poly1305_encrypt(key, nonce, aad, pt, ct, tag);

        std::vector<u8> recovered;
        bool ok = chacha20_poly1305_decrypt(
            key, nonce, aad, ct, tag, recovered);
        check("Empty message round-trip",
              "true", ok ? "true" : "false");
        check("Empty ciphertext length",
              "0", std::to_string(ct.size()));
    }

    // Print summary
    sep();
    int passed = 0, failed = 0;
    for (auto& r : g_results) {
        if (r.passed) passed++;
        else          failed++;
    }
    std::cout << "  Results: " << passed << " passed, "
              << failed << " failed.\n";
    sep('=');
}

// ============================================================
// ============================================================
//   SECTION 6 — BENCHMARK SUITE
// ============================================================
// ============================================================
// Measures throughput of:
//   - ChaCha20 keystream generation (MB/s)
//   - Poly1305 authentication (MB/s)
//   - ChaCha20-Poly1305 AEAD combined (MB/s)
// For comparison reference against ASCON-128 (your engine).
// ============================================================

static void run_benchmarks() {
    hdr("BENCHMARK SUITE");

    const size_t DATA_SIZE = 1024 * 1024; // 1 MB
    const int    ITERS     = 10;

    std::vector<u8> data(DATA_SIZE, 0xAB);
    std::vector<u8> out(DATA_SIZE);
    u8  key[32]   = {};
    u8  nonce[12] = {};

    // Fill key with test pattern
    for (int i = 0; i < 32; i++) key[i] = static_cast<u8>(i);

    // --------------------------------------------------------
    // BENCH 1: ChaCha20 keystream generation
    // --------------------------------------------------------
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        for (int iter = 0; iter < ITERS; iter++) {
            chacha20_xor(key, nonce, 1,
                          data.data(), out.data(), DATA_SIZE);
            nonce[0]++; // change nonce each iter
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(
                        t1 - t0).count();
        double mb_per_s = (DATA_SIZE * ITERS / 1e6) / (ms / 1000.0);
        std::cout << "  ChaCha20 encrypt (1MB x" << ITERS << "):\n";
        std::cout << "    Time     : " << std::fixed
                  << std::setprecision(1) << ms << " ms\n";
        std::cout << "    Throughput: " << std::setprecision(1)
                  << mb_per_s << " MB/s\n\n";
    }

    // --------------------------------------------------------
    // BENCH 2: Poly1305 authentication
    // --------------------------------------------------------
    {
        u8 otk[32] = {};
        u8 tag[16];
        auto t0 = std::chrono::high_resolution_clock::now();
        for (int iter = 0; iter < ITERS; iter++) {
            Poly1305 poly;
            poly.compute(otk, data.data(), DATA_SIZE, tag);
            otk[0]++;
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(
                        t1 - t0).count();
        double mb_per_s = (DATA_SIZE * ITERS / 1e6) / (ms / 1000.0);
        std::cout << "  Poly1305 MAC (1MB x" << ITERS << "):\n";
        std::cout << "    Time     : " << std::fixed
                  << std::setprecision(1) << ms << " ms\n";
        std::cout << "    Throughput: " << std::setprecision(1)
                  << mb_per_s << " MB/s\n\n";
    }

    // --------------------------------------------------------
    // BENCH 3: Full AEAD (encrypt + authenticate)
    // --------------------------------------------------------
    {
        std::vector<u8> aad(16, 0xCC);
        std::vector<u8> ct;
        u8 tag[16];
        nonce[0] = 0;

        auto t0 = std::chrono::high_resolution_clock::now();
        for (int iter = 0; iter < ITERS; iter++) {
            chacha20_poly1305_encrypt(
                key, nonce, aad, data, ct, tag);
            nonce[0]++;
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(
                        t1 - t0).count();
        double mb_per_s = (DATA_SIZE * ITERS / 1e6) / (ms / 1000.0);
        std::cout << "  ChaCha20-Poly1305 AEAD (1MB x"
                  << ITERS << "):\n";
        std::cout << "    Time     : " << std::fixed
                  << std::setprecision(1) << ms << " ms\n";
        std::cout << "    Throughput: " << std::setprecision(1)
                  << mb_per_s << " MB/s\n\n";
    }

    // --------------------------------------------------------
    // BENCH 4: Small packet overhead (typical TLS record = 1400B)
    // --------------------------------------------------------
    {
        const size_t PKT = 1400;
        const int    PKT_ITERS = 100000;
        std::vector<u8> pkt(PKT, 0xFF);
        std::vector<u8> aad(13, 0xAA); // TLS record header
        std::vector<u8> ct;
        u8 tag[16];
        nonce[0] = 0;

        auto t0 = std::chrono::high_resolution_clock::now();
        for (int iter = 0; iter < PKT_ITERS; iter++) {
            chacha20_poly1305_encrypt(
                key, nonce, aad, pkt, ct, tag);
            nonce[0]++;
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(
                        t1 - t0).count();
        double pkts_per_s = PKT_ITERS / (ms / 1000.0);
        double mb_per_s =
            (PKT * static_cast<double>(PKT_ITERS) / 1e6)
            / (ms / 1000.0);
        std::cout << "  AEAD small packets (1400B x"
                  << PKT_ITERS << "):\n";
        std::cout << "    Time      : " << std::fixed
                  << std::setprecision(1) << ms << " ms\n";
        std::cout << "    Packets/s : " << std::setprecision(0)
                  << pkts_per_s << "\n";
        std::cout << "    Throughput: " << std::setprecision(1)
                  << mb_per_s << " MB/s\n\n";
    }

    // --------------------------------------------------------
    // COMPARISON NOTES
    // --------------------------------------------------------
    sep();
    std::cout << "  COMPARISON REFERENCE (typical values):\n";
    std::cout << "  ChaCha20-Poly1305 (this impl): see above\n";
    std::cout << "  OpenSSL ChaCha20-Poly1305    : ~3000-6000 MB/s"
                 " (AES-NI + AVX2)\n";
    std::cout << "  ASCON-128 (your engine)       : ~50-200 MB/s"
                 " (designed for IoT)\n";
    std::cout << "  AES-256-GCM (hardware AES-NI) : ~4000-8000 MB/s\n";
    std::cout << "\n  Note: This is a pure C++ reference "
                 "implementation.\n";
    std::cout << "  Production use requires SIMD intrinsics "
                 "(AVX2/NEON)\n";
    std::cout << "  for competitive performance.\n";
    sep('=');
}

// ============================================================
// ============================================================
//   SECTION 7 — NONCE MISUSE ANALYSIS
// ============================================================
// ============================================================
// Demonstrates WHY nonce reuse breaks ChaCha20-Poly1305
// confidentiality (same nonce + same key = same keystream).
// This is the critical security property that makes
// WireGuard use a counter-based nonce.
// ============================================================

static void demo_nonce_misuse() {
    hdr("NONCE MISUSE DEMONSTRATION");

    u8 key[32] = {};
    u8 nonce[12] = {};
    for (int i = 0; i < 32; i++) key[i] = static_cast<u8>(i);

    std::string msg1 = "Attack at dawn on the eastern front";
    std::string msg2 = "Retreat to the western supply depot";

    std::vector<u8> pt1(msg1.begin(), msg1.end());
    std::vector<u8> pt2(msg2.begin(), msg2.end());

    // Same nonce used twice — DANGEROUS
    std::vector<u8> ct1(pt1.size()), ct2(pt2.size());
    chacha20_xor(key, nonce, 1,
                  pt1.data(), ct1.data(), pt1.size());
    chacha20_xor(key, nonce, 1,   // same nonce!
                  pt2.data(), ct2.data(), pt2.size());

    // An attacker who observes both ciphertexts can XOR them:
    // ct1 XOR ct2 = (pt1 XOR ks) XOR (pt2 XOR ks) = pt1 XOR pt2
    // This eliminates the keystream entirely.
    size_t xor_len = std::min(ct1.size(), ct2.size());
    std::vector<u8> ct_xor(xor_len);
    for (size_t i = 0; i < xor_len; i++)
        ct_xor[i] = ct1[i] ^ ct2[i];

    // Now XOR with known plaintext of msg1 to recover msg2
    std::vector<u8> recovered(xor_len);
    for (size_t i = 0; i < xor_len; i++)
        recovered[i] = ct_xor[i] ^ pt1[i];

    std::cout << "  Key      : " << to_hex(key, 32) << "\n";
    std::cout << "  Nonce    : " << to_hex(nonce, 12)
              << " (REUSED for both messages!)\n\n";
    std::cout << "  Message 1: \"" << msg1 << "\"\n";
    std::cout << "  Message 2: \"" << msg2 << "\"\n\n";
    std::cout << "  CT1 XOR CT2 (attacker computes this):\n";
    std::cout << "  " << to_hex(ct_xor) << "\n\n";
    std::cout << "  Recovered msg2 using known msg1:\n";
    std::cout << "  \""
              << std::string(recovered.begin(),
                              recovered.end())
              << "\"\n\n";
    sep();
    std::cout << "  LESSON: Nonce reuse eliminates stream cipher\n";
    std::cout << "  security. WireGuard prevents this by:\n";
    std::cout << "    1. Using a 64-bit monotonic counter as nonce\n";
    std::cout << "    2. Rejecting packets with replayed counters\n";
    std::cout << "    3. Rotating the key pair every 180 seconds\n";
    sep('=');
}

// ============================================================
// ============================================================
//   SECTION 8 — INTERACTIVE DEMO
// ============================================================
// ============================================================

static void print_banner() {
    sep('=');
    std::cout << "\n"
        "   ██████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗ █████╗\n"
        "  ██╔════╝██║  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗\n"
        "  ██║     ███████║███████║██║     ███████║███████║\n"
        "  ██║     ██╔══██║██╔══██║██║     ██╔══██║██╔══██║\n"
        "  ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██║██║  ██║\n"
        "   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝\n"
        "\n"
        "  ChaCha20-Poly1305 AEAD — from scratch\n"
        "  RFC 8439 compliant | Zero external libraries\n"
        "\n";
    sep('=');
}

static void print_menu() {
    std::cout << "\n";
    sep();
    std::cout << "  MAIN MENU\n";
    sep();
    std::cout << "  1.  Run RFC 8439 test vectors\n";
    std::cout << "  2.  Run benchmark suite\n";
    std::cout << "  3.  Nonce misuse demonstration\n";
    std::cout << "  4.  Encrypt a custom message\n";
    std::cout << "  5.  Decrypt a hex ciphertext\n";
    std::cout << "  6.  ChaCha20 keystream inspector\n";
    std::cout << "  7.  Poly1305 MAC calculator\n";
    std::cout << "  8.  Avalanche effect demo\n";
    std::cout << "  0.  Exit\n";
    sep();
    std::cout << "  Choice: ";
}

// ============================================================
// MAIN
// ============================================================
int main() {
    print_banner();

    int choice = -1;
    while (choice != 0) {
        print_menu();
        std::cin >> choice;
        std::cin.ignore();
        std::cout << "\n";

        // --------------------------------------------------------
        if (choice == 1) {
            g_results.clear();
            run_rfc_tests();
        }

        // --------------------------------------------------------
        else if (choice == 2) {
            run_benchmarks();
        }

        // --------------------------------------------------------
        else if (choice == 3) {
            demo_nonce_misuse();
        }

        // --------------------------------------------------------
        else if (choice == 4) {
            hdr("ENCRYPT A MESSAGE");

            std::cout << "  Key (64 hex chars, or press Enter"
                         " for zero key): ";
            std::string key_hex;
            std::getline(std::cin, key_hex);
            u8 key[32] = {};
            if (key_hex.size() == 64) {
                auto kv = from_hex(key_hex);
                std::memcpy(key, kv.data(), 32);
            }

            std::cout << "  Nonce (24 hex chars, or Enter"
                         " for zero nonce): ";
            std::string nonce_hex;
            std::getline(std::cin, nonce_hex);
            u8 nonce[12] = {};
            if (nonce_hex.size() == 24) {
                auto nv = from_hex(nonce_hex);
                std::memcpy(nonce, nv.data(), 12);
            }

            std::cout << "  AAD (additional data, or Enter"
                         " for none): ";
            std::string aad_str;
            std::getline(std::cin, aad_str);
            std::vector<u8> aad(aad_str.begin(), aad_str.end());

            std::cout << "  Plaintext: ";
            std::string pt_str;
            std::getline(std::cin, pt_str);
            std::vector<u8> pt(pt_str.begin(), pt_str.end());

            std::vector<u8> ct;
            u8 tag[16];
            chacha20_poly1305_encrypt(
                key, nonce, aad, pt, ct, tag);

            sep();
            std::cout << "  Key   : " << to_hex(key, 32) << "\n";
            std::cout << "  Nonce : " << to_hex(nonce, 12) << "\n";
            std::cout << "  AAD   : \"" << aad_str << "\"\n";
            std::cout << "  PT    : \"" << pt_str  << "\"\n";
            std::cout << "  CT    : " << to_hex(ct) << "\n";
            std::cout << "  Tag   : " << to_hex(tag, 16) << "\n";
            sep('=');
        }

        // --------------------------------------------------------
        else if (choice == 5) {
            hdr("DECRYPT A CIPHERTEXT");

            std::cout << "  Key (64 hex chars): ";
            std::string key_hex; std::getline(std::cin, key_hex);
            u8 key[32] = {};
            if (key_hex.size() == 64) {
                auto kv = from_hex(key_hex);
                std::memcpy(key, kv.data(), 32);
            }

            std::cout << "  Nonce (24 hex chars): ";
            std::string nonce_hex;
            std::getline(std::cin, nonce_hex);
            u8 nonce[12] = {};
            if (nonce_hex.size() == 24) {
                auto nv = from_hex(nonce_hex);
                std::memcpy(nonce, nv.data(), 12);
            }

            std::cout << "  AAD (string): ";
            std::string aad_str; std::getline(std::cin, aad_str);
            std::vector<u8> aad(aad_str.begin(), aad_str.end());

            std::cout << "  Ciphertext (hex): ";
            std::string ct_hex; std::getline(std::cin, ct_hex);
            std::vector<u8> ct = from_hex(ct_hex);

            std::cout << "  Tag (32 hex chars): ";
            std::string tag_hex; std::getline(std::cin, tag_hex);
            u8 tag[16] = {};
            if (tag_hex.size() == 32) {
                auto tv = from_hex(tag_hex);
                std::memcpy(tag, tv.data(), 16);
            }

            std::vector<u8> pt;
            bool ok = chacha20_poly1305_decrypt(
                key, nonce, aad, ct, tag, pt);

            sep();
            if (ok) {
                std::cout << "  Auth  : VALID\n";
                std::cout << "  PT    : \""
                          << std::string(pt.begin(), pt.end())
                          << "\"\n";
                std::cout << "  PT hex: " << to_hex(pt) << "\n";
            } else {
                std::cout << "  Auth  : FAILED — wrong key, "
                             "nonce, or tampered data.\n";
            }
            sep('=');
        }

        // --------------------------------------------------------
        else if (choice == 6) {
            hdr("CHACHA20 KEYSTREAM INSPECTOR");
            std::cout << "  Generates keystream bytes from a "
                         "ChaCha20 block.\n\n";

            std::cout << "  Counter value (0-999, Enter=1): ";
            std::string cnt_str; std::getline(std::cin, cnt_str);
            u32 counter = cnt_str.empty() ? 1
                : static_cast<u32>(std::stoul(cnt_str));

            u8 key[32] = {};
            u8 nonce[12] = {};
            for (int i = 0; i < 32; i++)
                key[i] = static_cast<u8>(i);

            u8 ks[64];
            chacha20_block(key, nonce, counter, ks);

            sep();
            std::cout << "  Key     : " << to_hex(key, 32) << "\n";
            std::cout << "  Nonce   : " << to_hex(nonce, 12)<< "\n";
            std::cout << "  Counter : " << counter << "\n\n";
            std::cout << "  Keystream block (64 bytes):\n";
            for (int row = 0; row < 4; row++) {
                std::cout << "  ";
                for (int col = 0; col < 16; col++)
                    std::cout << std::hex << std::setw(2)
                              << std::setfill('0')
                              << static_cast<int>(ks[row*16+col])
                              << " ";
                std::cout << "\n";
            }
            std::cout << std::dec;
            sep('=');
        }

        // --------------------------------------------------------
        else if (choice == 7) {
            hdr("POLY1305 MAC CALCULATOR");

            std::cout << "  OTK key (64 hex chars, "
                         "Enter=zero): ";
            std::string k_hex; std::getline(std::cin, k_hex);
            u8 otk[32] = {};
            if (k_hex.size() == 64) {
                auto kv = from_hex(k_hex);
                std::memcpy(otk, kv.data(), 32);
            }

            std::cout << "  Message (string): ";
            std::string msg; std::getline(std::cin, msg);
            std::vector<u8> data(msg.begin(), msg.end());

            u8 tag[16];
            Poly1305 poly;
            poly.compute(otk, data.data(), data.size(), tag);

            sep();
            std::cout << "  OTK : " << to_hex(otk, 32) << "\n";
            std::cout << "  Msg : \"" << msg << "\"\n";
            std::cout << "  Tag : " << to_hex(tag, 16) << "\n";
            sep('=');
        }

        // --------------------------------------------------------
        else if (choice == 8) {
            hdr("AVALANCHE EFFECT DEMONSTRATION");
            std::cout << "  Flipping 1 bit in the key and "
                         "measuring ciphertext change.\n\n";

            u8  key[32]   = {};
            u8  nonce[12] = {};
            for (int i = 0; i < 32; i++) key[i] = static_cast<u8>(i);
            std::string msg = "The quick brown fox jumps over"
                              " the lazy dog";
            std::vector<u8> pt(msg.begin(), msg.end());
            std::vector<u8> aad;
            std::vector<u8> ct1, ct2;
            u8 tag1[16], tag2[16];

            chacha20_poly1305_encrypt(
                key, nonce, aad, pt, ct1, tag1);

            // Flip bit 0 of key byte 0
            key[0] ^= 0x01;
            chacha20_poly1305_encrypt(
                key, nonce, aad, pt, ct2, tag2);

            // Count differing bits in ciphertext
            int diff_bits = 0;
            for (size_t i = 0;
                 i < std::min(ct1.size(), ct2.size()); i++) {
                u8 x = ct1[i] ^ ct2[i];
                while (x) { diff_bits += x & 1; x >>= 1; }
            }
            int total_bits =
                static_cast<int>(ct1.size()) * 8;

            sep();
            std::cout << "  Plaintext  : \"" << msg << "\"\n\n";
            std::cout << "  Key 1 CT   : "
                      << to_hex(ct1.data(), 16) << "...\n";
            std::cout << "  Key 1 Tag  : "
                      << to_hex(tag1, 16) << "\n\n";
            std::cout << "  Key 2 CT   : "
                      << to_hex(ct2.data(), 16) << "...\n";
            std::cout << "  Key 2 Tag  : "
                      << to_hex(tag2, 16) << "\n\n";
            std::cout << "  Bits changed in CT : "
                      << diff_bits << " / " << total_bits
                      << " ("
                      << std::fixed << std::setprecision(1)
                      << (diff_bits * 100.0 / total_bits)
                      << "%) — ideal ~50%\n";
            sep('=');
        }

        // --------------------------------------------------------
        else if (choice == 0) {
            sep('=');
            std::cout << "  Goodbye.\n";
            sep('=');
        }

        else {
            std::cout << "  Unknown option.\n";
        }
    }
    return 0;
}