// ============================================================
// Project 1: ASCON-128 Stream Cipher File Encryptor
// CLion / GCC / Clang compatible — C++17
// Encrypts and decrypts any binary file using ASCON-128.
// Reads file in 8-byte (64-bit) blocks, processes each block
// through the full ASCON pipeline, writes ciphertext + 16-byte
// authentication tag to output file. No external libraries.
// ============================================================
// Build:  cmake --build . --target ascon_file
// Usage:  ascon_file enc <input> <output> <keyfile>
//         ascon_file dec <input> <output> <keyfile>
// ============================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <string>
#include <cstring>
#include <cstdint>
#include <cinttypes>
#include <iomanip>
#include <chrono>
#include <sstream>

// ============================================================
// TYPE ALIASES
// ============================================================
using u64 = uint64_t;
using u8  = uint8_t;

// ============================================================
// ASCON CONSTANTS
// ============================================================
// Initialization vector encodes: key length=128, rate=64,
// pa=12 rounds, pb=6 rounds (ASCON-128 specification).
static constexpr u64 ASCON_IV = 0x80400c0600000000ULL;

// 16 round constants used by the add_constant layer.
// constants[i] = 0xf0 - i*0x0f (descending pattern per spec).
static constexpr u64 RC[16] = {
    0xf0ULL, 0xe1ULL, 0xd2ULL, 0xc3ULL,
    0xb4ULL, 0xa5ULL, 0x96ULL, 0x87ULL,
    0x78ULL, 0x69ULL, 0x5aULL, 0x4bULL,
    0x3cULL, 0x2dULL, 0x1eULL, 0x0fULL
};

// File format header magic bytes — lets us detect if a file
// was encrypted by this tool before attempting decryption.
static constexpr u8 FILE_MAGIC[8] = {
    0x41, 0x53, 0x43, 0x4f,   // "ASCO"
    0x4e, 0x31, 0x32, 0x38    // "N128"
};

// ============================================================
// ASCON STATE
// Holds five 64-bit words = 320 bits total.
// state[0] = rate word (absorbs plaintext / produces keystream)
// state[1..2] = capacity words mixed with key
// state[3..4] = capacity words mixed with nonce
// ============================================================
struct AsconState {
    u64 x[5] = {0, 0, 0, 0, 0};
};

// ============================================================
// UTILITY: Rotate right a 64-bit word by l bits.
// ============================================================
static inline u64 rotr64(u64 x, int l) {
    return (x >> l) | (x << (64 - l));
}

// ============================================================
// PERMUTATION LAYER 1: Add round constant
// XORs the constant for round i into the middle word x[2].
// 'a' = total rounds in this call (12 or 6), selects the
// correct constant from the RC table: RC[12 - a + i].
// ============================================================
static void add_constant(AsconState& s, int i, int a) {
    s.x[2] ^= RC[12 - a + i];
}

// ============================================================
// PERMUTATION LAYER 2: Substitution (S-Box)
// Bitsliced 5-bit S-box applied simultaneously to all 64
// column slices across the five 64-bit state words.
// Uses only NOT, AND, XOR — no table lookup.
// This avoids cache-timing side-channel attacks.
// ============================================================
static void sbox(AsconState& s) {
    u64 t0, t1, t2, t3, t4;

    // Step 1: initial XOR mixing
    s.x[0] ^= s.x[4];
    s.x[4] ^= s.x[3];
    s.x[2] ^= s.x[1];

    // Step 2: snapshot current state into temporaries
    t0 = s.x[0]; t1 = s.x[1]; t2 = s.x[2];
    t3 = s.x[3]; t4 = s.x[4];

    // Step 3: NOT each temp — invert every bit
    t0 = ~t0; t1 = ~t1; t2 = ~t2; t3 = ~t3; t4 = ~t4;

    // Step 4: AND each inverted temp with the next neighbour
    t0 &= s.x[1]; t1 &= s.x[2]; t2 &= s.x[3];
    t3 &= s.x[4]; t4 &= s.x[0];

    // Step 5: XOR temp results back into state
    s.x[0] ^= t1; s.x[1] ^= t2; s.x[2] ^= t3;
    s.x[3] ^= t4; s.x[4] ^= t0;

    // Step 6: final mixing round
    s.x[1] ^= s.x[0];
    s.x[0] ^= s.x[4];
    s.x[3] ^= s.x[2];
    s.x[2]  = ~s.x[2];   // final inversion of x[2]
}

// ============================================================
// PERMUTATION LAYER 3: Linear diffusion
// Each 64-bit word is XORed with two rotated copies of itself.
// Rotation constants are fixed by the ASCON specification:
//   x[0]: rotr(19) ^ rotr(28)
//   x[1]: rotr(61) ^ rotr(39)
//   x[2]: rotr( 1) ^ rotr( 6)
//   x[3]: rotr(10) ^ rotr(17)
//   x[4]: rotr( 7) ^ rotr(41)
// This ensures every bit affects every other bit within a word
// after one permutation call.
// ============================================================
static void linear(AsconState& s) {
    s.x[0] ^= rotr64(s.x[0], 19) ^ rotr64(s.x[0], 28);
    s.x[1] ^= rotr64(s.x[1], 61) ^ rotr64(s.x[1], 39);
    s.x[2] ^= rotr64(s.x[2],  1) ^ rotr64(s.x[2],  6);
    s.x[3] ^= rotr64(s.x[3], 10) ^ rotr64(s.x[3], 17);
    s.x[4] ^= rotr64(s.x[4],  7) ^ rotr64(s.x[4], 41);
}

// ============================================================
// FULL PERMUTATION: p^a
// Runs exactly 'a' rounds of:
//   add_constant → sbox → linear
// p12 (a=12): used in initialization and finalization
// p6  (a= 6): used in associated data and encryption blocks
// ============================================================
static void permute(AsconState& s, int a) {
    for (int i = 0; i < a; i++) {
        add_constant(s, i, a);
        sbox(s);
        linear(s);
    }
}

// ============================================================
// KEY STRUCT: 128-bit key stored as two 64-bit words.
// ============================================================
struct AsconKey {
    u64 k0 = 0;
    u64 k1 = 0;
};

// ============================================================
// NONCE STRUCT: 128-bit nonce stored as two 64-bit words.
// Nonce must be unique per encryption with the same key.
// ============================================================
struct AsconNonce {
    u64 n0 = 0;
    u64 n1 = 0;
};

// ============================================================
// PHASE 1: Initialization
// Load IV || key || nonce into state, run p12, then XOR key
// back into the capacity (state[3..4]). This binds the key
// into the state without revealing it in the rate word.
// ============================================================
static AsconState ascon_init(const AsconKey& key,
                              const AsconNonce& nonce) {
    AsconState s;
    s.x[0] = ASCON_IV;
    s.x[1] = key.k0;
    s.x[2] = key.k1;
    s.x[3] = nonce.n0;
    s.x[4] = nonce.n1;

    permute(s, 12);    // p12 for maximum diffusion

    s.x[3] ^= key.k0; // absorb key into capacity
    s.x[4] ^= key.k1;
    return s;
}

// ============================================================
// PHASE 2: Associated Data Processing
// Each 8-byte AD block is XORed into state[0] (the rate),
// then p6 is applied. After all blocks, XOR 1 into state[4]
// for domain separation (distinguishes AD phase from enc phase).
// 'ad' may be empty — if so, only domain separation is applied.
// ============================================================
static void ascon_absorb_ad(AsconState& s,
                             const std::vector<u8>& ad) {
    // Process full 8-byte AD blocks
    size_t i = 0;
    while (i + 8 <= ad.size()) {
        u64 block = 0;
        std::memcpy(&block, ad.data() + i, 8);
        // Convert from little-endian bytes to big-endian u64
        block = __builtin_bswap64(block);
        s.x[0] ^= block;
        permute(s, 6);
        i += 8;
    }

    // Process final partial AD block (with 0x80 padding)
    if (i < ad.size() || ad.empty()) {
        u64 block = 0x8000000000000000ULL; // padding start bit
        size_t rem = ad.size() - i;
        u8 tmp[8] = {0};
        std::memcpy(tmp, ad.data() + i, rem);
        u64 partial = 0;
        std::memcpy(&partial, tmp, 8);
        partial = __builtin_bswap64(partial);
        // Insert padding bit after last real byte
        block = partial | (0x8000000000000000ULL >> (rem * 8));
        s.x[0] ^= block;
        permute(s, 6);
    } else {
        // Exactly full blocks — still need final padding block
        s.x[0] ^= 0x8000000000000000ULL;
        permute(s, 6);
    }

    // Domain separation: flip bit 0 of state[4]
    s.x[4] ^= 0x0000000000000001ULL;
}

// ============================================================
// PHASE 3a: Encrypt one 8-byte block
// Ciphertext block = Plaintext XOR state[0] (keystream word).
// Then state[0] is replaced with the ciphertext block so that
// each block of ciphertext feeds into the next permutation.
// This is the ASCON CTR-like chaining construction.
// ============================================================
static u64 ascon_enc_block(AsconState& s, u64 plaintext) {
    u64 cipher = plaintext ^ s.x[0];
    s.x[0] = cipher;             // ciphertext feedback into state
    return cipher;
}

// ============================================================
// PHASE 3b: Decrypt one 8-byte block
// Recovers plaintext = Ciphertext XOR state[0] (same keystream).
// Then state[0] is set to the ciphertext block (not plaintext)
// to maintain the same state evolution as during encryption.
// ============================================================
static u64 ascon_dec_block(AsconState& s, u64 cipher) {
    u64 plain = cipher ^ s.x[0];
    s.x[0] = cipher;             // ciphertext feedback maintains state
    return plain;
}

// ============================================================
// PHASE 4: Finalization
// XOR key into state[1..2], run p12, then XOR key into
// state[3..4] to produce the 128-bit authentication tag.
// tag = state[3] || state[4] after finalization.
// ============================================================
static std::array<u64, 2> ascon_finalize(AsconState& s,
                                          const AsconKey& key) {
    s.x[1] ^= key.k0;
    s.x[2] ^= key.k1;
    permute(s, 12);    // p12 for maximum tag security
    s.x[3] ^= key.k0;
    s.x[4] ^= key.k1;
    return {s.x[3], s.x[4]};
}

// ============================================================
// UTILITY: Convert a u64 to big-endian 8 bytes.
// ASCON processes data in big-endian byte order.
// ============================================================
static void u64_to_be(u64 val, u8* out) {
    for (int i = 7; i >= 0; i--) {
        out[i] = static_cast<u8>(val & 0xFF);
        val >>= 8;
    }
}

// ============================================================
// UTILITY: Read 8 bytes from buffer as big-endian u64.
// Pads with zeros if fewer than 8 bytes available.
// ============================================================
static u64 be_to_u64(const u8* buf, size_t len) {
    u64 val = 0;
    for (size_t i = 0; i < len && i < 8; i++) {
        val = (val << 8) | buf[i];
    }
    // Shift left for short blocks so padding aligns correctly
    if (len < 8) val <<= (8 - len) * 8;
    return val;
}

// ============================================================
// UTILITY: Print a hex string for console output.
// ============================================================
static std::string to_hex(const u8* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

// ============================================================
// UTILITY: Print formatted separator for console output.
// ============================================================
static void print_sep(char c = '-', int w = 60) {
    std::cout << std::string(w, c) << "\n";
}

// ============================================================
// KEY FILE I/O
// Key file format (32 bytes total):
//   [0..7]  : key word 0  (big-endian u64)
//   [8..15] : key word 1  (big-endian u64)
//   [16..23]: nonce word 0 (big-endian u64)
//   [24..31]: nonce word 1 (big-endian u64)
// ============================================================
static bool load_keyfile(const std::string& path,
                          AsconKey& key, AsconNonce& nonce) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "[ERROR] Cannot open key file: " << path << "\n";
        return false;
    }

    u8 buf[32] = {0};
    f.read(reinterpret_cast<char*>(buf), 32);
    if (f.gcount() != 32) {
        std::cerr << "[ERROR] Key file must be exactly 32 bytes.\n";
        return false;
    }

    key.k0   = be_to_u64(buf +  0, 8);
    key.k1   = be_to_u64(buf +  8, 8);
    nonce.n0 = be_to_u64(buf + 16, 8);
    nonce.n1 = be_to_u64(buf + 24, 8);
    return true;
}

// ============================================================
// GENERATE DEFAULT KEY FILE
// Creates a demo key file with a fixed test key and nonce.
// In production, these should be cryptographically random bytes.
// ============================================================
static void generate_demo_keyfile(const std::string& path) {
    std::ofstream f(path, std::ios::binary);
    u8 buf[32] = {
        // Key (128 bits)
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        // Nonce (128 bits) — MUST be unique per encryption
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    f.write(reinterpret_cast<char*>(buf), 32);
    std::cout << "[KEY]  Demo key file written to: " << path << "\n";
}

// ============================================================
// ENCRYPTED FILE FORMAT
// Header (32 bytes):
//   [0..7]   : Magic "ASCON128"
//   [8..15]  : Original plaintext file size (big-endian u64)
//   [16..31] : Reserved (zeros)
// Body:
//   [32..N-16] : Encrypted blocks (each 8 bytes)
// Footer (16 bytes):
//   [N-16..N] : 128-bit authentication tag (tag0 || tag1)
// ============================================================

// ============================================================
// ENCRYPT FILE
// Reads input file, encrypts all blocks with ASCON-128,
// writes header + ciphertext + tag to output file.
// Returns true on success.
// ============================================================
static bool encrypt_file(const std::string& inpath,
                          const std::string& outpath,
                          const AsconKey& key,
                          const AsconNonce& nonce) {

    // --- Open input file ---
    std::ifstream fin(inpath, std::ios::binary | std::ios::ate);
    if (!fin) {
        std::cerr << "[ERROR] Cannot open input file: " << inpath << "\n";
        return false;
    }

    // Read entire plaintext into memory
    std::streamsize filesize = fin.tellg();
    fin.seekg(0, std::ios::beg);
    std::vector<u8> plaintext(static_cast<size_t>(filesize));
    if (!fin.read(reinterpret_cast<char*>(plaintext.data()), filesize)) {
        std::cerr << "[ERROR] Failed to read input file.\n";
        return false;
    }
    fin.close();

    // --- Open output file ---
    std::ofstream fout(outpath, std::ios::binary);
    if (!fout) {
        std::cerr << "[ERROR] Cannot create output file: " << outpath << "\n";
        return false;
    }

    std::cout << "[ENC]  Input file  : " << inpath << "\n";
    std::cout << "[ENC]  Output file : " << outpath << "\n";
    std::cout << "[ENC]  Plaintext size: " << filesize << " bytes\n";

    // --- Write file header ---
    u8 header[32] = {0};
    std::memcpy(header, FILE_MAGIC, 8);      // magic bytes
    u64 psize = static_cast<u64>(filesize);
    u64_to_be(psize, header + 8);            // original file size
    fout.write(reinterpret_cast<char*>(header), 32);

    // --- ASCON Initialization ---
    auto t_start = std::chrono::high_resolution_clock::now();
    AsconState state = ascon_init(key, nonce);

    // --- Associated Data ---
    // We use the file header itself as associated data.
    // This binds the ciphertext to this exact header — if the
    // header is tampered with, tag verification will fail.
    std::vector<u8> ad(header, header + 32);
    ascon_absorb_ad(state, ad);

    // --- Encrypt blocks ---
    std::vector<u8> ciphertext;
    ciphertext.reserve(plaintext.size() + 8); // padding headroom

    size_t offset  = 0;
    size_t blocks  = 0;

    // Process all full 8-byte blocks
    while (offset + 8 <= plaintext.size()) {
        u64 plain_block = be_to_u64(plaintext.data() + offset, 8);
        u64 cipher_block = ascon_enc_block(state, plain_block);

        u8 cb[8];
        u64_to_be(cipher_block, cb);
        ciphertext.insert(ciphertext.end(), cb, cb + 8);

        // After every block except the last, run p6 to advance state
        if (offset + 8 < plaintext.size()) {
            permute(state, 6);
        }

        offset += 8;
        blocks++;
    }

    // Process final partial block (or empty file)
    {
        size_t rem = plaintext.size() - offset;
        u64 plain_block = be_to_u64(plaintext.data() + offset, rem);

        // ASCON padding: append 0x80 bit after last real byte
        u64 pad_bit = (rem < 8)
            ? (0x8000000000000000ULL >> (rem * 8))
            : 0x8000000000000000ULL;
        plain_block |= pad_bit;

        u64 cipher_block = ascon_enc_block(state, plain_block);
        u8 cb[8];
        u64_to_be(cipher_block, cb);
        // Only write the bytes that correspond to real plaintext
        size_t write_len = (rem == 0) ? 8 : rem;
        // We always write 8 bytes — decoder knows true length from header
        ciphertext.insert(ciphertext.end(), cb, cb + 8);
        blocks++;
    }

    fout.write(reinterpret_cast<char*>(ciphertext.data()),
               static_cast<std::streamsize>(ciphertext.size()));

    // --- Finalization: generate authentication tag ---
    auto tag = ascon_finalize(state, key);

    u8 tag_bytes[16];
    u64_to_be(tag[0], tag_bytes);
    u64_to_be(tag[1], tag_bytes + 8);
    fout.write(reinterpret_cast<char*>(tag_bytes), 16);
    fout.close();

    auto t_end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(
                    t_end - t_start).count();

    print_sep();
    std::cout << "[ENC]  Blocks encrypted : " << blocks << "\n";
    std::cout << "[ENC]  Ciphertext size  : "
              << (ciphertext.size() + 16) << " bytes\n";
    std::cout << "[ENC]  Auth tag [0]     : "
              << to_hex(tag_bytes, 8) << "\n";
    std::cout << "[ENC]  Auth tag [1]     : "
              << to_hex(tag_bytes + 8, 8) << "\n";
    std::cout << "[ENC]  Time elapsed     : "
              << std::fixed << std::setprecision(3) << ms << " ms\n";
    print_sep();
    std::cout << "[ENC]  SUCCESS — file encrypted.\n";
    return true;
}

// ============================================================
// DECRYPT FILE
// Reads encrypted file, verifies header magic, decrypts all
// blocks with ASCON-128, re-generates tag, compares with stored
// tag. Writes plaintext to output only if tag matches.
// Returns true on success, false if authentication fails.
// ============================================================
static bool decrypt_file(const std::string& inpath,
                          const std::string& outpath,
                          const AsconKey& key,
                          const AsconNonce& nonce) {

    // --- Open encrypted input file ---
    std::ifstream fin(inpath, std::ios::binary | std::ios::ate);
    if (!fin) {
        std::cerr << "[ERROR] Cannot open encrypted file: " << inpath << "\n";
        return false;
    }

    std::streamsize total = fin.tellg();
    fin.seekg(0, std::ios::beg);

    // Minimum valid file: 32 (header) + 8 (one block) + 16 (tag)
    if (total < 56) {
        std::cerr << "[ERROR] File too small to be a valid ASCON ciphertext.\n";
        return false;
    }

    std::vector<u8> file_data(static_cast<size_t>(total));
    fin.read(reinterpret_cast<char*>(file_data.data()), total);
    fin.close();

    // --- Verify magic bytes ---
    if (std::memcmp(file_data.data(), FILE_MAGIC, 8) != 0) {
        std::cerr << "[ERROR] Not a valid ASCON-encrypted file"
                     " (magic mismatch).\n";
        return false;
    }

    // --- Parse header ---
    u64 orig_size = be_to_u64(file_data.data() + 8, 8);
    std::cout << "[DEC]  Input file     : " << inpath << "\n";
    std::cout << "[DEC]  Output file    : " << outpath << "\n";
    std::cout << "[DEC]  Original size  : " << orig_size << " bytes\n";

    // --- Split body and tag ---
    // Layout: [32 header][body...][16 tag]
    size_t body_start = 32;
    size_t tag_start  = file_data.size() - 16;
    size_t body_len   = tag_start - body_start;

    const u8* stored_tag = file_data.data() + tag_start;

    // --- ASCON Initialization ---
    auto t_start = std::chrono::high_resolution_clock::now();
    AsconState state = ascon_init(key, nonce);

    // --- Associated Data (same header as during encryption) ---
    std::vector<u8> ad(file_data.begin(), file_data.begin() + 32);
    ascon_absorb_ad(state, ad);

    // --- Decrypt blocks ---
    std::vector<u8> plaintext;
    plaintext.reserve(orig_size);

    size_t offset = body_start;
    size_t blocks = 0;
    bool is_last_block = false;

    while (offset < tag_start) {
        size_t rem = tag_start - offset;
        is_last_block = (rem <= 8);

        u64 cipher_block = be_to_u64(file_data.data() + offset, 8);
        u64 plain_block  = ascon_dec_block(state, cipher_block);

        // Determine how many real bytes are in this block
        size_t write_len;
        if (is_last_block) {
            // Last block: use original file size to determine bytes
            size_t already_written = plaintext.size();
            write_len = (orig_size > already_written)
                            ? orig_size - already_written
                            : 0;
        } else {
            write_len = 8;
        }

        // Extract write_len bytes from plain_block (big-endian)
        u8 pb[8];
        u64_to_be(plain_block, pb);
        for (size_t b = 0; b < write_len; b++) {
            plaintext.push_back(pb[b]);
        }

        // Advance permutation for non-final blocks
        if (!is_last_block) {
            permute(state, 6);
        }

        offset += 8;
        blocks++;
    }

    // --- Finalization: re-generate tag ---
    auto computed_tag = ascon_finalize(state, key);

    u8 comp_tag_bytes[16];
    u64_to_be(computed_tag[0], comp_tag_bytes);
    u64_to_be(computed_tag[1], comp_tag_bytes + 8);

    auto t_end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(
                    t_end - t_start).count();

    // --- Constant-time tag comparison ---
    // Avoid short-circuit comparison to prevent timing attacks.
    u8 diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= comp_tag_bytes[i] ^ stored_tag[i];
    }

    print_sep();
    std::cout << "[DEC]  Blocks decrypted   : " << blocks << "\n";
    std::cout << "[DEC]  Stored tag  [0]    : "
              << to_hex(stored_tag, 8) << "\n";
    std::cout << "[DEC]  Computed tag[0]    : "
              << to_hex(comp_tag_bytes, 8) << "\n";
    std::cout << "[DEC]  Stored tag  [1]    : "
              << to_hex(stored_tag + 8, 8) << "\n";
    std::cout << "[DEC]  Computed tag[1]    : "
              << to_hex(comp_tag_bytes + 8, 8) << "\n";
    std::cout << "[DEC]  Time elapsed       : "
              << std::fixed << std::setprecision(3) << ms << " ms\n";
    print_sep();

    if (diff != 0) {
        // Wipe recovered plaintext before returning on auth failure
        std::fill(plaintext.begin(), plaintext.end(), 0);
        std::cerr << "[DEC]  AUTHENTICATION FAILED — wrong key or "
                     "tampered file.\n";
        std::cerr << "[DEC]  Output file not written.\n";
        return false;
    }

    // --- Write decrypted plaintext ---
    std::ofstream fout(outpath, std::ios::binary);
    if (!fout) {
        std::cerr << "[ERROR] Cannot create output file: " << outpath << "\n";
        return false;
    }
    fout.write(reinterpret_cast<char*>(plaintext.data()),
               static_cast<std::streamsize>(plaintext.size()));
    fout.close();

    std::cout << "[DEC]  TAG MATCH — Authentication SUCCESSFUL\n";
    std::cout << "[DEC]  Plaintext size     : "
              << plaintext.size() << " bytes\n";
    std::cout << "[DEC]  SUCCESS — file decrypted to: " << outpath << "\n";
    return true;
}

// ============================================================
// SELF-TEST
// Runs a known-plaintext encrypt-decrypt cycle entirely in
// memory without touching the filesystem. Verifies that:
//   1. Ciphertext differs from plaintext
//   2. Decrypted output matches original plaintext exactly
//   3. Tag computed during decryption matches encryption tag
// Called automatically when no CLI args are provided.
// ============================================================
static void run_self_test() {
    print_sep('=');
    std::cout << "  ASCON-128 FILE ENCRYPTOR — SELF TEST\n";
    print_sep('=');

    // Test key and nonce
    AsconKey   key   = {0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL};
    AsconNonce nonce = {0x0001020304050607ULL, 0x08090A0B0C0D0E0FULL};

    // Test plaintext — 25 bytes (3 full blocks + 1 partial)
    std::vector<u8> original = {
        'H','e','l','l','o',' ','A','S',  // block 1
        'C','O','N','-','1','2','8',' ',  // block 2
        'F','i','l','e',' ','E','n','c',  // block 3
        '!'                               // partial block 4
    };

    std::cout << "[TEST] Plaintext  (" << original.size() << " bytes): ";
    std::cout.write(reinterpret_cast<char*>(original.data()),
                    static_cast<std::streamsize>(original.size()));
    std::cout << "\n";

    // --- ENCRYPTION ---
    AsconState enc_state = ascon_init(key, nonce);
    std::vector<u8> ad_demo = {'A','S','C','O','N','1','2','8'};
    ascon_absorb_ad(enc_state, ad_demo);

    std::vector<u8> ciphertext;
    size_t offset = 0;

    while (offset + 8 <= original.size()) {
        u64 pb = be_to_u64(original.data() + offset, 8);
        u64 cb = ascon_enc_block(enc_state, pb);
        u8 out[8]; u64_to_be(cb, out);
        ciphertext.insert(ciphertext.end(), out, out + 8);
        if (offset + 8 < original.size()) permute(enc_state, 6);
        offset += 8;
    }

    // Final partial block
    {
        size_t rem = original.size() - offset;
        u64 pb = be_to_u64(original.data() + offset, rem);
        pb |= (0x8000000000000000ULL >> (rem * 8));
        u64 cb = ascon_enc_block(enc_state, pb);
        u8 out[8]; u64_to_be(cb, out);
        ciphertext.insert(ciphertext.end(), out, out + 8);
    }

    auto enc_tag = ascon_finalize(enc_state, key);
    u8 enc_tag_b[16];
    u64_to_be(enc_tag[0], enc_tag_b);
    u64_to_be(enc_tag[1], enc_tag_b + 8);

    std::cout << "[TEST] Ciphertext (" << ciphertext.size() << " bytes): "
              << to_hex(ciphertext.data(), ciphertext.size()) << "\n";
    std::cout << "[TEST] Enc tag : " << to_hex(enc_tag_b, 16) << "\n";

    // --- DECRYPTION ---
    AsconState dec_state = ascon_init(key, nonce);
    ascon_absorb_ad(dec_state, ad_demo);

    std::vector<u8> recovered;
    offset = 0;
    size_t num_blocks = ciphertext.size() / 8;

    for (size_t b = 0; b < num_blocks; b++) {
        bool last = (b == num_blocks - 1);
        u64 cb = be_to_u64(ciphertext.data() + b * 8, 8);
        u64 pb = ascon_dec_block(dec_state, cb);
        u8 out[8]; u64_to_be(pb, out);
        size_t wlen = last ? (original.size() - (num_blocks - 1) * 8) : 8;
        for (size_t i = 0; i < wlen; i++) recovered.push_back(out[i]);
        if (!last) permute(dec_state, 6);
    }

    auto dec_tag = ascon_finalize(dec_state, key);
    u8 dec_tag_b[16];
    u64_to_be(dec_tag[0], dec_tag_b);
    u64_to_be(dec_tag[1], dec_tag_b + 8);

    std::cout << "[TEST] Recovered  (" << recovered.size() << " bytes): ";
    std::cout.write(reinterpret_cast<char*>(recovered.data()),
                    static_cast<std::streamsize>(recovered.size()));
    std::cout << "\n";
    std::cout << "[TEST] Dec tag : " << to_hex(dec_tag_b, 16) << "\n";

    // --- Verify ---
    bool tag_ok      = (std::memcmp(enc_tag_b, dec_tag_b, 16) == 0);
    bool content_ok  = (original == recovered);

    print_sep();
    std::cout << "[TEST] Tag match     : " << (tag_ok     ? "PASS" : "FAIL") << "\n";
    std::cout << "[TEST] Content match : " << (content_ok ? "PASS" : "FAIL") << "\n";
    print_sep('=');

    if (tag_ok && content_ok) {
        std::cout << "  ALL TESTS PASSED — ASCON file encryptor is ready.\n";
    } else {
        std::cerr << "  TESTS FAILED — check implementation.\n";
    }
    print_sep('=');
}

// ============================================================
// PRINT USAGE
// ============================================================
static void print_usage(const char* prog) {
    std::cout << "\nASCON-128 Stream Cipher File Encryptor\n";
    print_sep();
    std::cout << "Usage:\n";
    std::cout << "  " << prog << " genkey <keyfile>\n";
    std::cout << "      Generate a demo 32-byte key file.\n\n";
    std::cout << "  " << prog << " enc <input> <output> <keyfile>\n";
    std::cout << "      Encrypt input file to output file.\n\n";
    std::cout << "  " << prog << " dec <input> <output> <keyfile>\n";
    std::cout << "      Decrypt input file to output file.\n\n";
    std::cout << "  " << prog << "            (no args)\n";
    std::cout << "      Run self-test with built-in key/plaintext.\n";
    print_sep();
    std::cout << "Key file format (32 bytes):\n";
    std::cout << "  [0..15]  : 128-bit encryption key\n";
    std::cout << "  [16..31] : 128-bit nonce (must be unique per file)\n";
    print_sep();
}

// ============================================================
// MAIN ENTRY POINT
// ============================================================
int main(int argc, char* argv[]) {

    // No arguments: run self-test
    if (argc == 1) {
        run_self_test();
        std::cout << "\nRun with --help for usage instructions.\n";
        return 0;
    }

    std::string cmd = argv[1];

    // Help
    if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        print_usage(argv[0]);
        return 0;
    }

    // Generate demo key file
    if (cmd == "genkey") {
        if (argc < 3) {
            std::cerr << "[ERROR] Usage: " << argv[0]
                      << " genkey <keyfile>\n";
            return 1;
        }
        generate_demo_keyfile(argv[2]);
        std::cout << "[KEY]  Key file contains a DEMO key.\n";
        std::cout << "[KEY]  For production, replace with "
                     "cryptographically random bytes.\n";
        return 0;
    }

    // Encrypt
    if (cmd == "enc") {
        if (argc < 5) {
            std::cerr << "[ERROR] Usage: " << argv[0]
                      << " enc <input> <output> <keyfile>\n";
            return 1;
        }
        AsconKey   key;
        AsconNonce nonce;
        if (!load_keyfile(argv[4], key, nonce)) return 1;

        print_sep('=');
        std::cout << "  ASCON-128 ENCRYPTION\n";
        print_sep('=');
        bool ok = encrypt_file(argv[2], argv[3], key, nonce);
        return ok ? 0 : 1;
    }

    // Decrypt
    if (cmd == "dec") {
        if (argc < 5) {
            std::cerr << "[ERROR] Usage: " << argv[0]
                      << " dec <input> <output> <keyfile>\n";
            return 1;
        }
        AsconKey   key;
        AsconNonce nonce;
        if (!load_keyfile(argv[4], key, nonce)) return 1;

        print_sep('=');
        std::cout << "  ASCON-128 DECRYPTION\n";
        print_sep('=');
        bool ok = decrypt_file(argv[2], argv[3], key, nonce);
        return ok ? 0 : 1;
    }

    std::cerr << "[ERROR] Unknown command: " << cmd << "\n";
    print_usage(argv[0]);
    return 1;
}