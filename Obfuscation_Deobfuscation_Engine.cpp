#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <iomanip>
#include <cstdint>
#include <algorithm>
#include <cctype>

// =======================================================================
// UTILITY: METRICS & HEURISTICS
// =======================================================================

// Calculate Shannon Entropy
double calculate_entropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    size_t counts[256] = {0};
    for (uint8_t byte : data) counts[byte]++;

    double entropy = 0.0;
    for (size_t count : counts) {
        if (count > 0) {
            double p = static_cast<double>(count) / data.size();
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

// Heuristic to check if a byte array is mostly readable ASCII
bool is_readable_ascii(const std::vector<uint8_t>& data) {
    if (data.empty()) return false;
    int printable = 0;
    for (uint8_t b : data) {
        if (std::isprint(b) || b == '\n' || b == '\r' || b == '\t') printable++;
    }
    return (static_cast<double>(printable) / data.size()) > 0.90; // 90% printable threshold
}

// Heuristic to check if data looks like valid Base64
bool is_base64_format(const std::vector<uint8_t>& data) {
    if (data.empty() || data.size() % 4 != 0) return false;
    for (uint8_t b : data) {
        if (!std::isalnum(b) && b != '+' && b != '/' && b != '=') return false;
    }
    return true;
}

// =======================================================================
// OBFUSCATOR LAYERS
// =======================================================================

std::string base64_encode(const std::vector<uint8_t>& data) {
    static const char* b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64_table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(b64_table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::vector<uint8_t> base64_decode(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out;
    std::vector<int> t(256, -1);
    for (int i = 0; i < 64; i++) t["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val = 0, valb = -8;
    for (uint8_t c : data) {
        if (t[c] == -1) break;
        val = (val << 6) + t[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::vector<uint8_t> apply_rot13(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out = data;
    for (uint8_t& b : out) {
        if (std::isalpha(b)) {
            char base = std::islower(b) ? 'a' : 'A';
            b = (b - base + 13) % 26 + base;
        }
    }
    return out;
}

std::vector<uint8_t> rolling_xor(const std::vector<uint8_t>& data, uint8_t initial_key) {
    std::vector<uint8_t> out = data;
    uint8_t key = initial_key;
    for (uint8_t& b : out) {
        b ^= key;
        key = (key + 1) % 256; // Key rolls forward
    }
    return out;
}

// Simulate stack-string reconstruction (malware pushes chars to stack individually)
std::vector<uint8_t> reconstruct_stack_string() {
    std::cout << "[+] Reconstructing simulated stack-string...\n";
    volatile char s[] = {'h', 't', 't', 'p', ':', '/', '/', 'm', 'a', 'l', 'i', 'c', 'i', 'o', 'u', 's', '.', 'c', 'o', 'm', '\0'};
    std::vector<uint8_t> reconstructed;
    for (int i = 0; s[i] != '\0'; ++i) {
        reconstructed.push_back(s[i]);
    }
    return reconstructed;
}

// =======================================================================
// DEOBFUSCATION ENGINE (AUTOMATED LAYER PEELING)
// =======================================================================

void auto_deobfuscate(const std::vector<uint8_t>& payload, uint8_t xor_key_guess) {
    std::cout << "\n========================================================\n";
    std::cout << "               AUTONOMOUS DEOBFUSCATOR                  \n";
    std::cout << "========================================================\n";

    std::vector<uint8_t> current_data = payload;
    int layer = 1;

    // Phase 1: High Entropy Check (Likely XORed or Encrypted)
    double initial_entropy = calculate_entropy(current_data);
    std::cout << "[*] Initial Payload Entropy: " << std::fixed << std::setprecision(2) << initial_entropy << "\n";

    if (initial_entropy > 4.5 || !is_readable_ascii(current_data)) {
        std::cout << "[!] Layer " << layer++ << ": High entropy detected. Attempting Rolling-XOR reversal...\n";
        // In a real scenario, you'd brute force the key (0-255). We use the provided guess.
        current_data = rolling_xor(current_data, xor_key_guess);
        std::cout << "    -> Entropy after XOR peel: " << calculate_entropy(current_data) << "\n";
    }

    // Phase 2: Check for Base64 Signatures
    if (is_base64_format(current_data)) {
        std::cout << "[!] Layer " << layer++ << ": Base64 signature detected. Decoding...\n";
        current_data = base64_decode(current_data);
    }

    // Phase 3: Check for ROT13 (ASCII but nonsensical words)
    // If it's ASCII but still doesn't look like our target, try ROT13
    if (is_readable_ascii(current_data)) {
        std::cout << "[!] Layer " << layer++ << ": Analyzing textual patterns. Attempting ROT13 reversal...\n";
        std::vector<uint8_t> rot_test = apply_rot13(current_data);

        // Simple heuristic: ROT13 of "http" is "uggc".
        std::string test_str(rot_test.begin(), rot_test.end());
        if (test_str.find("http") != std::string::npos || test_str.find(".com") != std::string::npos) {
            std::cout << "    -> Known plaintext signature matched ('http' / '.com').\n";
            current_data = rot_test;
        } else {
             std::cout << "    -> ROT13 applied but no known signatures matched. (Reverting)\n";
        }
    }

    // Output Final Result
    if (is_readable_ascii(current_data)) {
        std::cout << "\n[+] DEOBFUSCATION SUCCESSFUL!\n";
        std::cout << "[+] Recovered Plaintext: " << std::string(current_data.begin(), current_data.end()) << "\n";
    } else {
        std::cout << "\n[-] DEOBFUSCATION FAILED. Payload remains obfuscated.\n";
    }
    std::cout << "========================================================\n";
}

// =======================================================================
// MAIN EXECUTION
// =======================================================================

int main() {
    // 1. Reconstruct baseline data
    std::vector<uint8_t> plaintext = reconstruct_stack_string();
    std::cout << "[*] Original Plaintext: " << std::string(plaintext.begin(), plaintext.end()) << "\n";

    // 2. Obfuscate (Malware Author Side)
    std::cout << "\n--- Applying Layered Obfuscation ---\n";

    std::vector<uint8_t> layer1_rot13 = apply_rot13(plaintext);
    std::string layer2_b64_str = base64_encode(layer1_rot13);
    std::vector<uint8_t> layer2_b64(layer2_b64_str.begin(), layer2_b64_str.end());

    uint8_t xor_key = 0xAA; // Arbitrary starting key
    std::vector<uint8_t> final_payload = rolling_xor(layer2_b64, xor_key);

    std::cout << "[+] Obfuscation Complete.\n";
    std::cout << "    -> Final Payload Size: " << final_payload.size() << " bytes\n";
    std::cout << "    -> Final Entropy: " << std::fixed << std::setprecision(2) << calculate_entropy(final_payload) << " (Obfuscated)\n";

    // 3. Deobfuscate (Analyst Side)
    // The engine automatically detects entropy spikes and signatures to reverse the process.
    auto_deobfuscate(final_payload, xor_key);

    return 0;
}