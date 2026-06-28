#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <functional> // For std::hash

// Represents a single entry in the audit log
struct LogEntry {
    int index;
    std::string data;
    std::string prev_hash;
    std::string current_hash;
};

// A simulated SHA-256 hash function (Production should use OpenSSL's SHA256)
std::string calculate_hash(const std::string& data, const std::string& prev_hash) {
    std::string input = data + prev_hash;
    std::hash<std::string> hasher;
    size_t hash_val = hasher(input);

    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << hash_val;
    return ss.str();
}

class AuditLog {
private:
    std::vector<LogEntry> chain;

public:
    void append(const std::string& data) {
        int index = chain.size();
        std::string prev_hash = chain.empty() ? "0000000000000000" : chain.back().current_hash;
        std::string current_hash = calculate_hash(data, prev_hash);

        chain.push_back({index, data, prev_hash, current_hash});
        std::cout << "[Append] Log entry " << index << " added.\n";
    }

    bool verify_chain() {
        for (size_t i = 0; i < chain.size(); ++i) {
            // Re-calculate hash to see if data matches
            std::string recalculated = calculate_hash(chain[i].data, chain[i].prev_hash);

            // Check current hash integrity
            if (recalculated != chain[i].current_hash) {
                std::cout << "!!! TAMPER ALERT: Data modification detected at entry " << i << " !!!\n";
                return false;
            }

            // Check link to previous hash
            if (i > 0 && chain[i].prev_hash != chain[i-1].current_hash) {
                std::cout << "!!! TAMPER ALERT: Link broken at entry " << i << " !!!\n";
                return false;
            }
        }
        std::cout << "SUCCESS: Chain integrity verified. No tampering detected.\n";
        return true;
    }

    // Function to simulate an attacker modifying data
    void simulate_tamper(int index, const std::string& new_data) {
        if (index >= 0 && index < chain.size()) {
            std::cout << "\n[Attacker] Modifying entry " << index << "...\n";
            chain[index].data = new_data;
        }
    }
};

int main() {
    AuditLog system_log;

    // 1. Build the chain
    system_log.append("User admin logged in");
    system_log.append("User admin accessed /etc/shadow");
    system_log.append("User admin logged out");

    // 2. Verify
    system_log.verify_chain();

    // 3. Tamper with the log
    system_log.simulate_tamper(1, "User admin deleted files");

    // 4. Verify again (should fail)
    system_log.verify_chain();

    return 0;
}