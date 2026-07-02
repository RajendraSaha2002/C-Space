#include <iostream>
#include <vector>
#include <string>
#include <sstream>

// 1. Define the types of fake "syscalls" we are tracking
enum class SyscallType {
    FILE_OPEN,
    REGISTRY_READ,
    NET_CONNECT,
    PROCESS_SPAWN,
    MEM_ALLOC
};

// Helper function to convert enum to string for the JSON output
std::string SyscallToString(SyscallType type) {
    switch(type) {
        case SyscallType::FILE_OPEN: return "FILE_OPEN";
        case SyscallType::REGISTRY_READ: return "REGISTRY_READ";
        case SyscallType::NET_CONNECT: return "NET_CONNECT";
        case SyscallType::PROCESS_SPAWN: return "PROCESS_SPAWN";
        case SyscallType::MEM_ALLOC: return "MEM_ALLOC";
        default: return "UNKNOWN";
    }
}

// 2. Struct for the intercepted Call
struct Syscall {
    SyscallType type;
    std::string target;  // e.g., IP address, file path, registry key
    std::string details; // e.g., Port, Read/Write permissions, memory size
};

// 3. Struct representing our scripted malware sample
struct MalwareSample {
    std::string name;
    std::vector<Syscall> script;
};

// 4. The Sandbox Simulator Class
class SandboxSimulator {
private:
    std::vector<Syscall> trace_log;
    int threat_score;
    std::vector<std::string> detected_patterns;

    // Pattern matching logic to assign threat scores
    void evaluateBehavior(const Syscall& call) {
        if (call.type == SyscallType::PROCESS_SPAWN) {
            if (call.target == "cmd.exe" || call.target == "powershell.exe") {
                threat_score += 20;
                detected_patterns.push_back("Suspicious process spawn: Command shell execution");
            }
        }
        else if (call.type == SyscallType::NET_CONNECT) {
            if (call.details == "Port: 4444" || call.details == "Port: 1337") {
                threat_score += 40;
                detected_patterns.push_back("Malicious network: Connected to known C2/Reverse Shell port");
            }
        }
        else if (call.type == SyscallType::REGISTRY_READ) {
            if (call.target.find("CurrentVersion\\Run") != std::string::npos) {
                threat_score += 30;
                detected_patterns.push_back("Persistence mechanism: Auto-start registry key accessed");
            }
        }
        else if (call.type == SyscallType::MEM_ALLOC) {
            if (call.details.find("RWX") != std::string::npos) {
                threat_score += 35;
                detected_patterns.push_back("Memory anomaly: Allocated Read-Write-Execute (RWX) memory");
            }
        }
        else if (call.type == SyscallType::FILE_OPEN) {
            if (call.target.find("vssadmin.exe") != std::string::npos) {
                threat_score += 50;
                detected_patterns.push_back("Ransomware behavior: Attempted interaction with Volume Shadow Copies");
            }
        }
    }

public:
    SandboxSimulator() : threat_score(0) {}

    // Executes the fake malware sample
    void runSample(const MalwareSample& sample) {
        trace_log.clear();
        threat_score = 0;
        detected_patterns.clear();

        for (const auto& call : sample.script) {
            trace_log.push_back(call); // Log the fake syscall
            evaluateBehavior(call);    // Analyze the behavior
        }
    }

    // Generates the JSON-style behavioral report
    std::string generateJSONReport(const std::string& sample_name) {
        std::ostringstream json;
        json << "{\n";
        json << "  \"sample_name\": \"" << sample_name << "\",\n";
        json << "  \"threat_score\": " << threat_score << ",\n";

        std::string classification = (threat_score >= 60) ? "MALICIOUS" : (threat_score >= 20) ? "SUSPICIOUS" : "SAFE";
        json << "  \"classification\": \"" << classification << "\",\n";

        // Output triggered behavioral patterns
        json << "  \"detected_patterns\": [\n";
        for (size_t i = 0; i < detected_patterns.size(); ++i) {
            json << "    \"" << detected_patterns[i] << "\"";
            if (i < detected_patterns.size() - 1) json << ",";
            json << "\n";
        }
        json << "  ],\n";

        // Output the raw syscall trace log
        json << "  \"syscall_trace\": [\n";
        for (size_t i = 0; i < trace_log.size(); ++i) {
            json << "    {\n";
            json << "      \"type\": \"" << SyscallToString(trace_log[i].type) << "\",\n";
            json << "      \"target\": \"" << trace_log[i].target << "\",\n";
            json << "      \"details\": \"" << trace_log[i].details << "\"\n";
            json << "    }";
            if (i < trace_log.size() - 1) json << ",";
            json << "\n";
        }
        json << "  ]\n";
        json << "}\n";

        return json.str();
    }
};

int main() {
    // ---------------------------------------------------------
    // TEST CASE 1: Malicious Sample (Simulated Ransomware/Dropper)
    // ---------------------------------------------------------
    MalwareSample badSample = {
        "WannaCry_Simulated.exe",
        {
            {SyscallType::FILE_OPEN, "C:\\Windows\\System32\\vssadmin.exe", "Access: Delete Shadows"},
            {SyscallType::MEM_ALLOC, "0x00A40000", "Permissions: RWX, Size: 1024 bytes"},
            {SyscallType::NET_CONNECT, "185.11.22.33", "Port: 4444"},
            {SyscallType::REGISTRY_READ, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Query: PersistenceKey"},
            {SyscallType::PROCESS_SPAWN, "cmd.exe", "Args: /c del C:\\temp\\payload.exe"}
        }
    };

    // ---------------------------------------------------------
    // TEST CASE 2: Safe Sample (Standard benign application)
    // ---------------------------------------------------------
    MalwareSample safeSample = {
        "Notepad_Updater.exe",
        {
            {SyscallType::FILE_OPEN, "C:\\Program Files\\Notepad\\config.ini", "Access: Read-Only"},
            {SyscallType::MEM_ALLOC, "0x00B20000", "Permissions: RW, Size: 512 bytes"},
            {SyscallType::NET_CONNECT, "api.software-update.com", "Port: 443"}
        }
    };

    // Initialize the sandbox
    SandboxSimulator sandbox;

    // Run and report Test Case 1
    std::cout << "=== ANALYZING SAMPLE 1 ===\n";
    sandbox.runSample(badSample);
    std::cout << sandbox.generateJSONReport(badSample.name) << "\n\n";

    // Run and report Test Case 2
    std::cout << "=== ANALYZING SAMPLE 2 ===\n";
    sandbox.runSample(safeSample);
    std::cout << sandbox.generateJSONReport(safeSample.name) << "\n";

    return 0;
}