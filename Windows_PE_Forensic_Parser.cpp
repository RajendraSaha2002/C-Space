#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cmath>
#include <iomanip>
#include <cstring>
#include <string>
#include <ctime>

// Ensure raw binary compatibility across compilers via strict 1-byte structural alignment
#pragma pack(push, 1)

struct DOSHeader {
    uint16_t e_magic;    // Magic number ("MZ")
    uint16_t e_cblp;     // Bytes on last page of file
    uint16_t e_cp;       // Pages in file
    uint16_t e_crlc;     // Relocations
    uint16_t e_cparhdr;  // Size of header in paragraphs
    uint16_t e_minalloc; // Minimum extra paragraphs needed
    uint16_t e_maxalloc; // Maximum extra paragraphs needed
    uint16_t e_ss;       // Initial (relative) SS value
    uint16_t e_sp;       // Initial SP value
    uint16_t e_csum;     // Checksum
    uint16_t e_ip;       // Initial IP value
    uint16_t e_cs;       // Initial (relative) CS value
    uint16_t e_lfarlc;   // File address of relocation table
    uint16_t e_ovno;     // Overlay number
    uint16_t e_res[4];   // Reserved words
    uint16_t e_oemid;    // OEM identifier
    uint16_t e_oeminfo;  // OEM information for e_oemid
    uint16_t e_res2[10]; // Reserved words
    uint32_t e_lfanew;   // File address of new exe header (NT Header Offset)
};

struct FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct OptionalHeader64 {
    uint16_t Magic; // 0x20b for PE32+ (64-bit)
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DataDirectory DataDirectory[16];
};

struct SectionHeader {
    uint8_t  Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

#pragma pack(pop)

// Calculates Shannon Entropy to identify encrypted or compressed sections
double calculate_shannon_entropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;

    size_t byte_counts[256] = {0};
    for (size_t i = 0; i < size; ++i) {
        byte_counts[data[i]]++;
    }

    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (byte_counts[i] > 0) {
            double probability = static_cast<double>(byte_counts[i]) / size;
            entropy -= probability * std::log2(probability);
        }
    }
    return entropy;
}

std::string format_timestamp(uint32_t timestamp) {
    std::time_t t = static_cast<std::time_t>(timestamp);
    std::tm* tm_info = std::gmtime(&t);
    if (!tm_info) return "Invalid Timestamp";
    char buffer[30];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S UTC", tm_info);
    return std::string(buffer);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "[-] Error: Missing argument.\nUsage: " << argv[0] << " <path_to_pe_executable>\n";
        return 1;
    }

    std::string file_path = argv[1];
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[-] Error: Failed to open target file: " << file_path << "\n";
        return 1;
    }

    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(file_size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), file_size)) {
        std::cerr << "[-] Error: Failed reading payload binary content.\n";
        return 1;
    }

    // 1. Verify DOS Header Signature
    if (file_size < sizeof(DOSHeader)) {
        std::cerr << "[-] Error: File is size-deficient to hold a structural DOS header.\n";
        return 1;
    }
    auto* dos_header = reinterpret_cast<DOSHeader*>(buffer.data());
    if (dos_header->e_magic != 0x5A4D) { // "MZ"
        std::cerr << "[-] Invalid File Format: Missing 'MZ' magic byte sequence.\n";
        return 1;
    }

    // 2. Locate and Verify NT Headers
    size_t nt_offset = dos_header->e_lfanew;
    if (nt_offset + sizeof(uint32_t) + sizeof(FileHeader) > buffer.size()) {
        std::cerr << "[-] Error: Corrupted or missing PE header offset values.\n";
        return 1;
    }

    uint32_t pe_signature = *reinterpret_cast<uint32_t*>(&buffer[nt_offset]);
    if (pe_signature != 0x00004550) { // "PE\0\0"
        std::cerr << "[-] Validation Mismatch: Signature is not recognized as valid Win32/64 PE execution binary.\n";
        return 1;
    }

    auto* file_header = reinterpret_cast<FileHeader*>(&buffer[nt_offset + sizeof(uint32_t)]);
    size_t opt_header_offset = nt_offset + sizeof(uint32_t) + sizeof(FileHeader);

    auto* opt_header = reinterpret_cast<OptionalHeader64*>(&buffer[opt_header_offset]);
    bool is_pe32_plus = (opt_header->Magic == 0x20B); // 0x10B = PE32, 0x20B = PE32+

    // 3. Render Metadata Layout Report
    std::cout << "========================================================\n";
    std::cout << "        STATIC PE MALWARE ANALYZER & PARSER ENGINE      \n";
    std::cout << "========================================================\n";
    std::cout << "[+] Target Path:      " << file_path << "\n";
    std::cout << "[+] Architecture:     " << (is_pe32_plus ? "PE32+ (64-bit)" : "PE32 (32-bit / Legacy Spec)") << "\n";
    std::cout << "[+] Header Timestamp: " << format_timestamp(file_header->TimeDateStamp) << "\n";
    std::cout << "[+] Section Count:    " << file_header->NumberOfSections << "\n";

    // Extract Directory References
    uint32_t export_rva = opt_header->DataDirectory[0].VirtualAddress;
    uint32_t export_size = opt_header->DataDirectory[0].Size;
    uint32_t import_rva = opt_header->DataDirectory[1].VirtualAddress;
    uint32_t tls_rva = opt_header->DataDirectory[9].VirtualAddress;

    std::cout << "--------------------------------------------------------\n";
    std::cout << "                   DIRECTORY INDEX                      \n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << " [*] Export Table RVA:  0x" << std::hex << std::setw(8) << std::setfill('0') << export_rva << " | Size: " << std::dec << export_size << " bytes\n";
    std::cout << " [*] Import Table RVA:  0x" << std::hex << std::setw(8) << std::setfill('0') << import_rva << "\n";
    std::cout << " [*] TLS Callbacks RVA: 0x" << std::hex << std::setw(8) << std::setfill('0') << tls_rva << "\n\n";

    // 4. Parse Sections Table & Compute Section Entropies
    size_t section_table_offset = opt_header_offset + file_header->SizeOfOptionalHeader;
    bool high_entropy_detected = false;

    std::cout << "--------------------------------------------------------\n";
    std::cout << "                 SECTION METRIC MATRIX                  \n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << std::left << std::setw(10) << "Name"
              << std::setw(12) << "Raw Size"
              << std::setw(14) << "Raw Offset"
              << "Entropy (Shannon)\n";

    for (int i = 0; i < file_header->NumberOfSections; ++i) {
        size_t current_section_offset = section_table_offset + (i * sizeof(SectionHeader));
        if (current_section_offset + sizeof(SectionHeader) > buffer.size()) break;

        auto* section = reinterpret_cast<SectionHeader*>(&buffer[current_section_offset]);

        // Clean section names safely
        char name[9] = {0};
        std::memcpy(name, section->Name, 8);
        std::string section_name(name);

        double entropy = 0.0;
        if (section->PointerToRawData < buffer.size() && section->PointerToRawData + section->SizeOfRawData <= buffer.size()) {
            entropy = calculate_shannon_entropy(&buffer[section->PointerToRawData], section->SizeOfRawData);
        }

        std::cout << std::left << std::setw(10) << (section_name.empty() ? "[Null]" : section_name)
                  << std::hex << "0x" << std::setw(10) << section->SizeOfRawData
                  << "0x" << std::setw(12) << section->PointerToRawData
                  << std::fixed << std::setprecision(4) << entropy;

        if (entropy >= 7.0) {
            std::cout << " [!] High Entropy (Packed/Encrypted)";
            high_entropy_detected = true;
        }
        std::cout << "\n";
    }

    // 5. Threat Indicator Flagging Engine (Heuristics Log)
    std::cout << "\n--------------------------------------------------------\n";
    std::cout << "             HEURISTIC THREAT REPORT LOG                \n";
    std::cout << "--------------------------------------------------------\n";
    bool clean = true;

    // Detection Rule A: Mismatched or Post-Dated Timestamps
    std::time_t current_time = std::time(nullptr);
    if (file_header->TimeDateStamp > current_time + 86400) {
        std::cout << "[ALERT] Suspicious Characteristic: Compilation timestamp is set to a future date ("
                  << format_timestamp(file_header->TimeDateStamp) << "). Likely tampered via an anti-forensic timestomping tool.\n";
        clean = false;
    }

    // Detection Rule B: Packed/Obfuscated Code Signatures
    if (high_entropy_detected) {
        std::cout << "[ALERT] Suspicious Characteristic: High raw structural data entropy observed. File is highly likely compressed, obscured, or armed with a dynamic loader runtime protector (e.g., UPX, VMProtect).\n";
        clean = false;
    }

    // Detection Rule C: Missing Export Directory in Native Execution
    if (export_rva == 0 && (file_header->Characteristics & 0x2000)) { // 0x2000 identifies safe structural DLL flags
        std::cout << "[ALERT] Suspicious Anomalous Event: File claims structure behavior of a Dynamic Link Library (.dll) but exposes no native entry exports.\n";
        clean = false;
    }

    if (clean) {
        std::cout << "[*] Status Clean: No immediate heuristic binary red-flags found.\n";
    }

    std::cout << "========================================================\n";
    return 0;
}