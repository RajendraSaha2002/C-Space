#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <string>

// Helper to read Big-Endian 16-bit integers (SQLite uses Big-Endian)
uint16_t read_uint16_be(const uint8_t* buffer) {
    return (buffer[0] << 8) | buffer[1];
}

// Helper to read Big-Endian 32-bit integers
uint32_t read_uint32_be(const uint8_t* buffer) {
    return (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
}

// Struct to represent the parsed SQLite 100-byte database header
struct SQLiteHeader {
    char magic[16];
    uint32_t page_size;
    uint32_t total_freelist_pages;
    uint32_t first_freelist_trunk;
};

// Function to handle raw B-Tree validation and searching for deleted row fragments
void parse_btree_page(const std::vector<uint8_t>& page_data, size_t page_num, bool is_page_1) {
    // Page 1 contains the 100-byte database header before the B-Tree page header starts
    size_t offset = is_page_1 ? 100 : 0;
    if (offset >= page_data.size()) return;

    uint8_t page_type = page_data[offset];
    std::cout << "  [Page " << page_num << "] Type: 0x"
              << std::hex << (int)page_type << std::dec << " -> ";

    switch (page_type) {
        case 0x02: std::cout << "Interior Index B-Tree Page\n"; break;
        case 0x05: std::cout << "Interior Table B-Tree Page\n"; break;
        case 0x0a: std::cout << "Leaf Index B-Tree Page\n"; break;
        case 0x0d: std::cout << "Leaf Table B-Tree Page (Contains Data Records)\n"; break;
        default:   std::cout << "Freelist, Overflow, or Unallocated Page\n"; return;
    }

    // Parse B-Tree Header fields (offsets relative to start of B-Tree header)
    uint16_t first_freeblock = read_uint16_be(&page_data[offset + 1]);
    uint16_t cell_count = read_uint16_be(&page_data[offset + 3]);
    uint16_t cell_content_offset = read_uint16_be(&page_data[offset + 5]);
    if (cell_content_offset == 0) cell_content_offset = 65536; // 0 means 65536 bytes

    std::cout << "    - Total active cells (live records): " << cell_count << "\n";
    std::cout << "    - First freeblock offset: " << first_freeblock << "\n";
    std::cout << "    - Cell content area start pointer: " << cell_content_offset << "\n";

    // --- FORENSIC ANALYSIS RECOVERY LOGIC ---
    // Active records grow upward from the bottom of the page.
    // The cell pointer array grows downward from the header.
    // The area between the end of the cell pointer array and 'cell_content_offset'
    // is unallocated space where deleted row records reside.

    size_t cell_pointer_array_start = offset + (page_type == 0x02 || page_type == 0x05 ? 12 : 8);
    size_t unallocated_start = cell_pointer_array_start + (2 * cell_count);

    std::cout << "    - Forensic Scan Range for deleted rows: Bytes "
              << unallocated_start << " to " << cell_content_offset << "\n";

    if (cell_content_offset > unallocated_start) {
        size_t unallocated_size = cell_content_offset - unallocated_start;
        std::cout << "    - [Analyzing " << unallocated_size << " bytes of unallocated slack space...]\n";

        // Pattern match logic (Cell header signatures) goes here
        // Example: Scanning for valid Varints or deleted payload structures
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Error: Missing argument.\nUsage: " << argv[0] << " <path_to_sqlite_db>\n";
        return 1;
    }

    std::string file_path = argv[1];
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open database file: " << file_path << "\n";
        return 1;
    }

    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (file_size < 100) {
        std::cerr << "Error: File is too small to be a valid SQLite database.\n";
        return 1;
    }

    std::vector<uint8_t> header_buf(100);
    if (!file.read(reinterpret_cast<char*>(header_buf.data()), 100)) {
        std::cerr << "Error reading database signature header.\n";
        return 1;
    }

    // 1. Verify Magic String Header Requirement
    if (std::memcmp(header_buf.data(), "SQLite format 3\0", 16) != 0) {
        std::cerr << "Error: Verified bad format. File is not a valid SQLite 3 database.\n";
        return 1;
    }

    SQLiteHeader db_header{};
    std::memcpy(db_header.magic, header_buf.data(), 16);

    // Parse Page Size (Offset 16, 2 bytes)
    db_header.page_size = read_uint16_be(&header_buf[16]);
    if (db_header.page_size == 1) db_header.page_size = 65536; // Spec handling for 65536

    // Parse Freelist details
    db_header.total_freelist_pages = read_uint32_be(&header_buf[32]);
    db_header.first_freelist_trunk = read_uint32_be(&header_buf[36]);

    std::cout << "==================================================\n";
    std::cout << "   SQLITE FORENSIC RECOVERY ENGINE (RAW PARSER)   \n";
    std::cout << "==================================================\n";
    std::cout << "Target File:            " << file_path << "\n";
    std::cout << "Total File Size:        " << file_size << " bytes\n";
    std::cout << "Detected Page Size:     " << db_header.page_size << " bytes\n";
    std::cout << "Total Freelist Pages:   " << db_header.total_freelist_pages << "\n";
    std::cout << "First Freelist Trunk:   " << db_header.first_freelist_trunk << "\n";
    std::cout << "--------------------------------------------------\n\n";

    // 2. Page-level Processing Loop
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> page_buffer(db_header.page_size);
    size_t current_page = 0;

    while (file.read(reinterpret_cast<char*>(page_buffer.data()), db_header.page_size)) {
        current_page++;

        // Track and process Freelist Page Chains
        if (current_page == db_header.first_freelist_trunk) {
            std::cout << "  [Page " << current_page << "] -> **Freelist Trunk Page Detected**\n";
            // Freelist pages often contain completely intact historical rows
            // before they are overwritten by new allocations.
        }

        // Process standard B-Tree records and scan for dropped elements
        parse_btree_page(page_buffer, current_page, (current_page == 1));
    }

    std::cout << "\n==================================================\n";
    std::cout << "Forensic scan complete. Evaluated " << current_page << " total pages.\n";
    std::cout << "==================================================\n";

    return 0;
}