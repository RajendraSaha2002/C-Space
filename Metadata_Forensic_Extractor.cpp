#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <string>
#include <cstring>

class ForensicsExtractor {
public:
    explicit ForensicsExtractor(const std::string& filepath) : filepath_(filepath) {}

    void analyze() {
        if (!loadFile()) return;

        std::cout << "==========================================\n";
        std::cout << "Analyzing file: " << filepath_ << "\n";
        std::cout << "File size: " << fileData_.size() << " bytes\n";
        std::cout << "==========================================\n";

        if (isJPEG()) {
            std::cout << "[+] Format identified: JPEG\n";
            parseJPEG();
        } else if (isPNG()) {
            std::cout << "[+] Format identified: PNG\n";
            parsePNG();
        } else {
            std::cerr << "[-] Error: Unknown or unsupported file format.\n";
        }
    }

private:
    std::string filepath_;
    std::vector<uint8_t> fileData_;

    bool loadFile() {
        std::ifstream file(filepath_, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "[-] Error: Could not open file " << filepath_ << "\n";
            return false;
        }
        file.seekg(0, std::ios::end);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        if (size <= 0) {
            std::cerr << "[-] Error: File is empty.\n";
            return false;
        }

        fileData_.resize(size);
        if (!file.read(reinterpret_cast<char*>(fileData_.data()), size)) {
            std::cerr << "[-] Error: Failed to read file data.\n";
            return false;
        }
        return true;
    }

    bool isJPEG() const {
        return fileData_.size() > 2 && fileData_[0] == 0xFF && fileData_[1] == 0xD8;
    }

    bool isPNG() const {
        const uint8_t pngSignature[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
        if (fileData_.size() < 8) return false;
        return std::memcmp(fileData_.data(), pngSignature, 8) == 0;
    }

    // --- JPEG PARSING LOGIC ---
    void parseJPEG() {
        size_t offset = 2; // Skip SOI (FF D8)
        bool hasExif = false;
        bool eoiFound = false;

        while (offset < fileData_.size() - 1) {
            if (fileData_[offset] != 0xFF) {
                std::cerr << "[-] Structural anomaly detected at offset 0x" << std::hex << offset << "\n";
                break;
            }

            uint8_t marker = fileData_[offset + 1];

            // End of Image (EOI)
            if (marker == 0xD9) {
                std::cout << "[INFO] Found EOI (End of Image) at 0x" << std::hex << offset << "\n";
                eoiFound = true;
                offset += 2;
                break;
            }

            // Markers without length (e.g., RSTn, SOI)
            if (marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0x00) {
                offset += 2;
                continue;
            }

            // Read 16-bit Big-Endian length
            if (offset + 3 >= fileData_.size()) break;
            uint16_t length = (fileData_[offset + 2] << 8) | fileData_[offset + 3];

            analyzeJPEGMarker(marker, offset, length, hasExif);

            // SOS (Start of Scan) - Entropy coded data follows, length doesn't cover it
            if (marker == 0xDA) {
                std::cout << "[INFO] Compressed image data begins (SOS). Skipping to EOI...\n";
                offset = scanForJPEGEoi(offset + 2 + length);
                continue;
            }

            offset += 2 + length;
        }

        // Tamper Detection Heuristics
        std::cout << "\n--- Tamper Detection (JPEG) ---\n";
        if (!hasExif) {
            std::cout << "[WARN] Metadata Stripping Detected: No EXIF APP1 segment found.\n";
        }
        if (eoiFound && offset < fileData_.size()) {
            std::cout << "[ALERT] Hidden Data Anomaly: " << std::dec << (fileData_.size() - offset)
                      << " bytes of trailing data found after EOI marker.\n";
        } else {
            std::cout << "[OK] No trailing data detected.\n";
        }
    }

    void analyzeJPEGMarker(uint8_t marker, size_t offset, uint16_t length, bool& hasExif) {
        std::cout << "Marker: FF" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)marker
                  << " | Offset: 0x" << offset << " | Size: " << std::dec << length << " bytes\n";

        if (marker == 0xE1) { // APP1 - EXIF or XMP
            if (offset + 8 < fileData_.size()) {
                std::string identifier(reinterpret_cast<const char*>(&fileData_[offset + 4]), 4);
                if (identifier == "Exif") {
                    hasExif = true;
                    std::cout << "   -> [Extracted] EXIF Metadata Payload found.\n";
                    // Further byte-by-byte TIFF parsing (GPS, Camera Model) happens inside this payload.
                } else if (identifier == "http") {
                    std::cout << "   -> [Extracted] XMP Namespace (Adobe) Payload found.\n";
                }
            }
        }
        else if (marker == 0xE2) { // APP2 - ICC Profile
            if (offset + 16 < fileData_.size()) {
                std::string identifier(reinterpret_cast<const char*>(&fileData_[offset + 4]), 11);
                if (identifier == "ICC_PROFILE") {
                    std::cout << "   -> [Extracted] ICC Color Profile found.\n";
                }
            }
        }
        else if (marker == 0xFE) { // COM - Comment
            std::cout << "   -> [Extracted] Software Comment/Watermark found.\n";
        }
    }

    size_t scanForJPEGEoi(size_t startOffset) {
        for (size_t i = startOffset; i < fileData_.size() - 1; ++i) {
            if (fileData_[i] == 0xFF && fileData_[i + 1] == 0xD9) {
                return i;
            }
        }
        return fileData_.size();
    }

    // --- PNG PARSING LOGIC ---
    void parsePNG() {
        size_t offset = 8; // Skip PNG Signature
        bool hasIEND = false;
        bool hasMetadata = false;

        while (offset + 8 <= fileData_.size()) {
            // Read 32-bit Big-Endian length
            uint32_t length = (fileData_[offset] << 24) | (fileData_[offset + 1] << 16) |
                              (fileData_[offset + 2] << 8) | fileData_[offset + 3];

            // Read 4-byte Chunk Type
            std::string chunkType(reinterpret_cast<const char*>(&fileData_[offset + 4]), 4);

            std::cout << "Chunk: " << chunkType << " | Offset: 0x" << std::hex << offset
                      << " | Size: " << std::dec << length << " bytes\n";

            analyzePNGChunk(chunkType, offset, length, hasMetadata);

            if (chunkType == "IEND") {
                hasIEND = true;
                offset += 12; // Length(4) + Type(4) + Data(0) + CRC(4)
                break;
            }

            offset += 12 + length; // Length(4) + Type(4) + Data(length) + CRC(4)
        }

        // Tamper Detection Heuristics
        std::cout << "\n--- Tamper Detection (PNG) ---\n";
        if (!hasMetadata) {
            std::cout << "[WARN] Metadata Stripping Detected: No text/EXIF chunks found.\n";
        }
        if (hasIEND && offset < fileData_.size()) {
            std::cout << "[ALERT] Hidden Data Anomaly: " << std::dec << (fileData_.size() - offset)
                      << " bytes of trailing data found after IEND chunk.\n";
        } else if (!hasIEND) {
             std::cout << "[ALERT] Structural Anomaly: IEND chunk missing. File may be truncated or corrupted.\n";
        } else {
            std::cout << "[OK] File terminates cleanly after IEND.\n";
        }
    }

    void analyzePNGChunk(const std::string& type, size_t offset, uint32_t length, bool& hasMetadata) {
        if (type == "eXIf") {
            hasMetadata = true;
            std::cout << "   -> [Extracted] Native EXIF chunk found.\n";
        } else if (type == "tEXt" || type == "iTXt" || type == "zTXt") {
            hasMetadata = true;
            std::cout << "   -> [Extracted] Text Metadata (Possible XMP/Software Watermarks).\n";
            // Basic extraction of the keyword to see what the text chunk contains
            if (length > 0 && offset + 8 + length <= fileData_.size()) {
                 std::string payload(reinterpret_cast<const char*>(&fileData_[offset + 8]), std::min(length, (uint32_t)20));
                 std::cout << "      Keyword snippet: " << payload.substr(0, payload.find('\0')) << "...\n";
            }
        } else if (type == "iCCP") {
            std::cout << "   -> [Extracted] ICC Color Profile found.\n";
        }
    }
};

int main(int argc, char* argv[]) {
    // You can hardcode a path here for testing in CLion if you don't want to use CLI arguments
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_image.jpg_or_png>\n";
        std::cout << "\nTip: To run in CLion, Edit Configurations -> add path to 'Program arguments'.\n";
        return 1;
    }

    std::string filepath = argv[1];
    ForensicsExtractor extractor(filepath);
    extractor.analyze();

    return 0;
}