#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <stdbool.h>

// --- Configuration ---
#define REGION_SIZE 1024
#define ENTROPY_THRESHOLD 7.2

// --- Compatibility Fix for Windows/MinGW ---
// Standard 'memmem' is not available in MinGW, so we provide this custom implementation.
void *memmem(const void *haystack, size_t haystack_len,
             const void *needle, size_t needle_len) {
    if (needle_len == 0) return (void *)haystack;
    if (haystack_len < needle_len) return NULL;

    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(h + i, n, needle_len) == 0) {
            return (void *)(h + i);
        }
    }
    return NULL;
}

typedef struct {
    char name[20];
    uint8_t *data;
    size_t size;
} MemoryRegion;

// --- Entropy Analysis ---
// Calculates Shannon Entropy to detect packed/encrypted data
double calculate_entropy(const uint8_t *data, size_t size) {
    if (size == 0) return 0.0;
    size_t frequencies[256] = {0};
    for (size_t i = 0; i < size; i++) frequencies[data[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequencies[i] > 0) {
            double p = (double)frequencies[i] / size;
            entropy -= p * (log2(p));
        }
    }
    return entropy;
}

// --- YARA-Inspired Rule Matching ---
void yara_scan(const MemoryRegion *region) {
    const char *signatures[] = {"\x90\x90\x90", "EVIL_PAYLOAD", "admin_secret"};
    printf("  [YARA] Scanning %s...\n", region->name);

    for (int i = 0; i < 3; i++) {
        // The custom memmem is used here
        if (memmem(region->data, region->size, signatures[i], strlen(signatures[i]))) {
            printf("    !!! ALERT: Match found: %s\n", signatures[i]);
        }
    }
}

// --- Forensic Analysis Runner ---
void analyze_memory(MemoryRegion *regions, int num_regions) {
    printf("=== Starting Forensic Analysis Report ===\n");
    for (int i = 0; i < num_regions; i++) {
        printf("\nRegion: %s (Size: %zu bytes)\n", regions[i].name, regions[i].size);

        // 1. Run Entropy Check
        double ent = calculate_entropy(regions[i].data, regions[i].size);
        printf("  [Entropy] Score: %.2f\n", ent);
        if (ent > ENTROPY_THRESHOLD) {
            printf("    !!! WARNING: High entropy detected (Potential Shellcode/Packed data)\n");
        }

        // 2. Run Signature Scan
        yara_scan(&regions[i]);
    }
    printf("\n=== Analysis Complete ===\n");
}

int main() {
    // Allocate Memory Regions
    MemoryRegion regions[3];
    for (int i = 0; i < 3; i++) {
        regions[i].data = (uint8_t *)calloc(REGION_SIZE, sizeof(uint8_t));
        regions[i].size = REGION_SIZE;
    }

    strcpy(regions[0].name, "Heap_Segment");
    strcpy(regions[1].name, "Stack_Segment");
    strcpy(regions[2].name, "Code_Segment");

    // Inject Malicious Artifacts for testing
    memcpy(regions[0].data, "EVIL_PAYLOAD_CONFIG", 19);
    memcpy(regions[1].data, "admin_secret:password123", 24);

    // Simulate encrypted data (High entropy)
    for(int i=0; i<100; i++) regions[0].data[50+i] = rand() % 256;

    // Execute Analysis
    analyze_memory(regions, 3);

    // Cleanup
    for (int i = 0; i < 3; i++) free(regions[i].data);
    return 0;
}