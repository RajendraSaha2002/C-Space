#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

// --- Configuration & Constants ---
#define MAX_PCR_VALUE 32
#define MIN_SUPPORTED_VERSION 1

// Simulated hardware "fuses"
static int system_security_version = 2; // Current platform version (Rollback protection)
static uint8_t pcr[MAX_PCR_VALUE] = {0}; // TPM PCR register (initially 0)

// Simulated Boot Stage Data
typedef struct {
    const char* name;
    uint32_t version;
    uint8_t  measurement[32]; // Hash of the binary
    uint8_t  signature[32];   // ASCON-signed certificate
} BootStage;

// --- Security Primitives (Mocks) ---
// In a real implementation, link against the ASCON and SHA256 libraries.
bool verify_ascon_signature(uint8_t* data, uint8_t* sig) {
    // Simulate ASCON verification logic
    printf("  [Verification] Checking ASCON signature for authenticity...\n");
    return true; // Simplified for simulation
}

void tpm_extend_pcr(uint8_t* new_measurement) {
    // TPM PCR extension: new_pcr = hash(old_pcr || new_measurement)
    printf("  [TPM] Extending PCR with new measurement...\n");
    // Simple XOR/Merge simulation for demonstration
    for(int i = 0; i < MAX_PCR_VALUE; i++) {
        pcr[i] ^= new_measurement[i % 32];
    }
}

// --- Chain of Trust Logic ---
bool load_stage(const BootStage* stage) {
    printf("\n--- Loading %s ---\n", stage->name);

    // 1. Rollback Protection Check
    if (stage->version < system_security_version) {
        printf("CRITICAL ERROR: Rollback detected! Version %d is older than required %d.\n",
               stage->version, system_security_version);
        return false;
    }

    // 2. Cryptographic Verification
    if (!verify_ascon_signature((uint8_t*)stage->name, (uint8_t*)stage->signature)) {
        printf("CRITICAL ERROR: Signature verification failed.\n");
        return false;
    }

    // 3. Chain of Trust: Extend TPM PCR
    tpm_extend_pcr((uint8_t*)stage->measurement);

    printf("SUCCESS: %s loaded and verified.\n", stage->name);
    return true;
}

int main() {
    printf("=== Secure Boot Chain Simulator ===\n");

    // Define the stages
    BootStage stage1 = {"Stage-1 Bootloader", 2, {0x11}, {0xAA}};
    BootStage kernel  = {"Kernel Image", 2, {0x22}, {0xBB}};

    // Execution Flow
    // 1. ROM Bootloader (Implicitly Trusted Root)
    printf("[System] ROM Bootloader initialized.\n");

    // 2. Validate and Load Stage 1
    if (!load_stage(&stage1)) {
        printf("System Halted.\n");
        return 1;
    }

    // 3. Validate and Load Kernel
    if (!load_stage(&kernel)) {
        printf("System Halted.\n");
        return 1;
    }

    printf("\n=== Secure Boot Complete. System Operational. ===\n");
    return 0;
}