#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

// Rights bitmask definitions
#define CAP_READ  (1 << 0) // 0x01
#define CAP_WRITE (1 << 1) // 0x02
#define CAP_EXEC  (1 << 2) // 0x04

// Token structure
typedef struct {
    char object_name[32];
    uint8_t rights;
    time_t expiry;
    uint8_t signature[32]; // ASCON-HMAC output size
} CapabilityToken;

// --- Cryptographic Placeholders ---
// In a real implementation, you would use the official Ascon-HMAC library functions.
void generate_ascon_hmac(const char* data, uint8_t* out_sig) {
    // Placeholder: In production, call your Ascon HMAC library here.
    // Example: ascon_hmac(key, data, len, out_sig);
    memset(out_sig, 0xAA, 32);
}

bool verify_ascon_hmac(const char* data, const uint8_t* sig) {
    // Placeholder: Validate the HMAC signature.
    uint8_t expected[32];
    memset(expected, 0xAA, 32);
    return memcmp(sig, expected, 32) == 0;
}

// --- CapBAC Logic ---

bool is_token_valid(const CapabilityToken* token, uint8_t required_rights) {
    // 1. Check Expiry
    if (time(NULL) > token->expiry) {
        printf("Error: Token expired.\n");
        return false;
    }

    // 2. Check Signature
    // We recreate the hash context from token fields to verify authenticity
    char data_to_verify[64];
    snprintf(data_to_verify, sizeof(data_to_verify), "%s%d%ld",
             token->object_name, token->rights, token->expiry);

    if (!verify_ascon_hmac(data_to_verify, token->signature)) {
        printf("Error: Invalid signature (Tampering detected).\n");
        return false;
    }

    // 3. Check Rights (Bitwise AND)
    if ((token->rights & required_rights) != required_rights) {
        printf("Error: Insufficient privileges.\n");
        return false;
    }

    return true;
}

// Simulated System Operation
void perform_operation(const CapabilityToken* token, const char* action, uint8_t required_rights) {
    printf("Attempting to %s on %s...\n", action, token->object_name);

    if (is_token_valid(token, required_rights)) {
        printf("SUCCESS: Operation allowed.\n");
    } else {
        printf("FAILURE: Operation denied.\n");
    }
}

int main() {
    // Example: A subject holds a token for "sensor_data" with READ access
    CapabilityToken myToken = {
        .object_name = "sensor_data",
        .rights = CAP_READ,
        .expiry = time(NULL) + 3600 // Valid for 1 hour
    };

    // Sign the token
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s%d%ld", myToken.object_name, myToken.rights, myToken.expiry);
    generate_ascon_hmac(buffer, myToken.signature);

    // Demonstration
    perform_operation(&myToken, "READ", CAP_READ);   // Should pass
    perform_operation(&myToken, "WRITE", CAP_WRITE); // Should fail (no write rights)

    return 0;
}