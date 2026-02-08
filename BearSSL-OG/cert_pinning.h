#pragma once

#include <bearssl.h>

#define MAX_PINNED_HOSTS 8

class cert_pinning
{
public:
    static void initialize();
    static void shutdown();

    // Add a pin: hostname + SHA-256 hash of certificate
    static bool add_pin(const char* hostname, const unsigned char* sha256_hash);

    // Remove a pin
    static void remove_pin(const char* hostname);

    // Clear all pins
    static void clear();

    // Verify certificate hash matches pin (returns true if no pin exists or if pin matches)
    static bool verify(const char* hostname, br_ssl_engine_context* engine);

    // Verify a pre-computed SHA-256 hash against stored pin
    // Returns true if no pin exists for hostname, or if pin matches the hash
    static bool verify_hash(const char* hostname, const unsigned char* cert_sha256);

    // Check if hostname has a pin
    static bool has_pin(const char* hostname);

    // Get the stored pin hash for a hostname (returns false if no pin)
    static bool get_pin_hash(const char* hostname, unsigned char* hash_out);

    // Get hash of current certificate (for setting up pins)
    static void get_cert_hash(br_ssl_engine_context* engine, unsigned char* hash_out);

private:
    struct pin_entry {
        char hostname[256];
        unsigned char sha256_hash[32];
        bool valid;
    };

    static pin_entry pins[MAX_PINNED_HOSTS];
    static bool initialized;

    static int find_pin(const char* hostname);
};
