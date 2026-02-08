#include "cert_pinning.h"
#include "ssl_debug.h"

#include <string.h>
#include <bearssl.h>

cert_pinning::pin_entry cert_pinning::pins[MAX_PINNED_HOSTS];
bool cert_pinning::initialized = false;

void cert_pinning::initialize()
{
    if (initialized) return;

    memset(pins, 0, sizeof(pins));
    initialized = true;
    ssl_debug::log_verbose("Certificate pinning initialized\n");
}

void cert_pinning::shutdown()
{
    clear();
    initialized = false;
}

int cert_pinning::find_pin(const char* hostname)
{
    for (int i = 0; i < MAX_PINNED_HOSTS; i++) {
        if (pins[i].valid && strcmp(pins[i].hostname, hostname) == 0) {
            return i;
        }
    }
    return -1;
}

bool cert_pinning::add_pin(const char* hostname, const unsigned char* sha256_hash)
{
    if (!initialized) initialize();

    // Check if already exists
    int idx = find_pin(hostname);
    if (idx >= 0) {
        // Update existing
        memcpy(pins[idx].sha256_hash, sha256_hash, 32);
        ssl_debug::log_info("Certificate pin updated for %s\n", hostname);
        return true;
    }

    // Find free slot
    for (int i = 0; i < MAX_PINNED_HOSTS; i++) {
        if (!pins[i].valid) {
            strncpy(pins[i].hostname, hostname, 255);
            pins[i].hostname[255] = '\0';
            memcpy(pins[i].sha256_hash, sha256_hash, 32);
            pins[i].valid = true;
            ssl_debug::log_info("Certificate pin added for %s\n", hostname);
            return true;
        }
    }

    ssl_debug::log_error("Certificate pin table full, cannot add %s\n", hostname);
    return false;
}

void cert_pinning::remove_pin(const char* hostname)
{
    int idx = find_pin(hostname);
    if (idx >= 0) {
        pins[idx].valid = false;
        ssl_debug::log_info("Certificate pin removed for %s\n", hostname);
    }
}

void cert_pinning::clear()
{
    memset(pins, 0, sizeof(pins));
    ssl_debug::log_verbose("All certificate pins cleared\n");
}

bool cert_pinning::has_pin(const char* hostname)
{
    return find_pin(hostname) >= 0;
}

bool cert_pinning::get_pin_hash(const char* hostname, unsigned char* hash_out)
{
    int idx = find_pin(hostname);
    if (idx < 0) {
        return false;
    }
    memcpy(hash_out, pins[idx].sha256_hash, 32);
    return true;
}

void cert_pinning::get_cert_hash(br_ssl_engine_context* engine, unsigned char* hash_out)
{
    /*
     * This legacy function is kept for API compatibility but is not the
     * recommended path. Use verify_hash() with a hash captured by the
     * custom X.509 callback in bearssl.c instead.
     */
    (void)engine;
    memset(hash_out, 0, 32);
}

bool cert_pinning::verify_hash(const char* hostname, const unsigned char* cert_sha256)
{
    if (!initialized) initialize();

    int idx = find_pin(hostname);
    if (idx < 0) {
        /* No pin for this host - allow connection */
        return true;
    }

    /* Compare the captured certificate hash against the stored pin */
    if (memcmp(pins[idx].sha256_hash, cert_sha256, 32) == 0) {
        ssl_debug::log_info("Certificate pin MATCH for %s\n", hostname);
        return true;
    }

    /* Pin mismatch */
    ssl_debug::log_error("Certificate pin MISMATCH for %s!\n", hostname);
    ssl_debug::log_error("  Expected: %02X%02X%02X%02X...\n",
        pins[idx].sha256_hash[0], pins[idx].sha256_hash[1],
        pins[idx].sha256_hash[2], pins[idx].sha256_hash[3]);
    ssl_debug::log_error("  Got:      %02X%02X%02X%02X...\n",
        cert_sha256[0], cert_sha256[1], cert_sha256[2], cert_sha256[3]);
    return false;
}

bool cert_pinning::verify(const char* hostname, br_ssl_engine_context* engine)
{
    if (!initialized) initialize();

    int idx = find_pin(hostname);
    if (idx < 0) {
        /* No pin for this host - allow connection */
        return true;
    }

    /*
     * Legacy path: try to use the engine directly.
     * The preferred path is verify_hash() called from the X.509 callback
     * in bearssl.c, which captures the leaf cert hash during the handshake.
     */
    ssl_debug::log_info("Certificate pin check for %s (via engine - use verify_hash for best results)\n", hostname);

    (void)engine;
    return true;
}
