#include "session_cache.h"
#include "ssl_debug.h"

#include <xtl.h>
#include <string.h>

// KeQuerySystemTime is exported by the Xbox kernel (xboxkrnl.lib)
#ifdef __cplusplus
extern "C"
#endif
void WINAPI KeQuerySystemTime(PLARGE_INTEGER CurrentTime);

session_cache::session_entry session_cache::entries[SESSION_CACHE_SIZE];
bool session_cache::initialized = false;

void session_cache::initialize()
{
    if (initialized) return;

    memset(entries, 0, sizeof(entries));
    initialized = true;
    ssl_debug::log_verbose("Session cache initialized (%d slots)\n", SESSION_CACHE_SIZE);
}

void session_cache::shutdown()
{
    clear();
    initialized = false;
}

uint32_t session_cache::get_current_time()
{
    LARGE_INTEGER system_time;
    KeQuerySystemTime(&system_time);
    // Convert 100-nanosecond intervals to seconds
    return (uint32_t)(system_time.QuadPart / 10000000ULL);
}

int session_cache::find_entry(const char* hostname)
{
    for (int i = 0; i < SESSION_CACHE_SIZE; i++) {
        if (entries[i].valid && strcmp(entries[i].hostname, hostname) == 0) {
            return i;
        }
    }
    return -1;
}

int session_cache::find_free_slot()
{
    uint32_t current_time = get_current_time();
    int oldest_idx = -1;
    uint32_t oldest_time = 0xFFFFFFFF;

    for (int i = 0; i < SESSION_CACHE_SIZE; i++) {
        // Free slot
        if (!entries[i].valid) {
            return i;
        }

        // Expired entry - reuse it (guard against RTC going backwards)
        if (current_time >= entries[i].timestamp
            && current_time - entries[i].timestamp > SESSION_MAX_AGE_SECONDS) {
            entries[i].valid = false;
            return i;
        }

        // Track oldest for LRU eviction
        if (entries[i].timestamp < oldest_time) {
            oldest_time = entries[i].timestamp;
            oldest_idx = i;
        }
    }

    // Evict oldest entry
    if (oldest_idx >= 0) {
        ssl_debug::log_verbose("Session cache: evicting entry for %s\n", entries[oldest_idx].hostname);
        entries[oldest_idx].valid = false;
        return oldest_idx;
    }

    return 0; // Fallback to first slot
}

bool session_cache::get(const char* hostname, br_ssl_session_parameters* params)
{
    if (!initialized) initialize();

    int idx = find_entry(hostname);
    if (idx < 0) {
        ssl_debug::log_verbose("Session cache: miss for %s\n", hostname);
        return false;
    }

    uint32_t current_time = get_current_time();
    if (current_time >= entries[idx].timestamp
        && current_time - entries[idx].timestamp > SESSION_MAX_AGE_SECONDS) {
        ssl_debug::log_verbose("Session cache: expired entry for %s\n", hostname);
        entries[idx].valid = false;
        return false;
    }

    /* Update timestamp on access for proper LRU eviction */
    entries[idx].timestamp = current_time;
    memcpy(params, &entries[idx].params, sizeof(br_ssl_session_parameters));
    ssl_debug::log_info("Session cache: hit for %s\n", hostname);
    return true;
}

void session_cache::store(const char* hostname, const br_ssl_session_parameters* params)
{
    if (!initialized) initialize();

    // Don't cache if no session ID and no session ticket
    if (params->session_id_len == 0 && params->session_ticket_len == 0) {
        return;
    }

    int idx = find_entry(hostname);
    if (idx < 0) {
        idx = find_free_slot();
    }

    strncpy(entries[idx].hostname, hostname, 255);
    entries[idx].hostname[255] = '\0';
    memcpy(&entries[idx].params, params, sizeof(br_ssl_session_parameters));
    entries[idx].timestamp = get_current_time();
    entries[idx].valid = true;

    ssl_debug::log_info("Session cache: stored session for %s\n", hostname);
}

void session_cache::remove(const char* hostname)
{
    int idx = find_entry(hostname);
    if (idx >= 0) {
        entries[idx].valid = false;
        ssl_debug::log_verbose("Session cache: removed entry for %s\n", hostname);
    }
}

void session_cache::clear()
{
    memset(entries, 0, sizeof(entries));
    ssl_debug::log_verbose("Session cache: cleared\n");
}

int session_cache::get_count()
{
    int count = 0;
    for (int i = 0; i < SESSION_CACHE_SIZE; i++) {
        if (entries[i].valid) count++;
    }
    return count;
}
