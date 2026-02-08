#pragma once

#include <bearssl.h>

#define SESSION_CACHE_SIZE 8
#define SESSION_MAX_AGE_SECONDS 3600

class session_cache
{
public:
    static void initialize();
    static void shutdown();

    static bool get(const char* hostname, br_ssl_session_parameters* params);
    static void store(const char* hostname, const br_ssl_session_parameters* params);
    static void remove(const char* hostname);
    static void clear();

    static int get_count();

private:
    struct session_entry {
        char hostname[256];
        br_ssl_session_parameters params;
        uint32_t timestamp;
        bool valid;
    };

    static session_entry entries[SESSION_CACHE_SIZE];
    static bool initialized;

    static int find_entry(const char* hostname);
    static int find_free_slot();
    static uint32_t get_current_time();
};
