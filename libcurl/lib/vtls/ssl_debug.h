#pragma once

#include <bearssl.h>

enum ssl_debug_level {
    SSL_DEBUG_NONE = 0,
    SSL_DEBUG_ERROR = 1,
    SSL_DEBUG_INFO = 2,
    SSL_DEBUG_VERBOSE = 3
};

class ssl_debug
{
public:
    static void set_level(ssl_debug_level level);
    static ssl_debug_level get_level();

    static void log_error(const char* format, ...);
    static void log_info(const char* format, ...);
    static void log_verbose(const char* format, ...);

    static void log_handshake_result(br_ssl_engine_context* engine);
    static void log_ssl_error(int error);
    static void log_peer_certificate(br_ssl_engine_context* engine);

    static const char* version_to_string(unsigned version);
    static const char* cipher_suite_to_string(uint16_t suite);

private:
    static ssl_debug_level current_level;
};
