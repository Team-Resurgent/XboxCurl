#include "ssl_debug.h"
#include "ssl_errors.h"
#include "debug_utility.h"

#include <stdio.h>
#include <stdarg.h>
#include <bearssl.h>

ssl_debug_level ssl_debug::current_level = SSL_DEBUG_ERROR;

void ssl_debug::set_level(ssl_debug_level level)
{
    current_level = level;
}

ssl_debug_level ssl_debug::get_level()
{
    return current_level;
}

void ssl_debug::log_error(const char* format, ...)
{
    if (current_level < SSL_DEBUG_ERROR) return;

    debug_log("[SSL ERROR] ");
    va_list args;
    va_start(args, format);
    char buffer[256];
    _vsnprintf(buffer, sizeof(buffer) - 1, format, args);
    buffer[sizeof(buffer) - 1] = '\0';
    va_end(args);
    debug_log("%s", buffer);
}

void ssl_debug::log_info(const char* format, ...)
{
    if (current_level < SSL_DEBUG_INFO) return;

    debug_log("[SSL] ");
    va_list args;
    va_start(args, format);
    char buffer[256];
    _vsnprintf(buffer, sizeof(buffer) - 1, format, args);
    buffer[sizeof(buffer) - 1] = '\0';
    va_end(args);
    debug_log("%s", buffer);
}

void ssl_debug::log_verbose(const char* format, ...)
{
    if (current_level < SSL_DEBUG_VERBOSE) return;

    debug_log("[SSL DEBUG] ");
    va_list args;
    va_start(args, format);
    char buffer[256];
    _vsnprintf(buffer, sizeof(buffer) - 1, format, args);
    buffer[sizeof(buffer) - 1] = '\0';
    va_end(args);
    debug_log("%s", buffer);
}

const char* ssl_debug::version_to_string(unsigned version)
{
    switch (version) {
        case BR_TLS10: return "TLS 1.0";
        case BR_TLS11: return "TLS 1.1";
        case BR_TLS12: return "TLS 1.2";
        default: return "Unknown";
    }
}

const char* ssl_debug::cipher_suite_to_string(uint16_t suite)
{
    switch (suite) {
        case BR_TLS_RSA_WITH_AES_128_CBC_SHA:
            return "RSA-AES128-CBC-SHA";
        case BR_TLS_RSA_WITH_AES_256_CBC_SHA:
            return "RSA-AES256-CBC-SHA";
        case BR_TLS_RSA_WITH_AES_128_CBC_SHA256:
            return "RSA-AES128-CBC-SHA256";
        case BR_TLS_RSA_WITH_AES_256_CBC_SHA256:
            return "RSA-AES256-CBC-SHA256";
        case BR_TLS_RSA_WITH_AES_128_GCM_SHA256:
            return "RSA-AES128-GCM-SHA256";
        case BR_TLS_RSA_WITH_AES_256_GCM_SHA384:
            return "RSA-AES256-GCM-SHA384";
        case BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
            return "ECDHE-RSA-AES128-CBC-SHA";
        case BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
            return "ECDHE-RSA-AES256-CBC-SHA";
        case BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
            return "ECDHE-RSA-AES128-CBC-SHA256";
        case BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
            return "ECDHE-RSA-AES256-CBC-SHA384";
        case BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            return "ECDHE-RSA-AES128-GCM-SHA256";
        case BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            return "ECDHE-RSA-AES256-GCM-SHA384";
        case BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            return "ECDHE-RSA-CHACHA20-POLY1305";
        case BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            return "ECDHE-ECDSA-AES128-GCM-SHA256";
        case BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
            return "ECDHE-ECDSA-AES256-GCM-SHA384";
        case BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return "ECDHE-ECDSA-CHACHA20-POLY1305";
        default:
            return "Unknown";
    }
}

void ssl_debug::log_handshake_result(br_ssl_engine_context* engine)
{
    if (current_level < SSL_DEBUG_INFO) return;

    unsigned version = br_ssl_engine_get_version(engine);
    log_info("Handshake complete\n");
    log_info("  Version: %s\n", version_to_string(version));

    br_ssl_session_parameters params;
    br_ssl_engine_get_session_parameters(engine, &params);
    log_info("  Cipher: %s\n", cipher_suite_to_string(params.cipher_suite));
    log_info("  Session resumed: %s\n", params.session_id_len > 0 ? "yes" : "no");
}

void ssl_debug::log_ssl_error(int error)
{
    if (error == 0) return;

    log_error("SSL error %d: %s\n", error, ssl_errors::error_to_string(error));

    if (error >= 256 && error < 512) {
        int alert = error - 256;
        log_error("  Alert: %s\n", ssl_errors::alert_to_string(alert));
    }
}

void ssl_debug::log_peer_certificate(br_ssl_engine_context* engine)
{
    // Note: BearSSL does not provide a direct API to retrieve the peer certificate
    // chain after handshake completion. Certificate inspection would require
    // custom X.509 callbacks during validation. This function is a placeholder.
    if (current_level < SSL_DEBUG_VERBOSE) return;
    log_verbose("Certificate inspection not available (requires X.509 callback)\n");
    (void)engine;  // Suppress unused parameter warning
}
