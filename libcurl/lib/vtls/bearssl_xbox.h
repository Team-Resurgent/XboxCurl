/*
 * BearSSL Xbox Integration Header
 * C-compatible wrappers for Xbox-specific SSL functionality
 *
 * This provides a C interface to the C++ classes for use by libcurl's bearssl.c
 */

#ifndef BEARSSL_XBOX_H
#define BEARSSL_XBOX_H

#include <bearssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Default CA bundle path on Xbox HDD.
 * T:\ maps to E:\TDATA\<TitleID>\ (title-persistent storage).
 * Drop cacert.pem there to use updated root CAs without recompiling.
 */
#define BEARSSL_XBOX_DEFAULT_CA_FILE "T:\\cacert.pem"

/*
 * Trust Anchor Management
 * Wraps certificates.cpp functionality
 */
void bearssl_xbox_init_trust_anchors(void);
void bearssl_xbox_cleanup_trust_anchors(void);
br_x509_trust_anchor* bearssl_xbox_get_trust_anchors(void);
size_t bearssl_xbox_get_trust_anchor_count(void);

/*
 * Session Cache Management
 * Wraps session_cache.cpp functionality
 */
void bearssl_xbox_session_init(void);
void bearssl_xbox_session_shutdown(void);
int bearssl_xbox_session_get(const char* hostname, br_ssl_session_parameters* params);
void bearssl_xbox_session_store(const char* hostname, const br_ssl_session_parameters* params);
void bearssl_xbox_session_remove(const char* hostname);
void bearssl_xbox_session_clear(void);

/*
 * Error Message Utilities
 * Wraps ssl_errors.cpp functionality
 */
const char* bearssl_xbox_error_string(int error);
const char* bearssl_xbox_alert_string(int alert_code);

/*
 * CA Loader - Runtime PEM certificate loading
 * Wraps ca_loader.cpp functionality
 */
int  bearssl_xbox_load_ca_file(const char *path,
         br_x509_trust_anchor **anchors_out, size_t *count_out);
void bearssl_xbox_free_loaded_anchors(br_x509_trust_anchor *anchors,
         size_t count);

/*
 * CA Auto-Update
 * Downloads cacert.pem from curl.se if not already present on disk.
 * Uses the compiled-in trust anchors (must be initialized first).
 * Returns 0 on success (file existed or was downloaded), -1 on failure.
 */
int  bearssl_xbox_update_trust_store(void);

/*
 * Certificate Pinning
 * Wraps cert_pinning.cpp functionality
 */
void bearssl_xbox_pin_init(void);
void bearssl_xbox_pin_shutdown(void);
int  bearssl_xbox_pin_add(const char* hostname, const unsigned char* sha256_hash);
void bearssl_xbox_pin_remove(const char* hostname);
void bearssl_xbox_pin_clear(void);
int  bearssl_xbox_pin_has(const char* hostname);
int  bearssl_xbox_pin_verify_hash(const char* hostname, const unsigned char* cert_sha256);
int  bearssl_xbox_pin_get_hash(const char* hostname, unsigned char* hash_out);

#ifdef __cplusplus
}
#endif

#endif /* BEARSSL_XBOX_H */
