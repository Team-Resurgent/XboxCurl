/*
 * BearSSL Xbox Integration Implementation
 * C-compatible wrappers for Xbox-specific SSL functionality
 */

#include "bearssl_xbox.h"
#include "certificates.h"
#include "ca_loader.h"
#include "session_cache.h"
#include "ssl_errors.h"
#include "cert_pinning.h"

extern "C" {

/*
 * Trust Anchor Management
 */
void bearssl_xbox_init_trust_anchors(void)
{
    certificates::initialize_trust_anchors();
}

void bearssl_xbox_cleanup_trust_anchors(void)
{
    certificates::close_trust_anchors();
}

br_x509_trust_anchor* bearssl_xbox_get_trust_anchors(void)
{
    return certificates::get_trust_anchors();
}

size_t bearssl_xbox_get_trust_anchor_count(void)
{
    return (size_t)certificates::get_num_trust_anchors();
}

/*
 * Session Cache Management
 */
void bearssl_xbox_session_init(void)
{
    session_cache::initialize();
}

void bearssl_xbox_session_shutdown(void)
{
    session_cache::shutdown();
}

int bearssl_xbox_session_get(const char* hostname, br_ssl_session_parameters* params)
{
    return session_cache::get(hostname, params) ? 1 : 0;
}

void bearssl_xbox_session_store(const char* hostname, const br_ssl_session_parameters* params)
{
    session_cache::store(hostname, params);
}

void bearssl_xbox_session_remove(const char* hostname)
{
    session_cache::remove(hostname);
}

void bearssl_xbox_session_clear(void)
{
    session_cache::clear();
}

/*
 * Error Message Utilities
 */
const char* bearssl_xbox_error_string(int error)
{
    return ssl_errors::error_to_string(error);
}

const char* bearssl_xbox_alert_string(int alert_code)
{
    return ssl_errors::alert_to_string(alert_code);
}

/*
 * CA Loader
 */
int bearssl_xbox_load_ca_file(const char *path,
    br_x509_trust_anchor **anchors_out, size_t *count_out)
{
    return ca_loader::load_pem_file(path, anchors_out, count_out);
}

void bearssl_xbox_free_loaded_anchors(br_x509_trust_anchor *anchors,
    size_t count)
{
    ca_loader::free_trust_anchors(anchors, count);
}

int bearssl_xbox_update_trust_store(void)
{
    return ca_loader::update_trust_store(
        BEARSSL_XBOX_DEFAULT_CA_FILE,
        certificates::get_trust_anchors(),
        (size_t)certificates::get_num_trust_anchors());
}

/*
 * Certificate Pinning
 */
void bearssl_xbox_pin_init(void)
{
    cert_pinning::initialize();
}

void bearssl_xbox_pin_shutdown(void)
{
    cert_pinning::shutdown();
}

int bearssl_xbox_pin_add(const char* hostname, const unsigned char* sha256_hash)
{
    return cert_pinning::add_pin(hostname, sha256_hash) ? 1 : 0;
}

void bearssl_xbox_pin_remove(const char* hostname)
{
    cert_pinning::remove_pin(hostname);
}

void bearssl_xbox_pin_clear(void)
{
    cert_pinning::clear();
}

int bearssl_xbox_pin_has(const char* hostname)
{
    return cert_pinning::has_pin(hostname) ? 1 : 0;
}

int bearssl_xbox_pin_verify_hash(const char* hostname, const unsigned char* cert_sha256)
{
    return cert_pinning::verify_hash(hostname, cert_sha256) ? 1 : 0;
}

int bearssl_xbox_pin_get_hash(const char* hostname, unsigned char* hash_out)
{
    return cert_pinning::get_pin_hash(hostname, hash_out) ? 1 : 0;
}

} /* extern "C" */
