#pragma once

// TLS Version Configuration
#define SSL_MIN_VERSION BR_TLS12
#define SSL_MAX_VERSION BR_TLS12

// Secure cipher suites (ECDHE + AEAD only)
static const uint16_t SSL_SECURE_SUITES[] = {
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
};

#define SSL_SECURE_SUITES_COUNT 6

// Feature flags
#define SSL_ENFORCE_TLS12       1
#define SSL_RESTRICT_CIPHERS    1
#define SSL_ENABLE_SESSION_CACHE 1

// Set to 1 to enable certificate pinning verification
#define SSL_ENABLE_CERT_PINNING 0

// Default CA bundle file path on Xbox HDD
// T:\ maps to E:\TDATA\<TitleID>\ (title-persistent storage)
// Place cacert.pem at E:\TDATA\<YourTitleID>\cacert.pem on the Xbox HDD
#define SSL_DEFAULT_CA_FILE "T:\\cacert.pem"
