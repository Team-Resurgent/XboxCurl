/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * BearSSL TLS backend for libcurl
 * Designed for Xbox (Visual Studio 2003 / C89 compatible)
 *
 * This file implements the libcurl vtls interface using BearSSL.
 * BearSSL is ideal for Xbox because:
 * - Written in C89/C90 (VS 2003 compatible)
 * - No dynamic memory allocation
 * - Small footprint
 * - No external dependencies
 *
 * Xbox-specific enhancements:
 * - Trust anchors loaded from embedded CA database (750+ CAs)
 * - Session caching for TLS resumption
 * - Descriptive error messages
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_BEARSSL

#include <bearssl.h>

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "vtls.h"
#include "connect.h"
#include "select.h"
#include "multiif.h"

/* Xbox-specific BearSSL integration */
#ifdef _XBOX
#include "bearssl_xbox.h"
#define BEARSSL_XBOX_INTEGRATION 1
#else
#define BEARSSL_XBOX_INTEGRATION 0
#endif

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Xbox time validation callback for X.509 certificate checking.
 *
 * The Xbox's internal RTC is unreliable: no NTP (Xbox Live for original Xbox
 * is defunct), CMOS battery may be dead after 20+ years, and the clock can
 * reset to 2000-01-01 or similar. A wrong system clock causes BearSSL's
 * time(NULL)-based date validation to reject perfectly valid certificates.
 *
 * We skip date validation entirely. Trust anchor verification and optional
 * certificate pinning provide the real security guarantees.
 *
 * Return: 0 = within validity period (always)
 */
#ifdef _XBOX
static int bearssl_xbox_time_check(void *tctx,
    uint32_t not_before_days, uint32_t not_before_seconds,
    uint32_t not_after_days, uint32_t not_after_seconds)
{
  (void)tctx;
  (void)not_before_days;
  (void)not_before_seconds;
  (void)not_after_days;
  (void)not_after_seconds;
  return 0;
}
#endif

/* Secure cipher suites - ECDHE with AEAD only */
static const uint16_t bearssl_secure_suites[] = {
  BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
};
#define BEARSSL_SECURE_SUITES_COUNT 6

/*
 * ALPN protocol names for HTTP/1.1
 *
 * ALPN (Application-Layer Protocol Negotiation) is a TLS extension that allows
 * the client and server to negotiate which application protocol to use over
 * the encrypted connection. Modern HTTPS servers (especially CDNs like
 * Cloudflare) require ALPN to be present in the TLS handshake.
 *
 * Without ALPN, many servers will:
 * - Reject the connection outright
 * - Assume HTTP/2 and fail when receiving HTTP/1.1
 * - Reset the connection after handshake completes
 *
 * We advertise "http/1.1" since this libcurl build doesn't support HTTP/2.
 */
static const char *bearssl_alpn_protocols[] = { "http/1.1" };
#define BEARSSL_ALPN_PROTOCOLS_COUNT 1

/*
 * "No Anchor" X509 validator - wraps br_x509_minimal but accepts all certs.
 *
 * This approach uses BearSSL's proven certificate parsing code (br_x509_minimal)
 * but overrides the validation result to always succeed. This is safer than
 * implementing our own certificate decoder.
 *
 * Used when SSL_VERIFYPEER is disabled.
 *
 * NOTE: We use a POINTER to the minimal context (not embedded) to avoid
 * memory layout issues with the union in ssl_backend_data.
 */
typedef struct {
  const br_x509_class *vtable;
  br_x509_minimal_context *minimal;  /* Pointer to minimal validator */
  /* Certificate pinning: hash the leaf (first) certificate */
  br_sha256_context pin_sha256;      /* SHA-256 running hash of leaf cert */
  unsigned char leaf_hash[32];       /* Final SHA-256 of leaf certificate */
  int cert_index;                    /* 0 = leaf cert, increments per cert */
  int leaf_hash_valid;               /* 1 if leaf_hash has been computed */
  char pin_hostname[256];            /* Hostname for pin lookup */
} br_x509_noanchor_context;

/* Forward the call to minimal validator */
static void xc_noanchor_start_chain(const br_x509_class **ctx,
    const char *server_name)
{
  br_x509_noanchor_context *xc = (br_x509_noanchor_context *)ctx;
#ifdef _XBOX
  {
    char dbg[256];
    msnprintf(dbg, sizeof(dbg),
      "BearSSL noanchor X509: start_chain called, ctx=%p, xc=%p, minimal=%p\n",
      (void*)ctx, (void*)xc, (void*)xc->minimal);
    OutputDebugStringA(dbg);
    if(xc->minimal) {
      msnprintf(dbg, sizeof(dbg),
        "BearSSL noanchor X509: server=%s, minimal->vtable=%p\n",
        server_name ? server_name : "(null)",
        (void*)xc->minimal->vtable);
      OutputDebugStringA(dbg);
    }
  }
#endif
  if(!xc->minimal || !xc->minimal->vtable) {
    OutputDebugStringA("BearSSL noanchor X509: ERROR - minimal or vtable is NULL!\n");
    return;
  }

  /* Reset pinning state for this new chain */
  xc->cert_index = 0;
  xc->leaf_hash_valid = 0;
  memset(xc->leaf_hash, 0, sizeof(xc->leaf_hash));
  if(server_name) {
    strncpy(xc->pin_hostname, server_name, sizeof(xc->pin_hostname) - 1);
    xc->pin_hostname[sizeof(xc->pin_hostname) - 1] = '\0';
  }
  else {
    xc->pin_hostname[0] = '\0';
  }

  xc->minimal->vtable->start_chain(&xc->minimal->vtable, server_name);
  OutputDebugStringA("BearSSL noanchor X509: start_chain forwarded OK\n");
}

static void xc_noanchor_start_cert(const br_x509_class **ctx, uint32_t length)
{
  br_x509_noanchor_context *xc = (br_x509_noanchor_context *)ctx;
#ifdef _XBOX
  {
    char dbg[128];
    msnprintf(dbg, sizeof(dbg), "BearSSL noanchor X509: start_cert[%d], length=%u\n",
              xc->cert_index, (unsigned)length);
    OutputDebugStringA(dbg);
  }
#endif
  /* For the leaf certificate (index 0), start hashing for pin check */
  if(xc->cert_index == 0) {
    br_sha256_init(&xc->pin_sha256);
  }
  xc->minimal->vtable->start_cert(&xc->minimal->vtable, length);
}

static void xc_noanchor_append(const br_x509_class **ctx,
    const unsigned char *buf, size_t len)
{
  br_x509_noanchor_context *xc = (br_x509_noanchor_context *)ctx;
  /* Feed leaf certificate bytes into SHA-256 for pinning */
  if(xc->cert_index == 0) {
    br_sha256_update(&xc->pin_sha256, buf, len);
  }
  xc->minimal->vtable->append(&xc->minimal->vtable, buf, len);
}

static void xc_noanchor_end_cert(const br_x509_class **ctx)
{
  br_x509_noanchor_context *xc = (br_x509_noanchor_context *)ctx;
#ifdef _XBOX
  {
    char dbg[64];
    msnprintf(dbg, sizeof(dbg), "BearSSL noanchor X509: end_cert[%d]\n",
              xc->cert_index);
    OutputDebugStringA(dbg);
  }
#endif
  xc->minimal->vtable->end_cert(&xc->minimal->vtable);

  /* Finalize the SHA-256 hash of the leaf certificate */
  if(xc->cert_index == 0) {
    br_sha256_out(&xc->pin_sha256, xc->leaf_hash);
    xc->leaf_hash_valid = 1;
#ifdef _XBOX
    {
      char dbg[128];
      msnprintf(dbg, sizeof(dbg),
        "BearSSL noanchor X509: leaf cert SHA-256: "
        "%02X%02X%02X%02X%02X%02X%02X%02X...\n",
        xc->leaf_hash[0], xc->leaf_hash[1],
        xc->leaf_hash[2], xc->leaf_hash[3],
        xc->leaf_hash[4], xc->leaf_hash[5],
        xc->leaf_hash[6], xc->leaf_hash[7]);
      OutputDebugStringA(dbg);
    }
#endif
  }
  xc->cert_index++;

#ifdef _XBOX
  /* Log the minimal validator's state after processing certificate */
  {
    char dbg[256];
    msnprintf(dbg, sizeof(dbg),
      "BearSSL noanchor X509: minimal->err=%d, pkey.key_type=%d\n",
      xc->minimal->err, xc->minimal->pkey.key_type);
    OutputDebugStringA(dbg);

    if(xc->minimal->pkey.key_type == BR_KEYTYPE_RSA) {
      msnprintf(dbg, sizeof(dbg),
        "BearSSL noanchor X509: RSA key - n=%p nlen=%u e=%p elen=%u\n",
        (void*)xc->minimal->pkey.key.rsa.n,
        (unsigned)xc->minimal->pkey.key.rsa.nlen,
        (void*)xc->minimal->pkey.key.rsa.e,
        (unsigned)xc->minimal->pkey.key.rsa.elen);
      OutputDebugStringA(dbg);
    }
    else if(xc->minimal->pkey.key_type == BR_KEYTYPE_EC) {
      msnprintf(dbg, sizeof(dbg),
        "BearSSL noanchor X509: EC key - curve=%d q=%p qlen=%u\n",
        xc->minimal->pkey.key.ec.curve,
        (void*)xc->minimal->pkey.key.ec.q,
        (unsigned)xc->minimal->pkey.key.ec.qlen);
      OutputDebugStringA(dbg);
    }
  }
#endif
}

static unsigned xc_noanchor_end_chain(const br_x509_class **ctx)
{
  br_x509_noanchor_context *xc = (br_x509_noanchor_context *)ctx;
  unsigned result;

  /* Call the minimal validator's end_chain */
  result = xc->minimal->vtable->end_chain(&xc->minimal->vtable);

#ifdef _XBOX
  {
    char dbg[128];
    msnprintf(dbg, sizeof(dbg),
      "BearSSL noanchor X509: end_chain, minimal returned %u (err=%d)\n",
      result, xc->minimal->err);
    OutputDebugStringA(dbg);
  }
#endif

  /*
   * Override the result: accept certificates in insecure mode.
   *
   * When SSL_VERIFYPEER is disabled, we accept all validation errors:
   * - BR_ERR_X509_OK (32) - success
   * - BR_ERR_X509_EXPIRED (54) - certificate expired or not yet valid
   * - BR_ERR_X509_DN_MISMATCH (55) - issuer/subject DN mismatch
   * - BR_ERR_X509_BAD_SERVER_NAME (56) - server name doesn't match cert
   * - BR_ERR_X509_NOT_TRUSTED (62) - no matching trust anchor
   *
   * We only fail on actual parsing errors (33-52) which indicate a
   * malformed certificate that cannot be used.
   */
  if(result == BR_ERR_X509_OK ||
     result == BR_ERR_X509_EXPIRED ||
     result == BR_ERR_X509_DN_MISMATCH ||
     result == BR_ERR_X509_BAD_SERVER_NAME ||
     result == BR_ERR_X509_CRITICAL_EXTENSION ||
     result == BR_ERR_X509_NOT_CA ||
     result == BR_ERR_X509_FORBIDDEN_KEY_USAGE ||
     result == BR_ERR_X509_WEAK_PUBLIC_KEY ||
     result == BR_ERR_X509_NOT_TRUSTED) {

    /*
     * Certificate pinning check: if a pin is registered for this hostname,
     * verify the leaf certificate hash matches. This runs even in insecure
     * mode because pinning is an explicit trust decision by the application.
     */
#if BEARSSL_XBOX_INTEGRATION
    if(xc->leaf_hash_valid && xc->pin_hostname[0] != '\0') {
      if(!bearssl_xbox_pin_verify_hash(xc->pin_hostname, xc->leaf_hash)) {
#ifdef _XBOX
        OutputDebugStringA("BearSSL noanchor X509: CERTIFICATE PIN MISMATCH - rejecting!\n");
#endif
        return BR_ERR_X509_NOT_TRUSTED;
      }
    }
#endif

#ifdef _XBOX
    {
      char dbg[128];
      msnprintf(dbg, sizeof(dbg),
        "BearSSL noanchor X509: accepting certificate (insecure mode, result=%u)\n",
        result);
      OutputDebugStringA(dbg);
    }
#endif
    return 0;  /* Success */
  }

  /* For actual parsing errors (bad certificate format, etc.), we still fail */
#ifdef _XBOX
  {
    char dbg[128];
    msnprintf(dbg, sizeof(dbg),
      "BearSSL noanchor X509: certificate parsing error %u\n", result);
    OutputDebugStringA(dbg);
  }
#endif
  return result;
}

static const br_x509_pkey *xc_noanchor_get_pkey(
    const br_x509_class *const *ctx, unsigned *usages)
{
  br_x509_noanchor_context *xc = (br_x509_noanchor_context *)ctx;
  const br_x509_pkey *pk;

  /* Get the public key from the minimal validator */
  pk = xc->minimal->vtable->get_pkey(&xc->minimal->vtable, usages);

#ifdef _XBOX
  {
    char dbg[128];
    msnprintf(dbg, sizeof(dbg),
      "BearSSL noanchor X509: get_pkey returned %p (err=%d, key_type=%d)\n",
      (void*)pk, xc->minimal->err, xc->minimal->pkey.key_type);
    OutputDebugStringA(dbg);
  }
#endif

  /*
   * The minimal validator only returns the key if err is OK (32) or
   * NOT_TRUSTED (62). For other validation errors like BAD_SERVER_NAME (56),
   * EXPIRED (54), etc., it returns NULL even though the key was parsed.
   *
   * In insecure mode, we need to return the key for any validation error
   * as long as the key itself was successfully parsed.
   */
  if(!pk) {
    /*
     * Minimal validator didn't return key. Check if the key was parsed
     * successfully - if so, return it directly. This handles validation
     * errors like BAD_SERVER_NAME where the cert is valid but doesn't
     * match requirements we're choosing to ignore.
     */
    if(xc->minimal->pkey.key_type == BR_KEYTYPE_RSA ||
       xc->minimal->pkey.key_type == BR_KEYTYPE_EC) {
#ifdef _XBOX
      {
        char dbg[128];
        msnprintf(dbg, sizeof(dbg),
          "BearSSL noanchor X509: returning key directly (err=%d bypassed)\n",
          xc->minimal->err);
        OutputDebugStringA(dbg);
      }
#endif
      if(usages)
        *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
      return &xc->minimal->pkey;
    }
#ifdef _XBOX
    OutputDebugStringA("BearSSL noanchor X509: ERROR - no valid key available!\n");
#endif
  }

  return pk;
}

static const br_x509_class br_x509_noanchor_vtable = {
  sizeof(br_x509_noanchor_context),
  xc_noanchor_start_chain,
  xc_noanchor_start_cert,
  xc_noanchor_append,
  xc_noanchor_end_cert,
  xc_noanchor_end_chain,
  xc_noanchor_get_pkey
};

/*
 * Legacy insecure validator kept for reference but not used.
 * The noanchor approach above is preferred.
 */
#if 0  /* DISABLED - using noanchor instead */

typedef struct {
  const br_x509_class *vtable;
  br_x509_decoder_context decoder;
  br_x509_pkey pkey;
  unsigned char pkey_data[BR_EC_KBUF_PUB_MAX_SIZE];
  unsigned char rsa_n[512];
  unsigned char rsa_e[8];
  int first_cert;
  int pkey_valid;
  uint32_t expected_len;
  uint32_t received_len;
} br_x509_insecure_context;

static void xc_insecure_start_chain(const br_x509_class **ctx,
    const char *server_name)
{
  br_x509_insecure_context *xc = (br_x509_insecure_context *)ctx;
  (void)server_name;
  xc->first_cert = 1;
  xc->pkey_valid = 0;
}

/* ... rest of insecure implementation ... */

#endif /* DISABLED */

/* BearSSL backend data structure */
struct ssl_backend_data {
  br_ssl_client_context sc;
  br_x509_minimal_context xc_minimal;    /* Minimal X509 validator */
  br_x509_noanchor_context xc_noanchor;  /* Noanchor wrapper (small, just vtable + pointer) */
  int using_noanchor;   /* Are we using the noanchor (no-verify) validator? */
  unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
  br_sslio_context ioc;
  int active;           /* Is the SSL connection active? */
  int session_resumed;  /* Was session resumed? */
  unsigned char resume_master_secret[48]; /* Master secret from resume attempt */
  int io_error;         /* Have we had a socket I/O error? Skip graceful close if so */
  unsigned char leaf_cert_hash[32];  /* SHA-256 of leaf cert (from X.509 callback) */
  int leaf_cert_hash_valid;          /* 1 if hash was captured */
  char hostname[256];   /* Hostname for session caching */
#if BEARSSL_XBOX_INTEGRATION
  br_x509_trust_anchor *file_anchors;  /* Per-connection CAs from CURLOPT_CAINFO */
  size_t file_anchor_count;
#endif
};

#define BACKEND connssl->backend

/* Forward declarations for send/recv functions */
static Curl_recv bearssl_recv;
static Curl_send bearssl_send;

/* Global state for trust anchor initialization */
static int bearssl_trust_anchors_loaded = 0;
#if BEARSSL_XBOX_INTEGRATION
static int bearssl_trust_store_updated = 0;
#endif

/* Low-level socket read callback for BearSSL */
static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
  curl_socket_t fd = *(curl_socket_t *)ctx;
  ssize_t rlen;

  /*
   * Simple blocking read - no retry loop.
   * The socket should already be in blocking mode, and libcurl manages
   * timeouts at a higher level. We just do a single recv() call.
   */
  rlen = recv(fd, (char *)buf, (int)len, 0);

  if(rlen > 0) {
    /* Success - got data */
#ifdef BEARSSL_VERBOSE_DEBUG
    {
      char dbg[64];
      msnprintf(dbg, sizeof(dbg), "BearSSL sock_read: got %d bytes\n", (int)rlen);
      OutputDebugStringA(dbg);
    }
#endif
    return (int)rlen;
  }

  if(rlen == 0) {
    /* Connection closed by peer */
#ifdef BEARSSL_VERBOSE_DEBUG
    OutputDebugStringA("BearSSL sock_read: connection closed by peer\n");
#endif
    return -1;
  }

  /* rlen < 0 - error */
  {
    int err = SOCKERRNO;
#ifdef BEARSSL_VERBOSE_DEBUG
    {
      char dbg[64];
      msnprintf(dbg, sizeof(dbg), "BearSSL sock_read: recv error %d\n", err);
      OutputDebugStringA(dbg);
    }
#endif

    /* For EINTR, we could retry, but it's simpler to let the caller handle it */
    if(err == EWOULDBLOCK || err == EAGAIN) {
      /* Would block - return 0 to indicate no data available yet */
      /* BearSSL will handle this appropriately */
      return 0;
    }

    /* Real error - return -1 */
    return -1;
  }
}

/* Low-level socket write callback for BearSSL */
static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
  curl_socket_t fd = *(curl_socket_t *)ctx;
  ssize_t wlen;

  /*
   * Simple blocking write - no retry loop.
   * The socket should already be in blocking mode, and libcurl manages
   * timeouts at a higher level. We just do a single send() call.
   */
  wlen = send(fd, (const char *)buf, (int)len, 0);

  if(wlen > 0) {
    /* Success - data sent */
#ifdef BEARSSL_VERBOSE_DEBUG
    {
      char dbg[64];
      msnprintf(dbg, sizeof(dbg), "BearSSL sock_write: sent %d bytes\n", (int)wlen);
      OutputDebugStringA(dbg);
    }
#endif
    return (int)wlen;
  }

  if(wlen == 0) {
    /* No data sent - treat as would-block */
    return 0;
  }

  /* wlen < 0 - error */
  {
    int err = SOCKERRNO;
#ifdef BEARSSL_VERBOSE_DEBUG
    {
      char dbg[64];
      msnprintf(dbg, sizeof(dbg), "BearSSL sock_write: send error %d\n", err);
      OutputDebugStringA(dbg);
    }
#endif

    if(err == EWOULDBLOCK || err == EAGAIN) {
      /* Would block - return 0 to indicate no data sent yet */
      return 0;
    }

    /* Real error - return -1 */
    return -1;
  }
}

/* Get descriptive error message for BearSSL error code */
static const char *
bearssl_error_string(int err)
{
#if BEARSSL_XBOX_INTEGRATION
  return bearssl_xbox_error_string(err);
#else
  /* Fallback error messages for non-Xbox builds */
  switch(err) {
  case BR_ERR_OK: return "Success";
  case BR_ERR_BAD_PARAM: return "Bad parameter";
  case BR_ERR_BAD_STATE: return "Invalid state";
  case BR_ERR_UNSUPPORTED_VERSION: return "Unsupported TLS version";
  case BR_ERR_BAD_VERSION: return "Bad TLS version";
  case BR_ERR_TOO_LARGE: return "Record too large";
  case BR_ERR_BAD_MAC: return "MAC verification failed";
  case BR_ERR_NO_RANDOM: return "No random seed";
  case BR_ERR_UNKNOWN_TYPE: return "Unknown record type";
  case BR_ERR_UNEXPECTED: return "Unexpected message";
  case BR_ERR_BAD_CCS: return "Bad ChangeCipherSpec";
  case BR_ERR_BAD_ALERT: return "Bad alert";
  case BR_ERR_BAD_HANDSHAKE: return "Bad handshake message";
  case BR_ERR_OVERSIZED_ID: return "Oversized ID";
  case BR_ERR_BAD_CIPHER_SUITE: return "Bad cipher suite";
  case BR_ERR_BAD_COMPRESSION: return "Bad compression";
  case BR_ERR_BAD_FRAGLEN: return "Bad fragment length";
  case BR_ERR_BAD_SECRENEG: return "Bad secure renegotiation";
  case BR_ERR_EXTRA_EXTENSION: return "Extra extension";
  case BR_ERR_BAD_SNI: return "Bad SNI";
  case BR_ERR_BAD_HELLO_DONE: return "Bad HelloDone";
  case BR_ERR_LIMIT_EXCEEDED: return "Limit exceeded";
  case BR_ERR_BAD_FINISHED: return "Bad Finished message";
  case BR_ERR_RESUME_MISMATCH: return "Session resume mismatch";
  case BR_ERR_INVALID_ALGORITHM: return "Invalid algorithm";
  case BR_ERR_BAD_SIGNATURE: return "Bad signature";
  case BR_ERR_WRONG_KEY_USAGE: return "Wrong key usage";
  case BR_ERR_NO_CLIENT_AUTH: return "No client auth";
  case BR_ERR_IO: return "I/O error";
  default:
    if(err >= 256 && err < 512)
      return "Received fatal alert from server";
    if(err >= 512)
      return "Sent fatal alert to server";
    return "Unknown SSL error";
  }
#endif
}

static int Curl_bearssl_init(void)
{
#if BEARSSL_XBOX_INTEGRATION
  /* Initialize trust anchors from Xbox certificate store */
  if(!bearssl_trust_anchors_loaded) {
    bearssl_xbox_init_trust_anchors();
    bearssl_xbox_session_init();
    bearssl_trust_anchors_loaded = 1;
  }
#endif
  return 1;
}

static void Curl_bearssl_cleanup(void)
{
#if BEARSSL_XBOX_INTEGRATION
  if(bearssl_trust_anchors_loaded) {
    bearssl_xbox_session_shutdown();
    bearssl_xbox_cleanup_trust_anchors();
    bearssl_trust_anchors_loaded = 0;
    bearssl_trust_store_updated = 0;
  }
#endif
}

static size_t Curl_bearssl_version(char *buffer, size_t size)
{
  return msnprintf(buffer, size, "BearSSL/0.6-Xbox");
}

static CURLcode Curl_bearssl_random(struct Curl_easy *data,
                                    unsigned char *entropy, size_t length)
{
  br_hmac_drbg_context rng;
  br_prng_seeder seeder;

  (void)data;

  seeder = br_prng_seeder_system(NULL);
  if(!seeder) {
    return CURLE_SSL_CONNECT_ERROR;
  }

  br_hmac_drbg_init(&rng, &br_sha256_vtable, NULL, 0);
  if(!seeder(&rng.vtable)) {
    return CURLE_SSL_CONNECT_ERROR;
  }

  br_hmac_drbg_generate(&rng, entropy, length);
  return CURLE_OK;
}

static CURLcode
bearssl_connect_step1(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  const char *hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
                                          conn->host.name;
  br_x509_trust_anchor *trust_anchors = NULL;
  size_t trust_anchor_count = 0;
  int session_resume = 0;
#if BEARSSL_XBOX_INTEGRATION
  br_ssl_session_parameters session_params;
#endif

  /*
   * NOTE: BACKEND memory is pre-allocated by the vtls layer in url.c as part
   * of a single contiguous block for all SSL contexts. We must NOT allocate
   * or free it ourselves - that would corrupt the heap.
   *
   * See url.c:allocate_conn() which does:
   *   conn->ssl[0].backend = (void *)ssl;
   *   conn->ssl[1].backend = (void *)(ssl + sslsize);
   *   conn->proxy_ssl[0].backend = (void *)(ssl + 2 * sslsize);
   *   conn->proxy_ssl[1].backend = (void *)(ssl + 3 * sslsize);
   */
  DEBUGASSERT(BACKEND != NULL);

#ifdef _XBOX
  {
    char dbg[128];
    msnprintf(dbg, sizeof(dbg),
      "BearSSL step1: Using pre-allocated backend at %p, size=%u bytes\n",
      (void*)BACKEND, (unsigned)sizeof(struct ssl_backend_data));
    OutputDebugStringA(dbg);
  }
#endif

  /* Clear the backend structure for fresh initialization */
  memset(BACKEND, 0, sizeof(struct ssl_backend_data));

  /* Store hostname for session caching */
  strncpy(BACKEND->hostname, hostname, sizeof(BACKEND->hostname) - 1);
  BACKEND->hostname[sizeof(BACKEND->hostname) - 1] = '\0';
  BACKEND->session_resumed = 0;

#if BEARSSL_XBOX_INTEGRATION
  /* Auto-download cacert.pem on first connection if not on disk.
   * Done here (not in Curl_bearssl_init) because XNet needs time
   * after DHCP before TCP connects work reliably. */
  if(!bearssl_trust_store_updated) {
    bearssl_trust_store_updated = 1;
    bearssl_xbox_update_trust_store();
  }
#endif

  /* Check if certificate verification is disabled */
  if(!SSL_CONN_CONFIG(verifypeer)) {
    /*
     * No verification - use the "noanchor" validator that wraps br_x509_minimal
     * but accepts all certificates. This leverages BearSSL's proven certificate
     * parsing code while bypassing the trust validation.
     */
    OutputDebugStringA("BearSSL: Certificate verification DISABLED - using noanchor validator\n");
    BACKEND->using_noanchor = 1;

#ifdef _XBOX
    {
      char dbg[512];
      msnprintf(dbg, sizeof(dbg),
        "BearSSL: BACKEND=%p, sizeof(ssl_backend_data)=%u\n",
        (void*)BACKEND, (unsigned)sizeof(struct ssl_backend_data));
      OutputDebugStringA(dbg);
      msnprintf(dbg, sizeof(dbg),
        "BearSSL: sizeof(br_ssl_client_context)=%u\n",
        (unsigned)sizeof(br_ssl_client_context));
      OutputDebugStringA(dbg);
      msnprintf(dbg, sizeof(dbg),
        "BearSSL: sizeof(br_x509_minimal_context)=%u\n",
        (unsigned)sizeof(br_x509_minimal_context));
      OutputDebugStringA(dbg);
      msnprintf(dbg, sizeof(dbg),
        "BearSSL: &BACKEND->sc=%p, &BACKEND->xc_minimal=%p\n",
        (void*)&BACKEND->sc, (void*)&BACKEND->xc_minimal);
      OutputDebugStringA(dbg);
    }
#endif

    OutputDebugStringA("BearSSL: Calling br_ssl_client_init_full...\n");

    /*
     * Initialize the SSL client with the minimal X509 validator.
     * We pass NULL trust anchors - the minimal validator will fail with
     * NOT_TRUSTED, but our noanchor wrapper overrides that to accept anyway.
     */
    br_ssl_client_init_full(&BACKEND->sc, &BACKEND->xc_minimal, NULL, 0);

    OutputDebugStringA("BearSSL: br_ssl_client_init_full done\n");

#ifdef _XBOX
    {
      char dbg[256];
      msnprintf(dbg, sizeof(dbg),
        "BearSSL: xc_minimal at %p, xc_minimal.vtable = %p\n",
        (void*)&BACKEND->xc_minimal,
        (void*)BACKEND->xc_minimal.vtable);
      OutputDebugStringA(dbg);
    }
#endif

    /* Set up the noanchor wrapper to point to the minimal validator */
    BACKEND->xc_noanchor.vtable = &br_x509_noanchor_vtable;
    BACKEND->xc_noanchor.minimal = &BACKEND->xc_minimal;

    OutputDebugStringA("BearSSL: Setting X509 engine to noanchor wrapper...\n");

#ifdef _XBOX
    {
      char dbg[256];
      msnprintf(dbg, sizeof(dbg),
        "BearSSL: xc_noanchor at %p, vtable=%p, minimal=%p\n",
        (void*)&BACKEND->xc_noanchor,
        (void*)BACKEND->xc_noanchor.vtable,
        (void*)BACKEND->xc_noanchor.minimal);
      OutputDebugStringA(dbg);
    }
#endif

    /* Replace the X509 engine with our noanchor validator wrapper */
    br_ssl_engine_set_x509(&BACKEND->sc.eng, &BACKEND->xc_noanchor.vtable);
    OutputDebugStringA("BearSSL: Noanchor X509 validator installed\n");
  }
  else {
#if BEARSSL_XBOX_INTEGRATION
    {
      /* Check for CURLOPT_CAINFO or default Xbox CA path */
      const char *cafile = SSL_CONN_CONFIG(CAfile);

      /* If no explicit CA file, try the default Xbox TDATA path */
      if(!cafile || !cafile[0]) {
        cafile = BEARSSL_XBOX_DEFAULT_CA_FILE;
      }

      /* Try loading CA bundle from PEM file */
      if(bearssl_xbox_load_ca_file(cafile,
          &BACKEND->file_anchors, &BACKEND->file_anchor_count) == 0) {
        trust_anchors = BACKEND->file_anchors;
        trust_anchor_count = BACKEND->file_anchor_count;
        infof(data, "BearSSL: Loaded %zu trust anchors from %s\n",
              trust_anchor_count, cafile);
      }

      /* Fall back to compiled-in trust anchors */
      if(!trust_anchors) {
        trust_anchors = bearssl_xbox_get_trust_anchors();
        trust_anchor_count = bearssl_xbox_get_trust_anchor_count();
      }
    }

    if(!trust_anchors || trust_anchor_count == 0) {
      failf(data, "BearSSL: No trust anchors available for certificate verification");
      return CURLE_SSL_CACERT_BADFILE;
    }
    infof(data, "BearSSL: Using %zu trust anchors for verification\n",
          trust_anchor_count);
#else
    /* No trust anchors available - cannot verify */
    failf(data, "BearSSL: Certificate verification requested but no trust anchors available");
    return CURLE_SSL_CACERT_BADFILE;
#endif

    BACKEND->using_noanchor = 0;
    /* Initialize the BearSSL client context with trust anchors */
    br_ssl_client_init_full(&BACKEND->sc, &BACKEND->xc_minimal,
                            trust_anchors, trust_anchor_count);

#ifdef _XBOX
    /* Skip certificate date validation - Xbox clock is unreliable */
    br_x509_minimal_set_time_callback(&BACKEND->xc_minimal,
                                       NULL, bearssl_xbox_time_check);
#endif
  }

  OutputDebugStringA("BearSSL: Setting protocol versions...\n");

  /* Set protocol versions based on CURLOPT_SSLVERSION */
  {
    /*
     * Default to TLS 1.2 minimum for security.
     * TLS 1.0 and 1.1 are deprecated and have known vulnerabilities.
     */
    int min_ver = BR_TLS12;
    int max_ver = BR_TLS12;

    switch(SSL_CONN_CONFIG(version)) {
    case CURL_SSLVERSION_DEFAULT:
      /* Default: TLS 1.2 only (most compatible + secure) */
      min_ver = BR_TLS12;
      break;
    case CURL_SSLVERSION_TLSv1:
    case CURL_SSLVERSION_TLSv1_0:
      /* Allow TLS 1.0 if explicitly requested (legacy support) */
      min_ver = BR_TLS10;
      break;
    case CURL_SSLVERSION_TLSv1_1:
      min_ver = BR_TLS11;
      break;
    case CURL_SSLVERSION_TLSv1_2:
      min_ver = BR_TLS12;
      break;
    case CURL_SSLVERSION_TLSv1_3:
      /* BearSSL doesn't support TLS 1.3 */
      failf(data, "BearSSL does not support TLS 1.3");
      return CURLE_SSL_CONNECT_ERROR;
    default:
      failf(data, "Unsupported SSL version");
      return CURLE_SSL_CONNECT_ERROR;
    }

    br_ssl_engine_set_versions(&BACKEND->sc.eng, min_ver, max_ver);
  }
  OutputDebugStringA("BearSSL: Protocol versions set\n");

  /* Use secure cipher suites only */
  br_ssl_engine_set_suites(&BACKEND->sc.eng,
                           bearssl_secure_suites, BEARSSL_SECURE_SUITES_COUNT);
  OutputDebugStringA("BearSSL: Cipher suites set\n");

  /*
   * Set ALPN (Application-Layer Protocol Negotiation) protocols.
   *
   * This tells the server we want to speak HTTP/1.1. Without ALPN, modern
   * servers like Cloudflare may reset the connection after handshake because
   * they don't know what protocol the client expects.
   */
  br_ssl_engine_set_protocol_names(&BACKEND->sc.eng,
                                   bearssl_alpn_protocols,
                                   BEARSSL_ALPN_PROTOCOLS_COUNT);
  OutputDebugStringA("BearSSL: ALPN protocols set (http/1.1)\n");

  /* Set I/O buffer */
  br_ssl_engine_set_buffer(&BACKEND->sc.eng, BACKEND->iobuf,
                           sizeof(BACKEND->iobuf), 1);
  OutputDebugStringA("BearSSL: I/O buffer set\n");

#if BEARSSL_XBOX_INTEGRATION
  /* Try to resume previous session */
  if(bearssl_xbox_session_get(hostname, &session_params)) {
    br_ssl_engine_set_session_parameters(&BACKEND->sc.eng, &session_params);
    memcpy(BACKEND->resume_master_secret, session_params.master_secret, 48);
    session_resume = 1;
    infof(data, "BearSSL: Attempting session resumption for %s\n", hostname);
  }
#endif

  OutputDebugStringA("BearSSL: Calling br_ssl_client_reset...\n");

  /* Reset the client context for the new connection */
  br_ssl_client_reset(&BACKEND->sc, hostname, session_resume);

  OutputDebugStringA("BearSSL: br_ssl_client_reset done\n");

#ifdef _XBOX
  {
    char dbg[256];
    msnprintf(dbg, sizeof(dbg),
      "BearSSL step1: hostname=%s, socket=%d, sockindex=%d\n",
      hostname, (int)conn->sock[sockindex], sockindex);
    OutputDebugStringA(dbg);

    /* Verify socket is valid */
    if(conn->sock[sockindex] == CURL_SOCKET_BAD) {
      OutputDebugStringA("BearSSL step1: ERROR - socket is INVALID!\n");
    }
  }
#endif

  OutputDebugStringA("BearSSL: Calling br_sslio_init...\n");

  /* Initialize the I/O wrapper */
  br_sslio_init(&BACKEND->ioc, &BACKEND->sc.eng,
                sock_read, &conn->sock[sockindex],
                sock_write, &conn->sock[sockindex]);

  OutputDebugStringA("BearSSL: br_sslio_init done\n");

  /* Note: BACKEND->active is set in step3 after handshake completes */
  connssl->connecting_state = ssl_connect_2;

  OutputDebugStringA("BearSSL step1: complete, moving to step2\n");
  return CURLE_OK;
}

static CURLcode
bearssl_connect_step2(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  unsigned state;
  int err;

  state = br_ssl_engine_current_state(&BACKEND->sc.eng);

#ifdef _XBOX
  {
    static int step2_call_count = 0;
    char dbg[256];
    step2_call_count++;
    msnprintf(dbg, sizeof(dbg),
      "BearSSL step2 [%d]: state=0x%x (CLOSED=%d SENDREC=%d RECVREC=%d SENDAPP=%d)\n",
      step2_call_count, state,
      (state & BR_SSL_CLOSED) ? 1 : 0,
      (state & BR_SSL_SENDREC) ? 1 : 0,
      (state & BR_SSL_RECVREC) ? 1 : 0,
      (state & BR_SSL_SENDAPP) ? 1 : 0);
    OutputDebugStringA(dbg);
  }
#endif

  /* Check for errors */
  err = br_ssl_engine_last_error(&BACKEND->sc.eng);
  if(err != BR_ERR_OK) {
#ifdef _XBOX
    {
      char dbg[128];
      msnprintf(dbg, sizeof(dbg), "BearSSL step2: engine error %d\n", err);
      OutputDebugStringA(dbg);
    }
#endif
    failf(data, "BearSSL: %s (error %d)", bearssl_error_string(err), err);
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Check if handshake is complete */
  if(state & BR_SSL_SENDAPP) {
    /* Handshake complete, application data can be sent */
    connssl->connecting_state = ssl_connect_3;
    return CURLE_OK;
  }

  /* Handshake still in progress */
  if(state & BR_SSL_SENDREC) {
    /* Need to send data */
    int ret;
    OutputDebugStringA("BearSSL step2: flushing send buffer...\n");
    ret = br_sslio_flush(&BACKEND->ioc);
#ifdef _XBOX
    {
      char dbg[128];
      msnprintf(dbg, sizeof(dbg), "BearSSL step2: flush returned %d\n", ret);
      OutputDebugStringA(dbg);
    }
#endif
    if(ret < 0) {
      err = br_ssl_engine_last_error(&BACKEND->sc.eng);
#ifdef _XBOX
      {
        char dbg[128];
        msnprintf(dbg, sizeof(dbg), "BearSSL step2: flush error, engine err=%d\n", err);
        OutputDebugStringA(dbg);
      }
#endif
      if(err != BR_ERR_OK) {
        failf(data, "BearSSL handshake: %s (error %d)",
              bearssl_error_string(err), err);
        return CURLE_SSL_CONNECT_ERROR;
      }
    }
  }

  if(state & BR_SSL_RECVREC) {
    /* Need to receive data - handled by sslio layer */
    unsigned char tmp[1];
    int ret;
    OutputDebugStringA("BearSSL step2: attempting to receive...\n");
    ret = br_sslio_read(&BACKEND->ioc, tmp, 0);
#ifdef _XBOX
    {
      char dbg[128];
      msnprintf(dbg, sizeof(dbg), "BearSSL step2: read returned %d\n", ret);
      OutputDebugStringA(dbg);
    }
#endif
    if(ret < 0) {
      err = br_ssl_engine_last_error(&BACKEND->sc.eng);
#ifdef _XBOX
      {
        char dbg[128];
        msnprintf(dbg, sizeof(dbg), "BearSSL step2: read error, engine err=%d\n", err);
        OutputDebugStringA(dbg);
      }
#endif
      if(err != BR_ERR_OK && err != BR_ERR_IO) {
        failf(data, "BearSSL handshake: %s (error %d)",
              bearssl_error_string(err), err);
        return CURLE_SSL_CONNECT_ERROR;
      }
    }
  }

  /* Check state again */
  state = br_ssl_engine_current_state(&BACKEND->sc.eng);
  if(state & BR_SSL_SENDAPP) {
    connssl->connecting_state = ssl_connect_3;
    return CURLE_OK;
  }

  /* Still connecting */
  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

static CURLcode
bearssl_connect_step3(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  br_ssl_session_parameters session_params;
  unsigned version;
  const char *version_str;

  /* Get negotiated TLS version */
  version = br_ssl_engine_get_version(&BACKEND->sc.eng);
  switch(version) {
  case BR_TLS10: version_str = "TLS 1.0"; break;
  case BR_TLS11: version_str = "TLS 1.1"; break;
  case BR_TLS12: version_str = "TLS 1.2"; break;
  default: version_str = "Unknown"; break;
  }

  /* Log ALPN negotiation result */
  {
    const char *alpn_protocol;
    alpn_protocol = br_ssl_engine_get_selected_protocol(&BACKEND->sc.eng);
    if(alpn_protocol) {
      infof(data, "BearSSL: ALPN negotiated protocol: %s\n", alpn_protocol);
#ifdef _XBOX
      {
        char dbg[128];
        msnprintf(dbg, sizeof(dbg), "BearSSL: ALPN selected: %s\n", alpn_protocol);
        OutputDebugStringA(dbg);
      }
#endif
    }
    else {
      infof(data, "BearSSL: ALPN not negotiated (server may not support it)\n");
#ifdef _XBOX
      OutputDebugStringA("BearSSL: ALPN not negotiated by server\n");
#endif
    }
  }

  /* Check if session was resumed by comparing master secrets.
   * Both ID-based and ticket-based (RFC 5077) resumption reuse the
   * original master secret; a full handshake always derives a new one. */
  br_ssl_engine_get_session_parameters(&BACKEND->sc.eng, &session_params);
  if(memcmp(BACKEND->resume_master_secret, session_params.master_secret,
            48) == 0
     && session_params.master_secret[0] != 0) {
    BACKEND->session_resumed = 1;
  }
  infof(data, "BearSSL: %s connection using %s\n",
        BACKEND->session_resumed ? "Resumed" : "New", version_str);
#ifdef _XBOX
  {
    char dbg[128];
    msnprintf(dbg, sizeof(dbg), "BearSSL: %s connection using %s\n",
              BACKEND->session_resumed ? "Resumed" : "New", version_str);
    OutputDebugStringA(dbg);
  }
#endif

#if BEARSSL_XBOX_INTEGRATION
  /* Store session for future resumption.
   * Store if we have a session ID or a session ticket (RFC 5077). */
  if(session_params.session_id_len > 0
     || session_params.session_ticket_len > 0) {
    bearssl_xbox_session_store(BACKEND->hostname, &session_params);
  }

  /* Copy captured leaf certificate hash from X.509 callback.
   * On resumed sessions, no X.509 validation runs so the hash won't
   * be available — this is expected and not an error. */
  if(BACKEND->using_noanchor && BACKEND->xc_noanchor.leaf_hash_valid) {
    memcpy(BACKEND->leaf_cert_hash, BACKEND->xc_noanchor.leaf_hash, 32);
    BACKEND->leaf_cert_hash_valid = 1;
#ifdef _XBOX
    {
      char dbg[256];
      msnprintf(dbg, sizeof(dbg),
        "BearSSL step3: Leaf cert SHA-256: "
        "%02X%02X%02X%02X %02X%02X%02X%02X "
        "%02X%02X%02X%02X %02X%02X%02X%02X "
        "%02X%02X%02X%02X %02X%02X%02X%02X "
        "%02X%02X%02X%02X %02X%02X%02X%02X\n",
        BACKEND->leaf_cert_hash[0],  BACKEND->leaf_cert_hash[1],
        BACKEND->leaf_cert_hash[2],  BACKEND->leaf_cert_hash[3],
        BACKEND->leaf_cert_hash[4],  BACKEND->leaf_cert_hash[5],
        BACKEND->leaf_cert_hash[6],  BACKEND->leaf_cert_hash[7],
        BACKEND->leaf_cert_hash[8],  BACKEND->leaf_cert_hash[9],
        BACKEND->leaf_cert_hash[10], BACKEND->leaf_cert_hash[11],
        BACKEND->leaf_cert_hash[12], BACKEND->leaf_cert_hash[13],
        BACKEND->leaf_cert_hash[14], BACKEND->leaf_cert_hash[15],
        BACKEND->leaf_cert_hash[16], BACKEND->leaf_cert_hash[17],
        BACKEND->leaf_cert_hash[18], BACKEND->leaf_cert_hash[19],
        BACKEND->leaf_cert_hash[20], BACKEND->leaf_cert_hash[21],
        BACKEND->leaf_cert_hash[22], BACKEND->leaf_cert_hash[23],
        BACKEND->leaf_cert_hash[24], BACKEND->leaf_cert_hash[25],
        BACKEND->leaf_cert_hash[26], BACKEND->leaf_cert_hash[27],
        BACKEND->leaf_cert_hash[28], BACKEND->leaf_cert_hash[29],
        BACKEND->leaf_cert_hash[30], BACKEND->leaf_cert_hash[31]);
      OutputDebugStringA(dbg);
    }
#endif
  }
  else if(BACKEND->session_resumed) {
#ifdef _XBOX
    OutputDebugStringA("BearSSL step3: Leaf cert hash not available (resumed session)\n");
#endif
  }
#endif

  /* Connection is now established - mark SSL as active for proper cleanup */
  /*
   * CRITICAL: Register our SSL send/recv functions with libcurl.
   *
   * libcurl uses conn->recv[sockindex] and conn->send[sockindex] for all
   * data transfer. If we don't set these to our BearSSL functions, libcurl
   * will send raw unencrypted data over the TLS connection, causing the
   * server to reset the connection.
   *
   * This was the root cause of the "connection reset after handshake" bug.
   */
  conn->recv[sockindex] = bearssl_recv;
  conn->send[sockindex] = bearssl_send;

#ifdef _XBOX
  OutputDebugStringA("BearSSL: Registered send/recv handlers with libcurl\n");
#endif

  BACKEND->active = 1;
  connssl->connecting_state = ssl_connect_done;
  connssl->state = ssl_connection_complete;

  return CURLE_OK;
}

static CURLcode
bearssl_connect_common(struct connectdata *conn, int sockindex,
                       bool nonblocking, bool *done)
{
  CURLcode result;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  long timeout_ms;
  int what;

  /* Check if already connected */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    timeout_ms = Curl_timeleft(data, NULL, TRUE);
    if(timeout_ms < 0) {
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }
    result = bearssl_connect_step1(conn, sockindex);
    if(result)
      return result;
  }

  while(ssl_connect_2 == connssl->connecting_state) {
    timeout_ms = Curl_timeleft(data, NULL, TRUE);
    if(timeout_ms < 0) {
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    /* Check socket readiness */
    what = Curl_socket_check(sockfd, CURL_SOCKET_BAD, sockfd,
                             nonblocking ? 0 : timeout_ms);
    if(what < 0) {
      failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
      return CURLE_SSL_CONNECT_ERROR;
    }
    else if(0 == what) {
      if(nonblocking) {
        *done = FALSE;
        return CURLE_OK;
      }
      else {
        failf(data, "SSL connection timeout");
        return CURLE_OPERATION_TIMEDOUT;
      }
    }

    result = bearssl_connect_step2(conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_3 == connssl->connecting_state) {
    result = bearssl_connect_step3(conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    *done = TRUE;
  }
  else {
    *done = FALSE;
  }

  return CURLE_OK;
}

static CURLcode
Curl_bearssl_connect_blocking(struct connectdata *conn, int sockindex)
{
  bool done = FALSE;
  CURLcode result;

  result = bearssl_connect_common(conn, sockindex, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);
  return CURLE_OK;
}

static CURLcode
Curl_bearssl_connect_nonblocking(struct connectdata *conn, int sockindex,
                                 bool *done)
{
  return bearssl_connect_common(conn, sockindex, TRUE, done);
}

static void Curl_bearssl_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

#ifdef _XBOX
  {
    char dbg[128];
    msnprintf(dbg, sizeof(dbg),
      "BearSSL close: sockindex=%d, state=%d, backend=%p\n",
      sockindex, (int)connssl->state, (void*)BACKEND);
    OutputDebugStringA(dbg);
  }
#endif

  /* Free per-connection file-loaded trust anchors even if handshake didn't
   * complete (e.g. step1 failed after loading CAs but before connecting).
   * Must happen before the early-return guard below. */
#if BEARSSL_XBOX_INTEGRATION
  if(BACKEND && BACKEND->file_anchors) {
    bearssl_xbox_free_loaded_anchors(BACKEND->file_anchors,
                                      BACKEND->file_anchor_count);
    BACKEND->file_anchors = NULL;
    BACKEND->file_anchor_count = 0;
  }
#endif

  /* Only cleanup SSL state if it was actually initialized */
  if(connssl->state == ssl_connection_none)
    return;

  if(BACKEND) {
    if(BACKEND->active) {
      /*
       * Attempt graceful TLS close only if the connection is still healthy.
       * br_sslio_close() sends a close_notify alert, which calls sock_write().
       * If the socket is dead, sock_write() fails and BearSSL's I/O state
       * becomes inconsistent, causing heap corruption. Guard against this by
       * checking io_error (set by bearssl_send/recv on failure), the engine
       * error code, and the engine closed flag.
       */
      int err = br_ssl_engine_last_error(&BACKEND->sc.eng);
      unsigned state = br_ssl_engine_current_state(&BACKEND->sc.eng);

#ifdef _XBOX
      {
        char dbg[128];
        msnprintf(dbg, sizeof(dbg),
          "BearSSL close: io_error=%d, err=%d, state=0x%x\n",
          BACKEND->io_error, err, state);
        OutputDebugStringA(dbg);
      }
#endif

      if(!BACKEND->io_error && err == BR_ERR_OK && !(state & BR_SSL_CLOSED)) {
        br_sslio_close(&BACKEND->ioc);
      }
      BACKEND->active = 0;
    }
    /*
     * NOTE: Do NOT free BACKEND! The vtls layer allocates all backend memory
     * as a single block in url.c:allocate_conn(). Freeing BACKEND here would
     * corrupt the heap because it's an offset into a larger allocation.
     *
     * Just clear the backend data to prepare for potential reuse.
     */
#ifdef _XBOX
    {
      char dbg[128];
      msnprintf(dbg, sizeof(dbg),
        "BearSSL: Clearing backend at %p (NOT freeing - vtls manages memory)\n",
        (void*)BACKEND);
      OutputDebugStringA(dbg);
    }
#endif

    /* file_anchors already freed above (before early-return guard) */

    /* Clear backend data but do NOT free (vtls owns the memory) */
    memset(BACKEND, 0, sizeof(struct ssl_backend_data));
  }

  /* Reset state */
  connssl->state = ssl_connection_none;
  connssl->connecting_state = ssl_connect_1;
}

static void Curl_bearssl_close_all(struct Curl_easy *data)
{
  (void)data;
}

static int Curl_bearssl_shutdown(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

#ifdef _XBOX
  {
    char dbg[128];
    msnprintf(dbg, sizeof(dbg),
      "BearSSL shutdown: sockindex=%d, state=%d, backend=%p\n",
      sockindex, (int)connssl->state, (void*)BACKEND);
    OutputDebugStringA(dbg);
  }
#endif

  /* Only shutdown if SSL was actually initialized */
  if(connssl->state == ssl_connection_none)
    return 0;

  /* Check BACKEND exists before accessing it */
  if(!BACKEND)
    return 0;

  if(BACKEND->active) {
    /*
     * Only attempt graceful TLS close if no I/O errors occurred.
     * Avoid trying to send close_notify on a dead socket.
     */
    int err = br_ssl_engine_last_error(&BACKEND->sc.eng);
    unsigned state = br_ssl_engine_current_state(&BACKEND->sc.eng);

    if(!BACKEND->io_error && err == BR_ERR_OK && !(state & BR_SSL_CLOSED)) {
      br_sslio_close(&BACKEND->ioc);
    }
    BACKEND->active = 0;
  }

  return 0;
}

static ssize_t bearssl_send(struct connectdata *conn, int sockindex,
                            const void *mem, size_t len, CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  int ret;
  int flush_ret;

  /* Defensive check - BACKEND must be valid */
  if(!BACKEND || !BACKEND->active) {
    OutputDebugStringA("bearssl_send: BACKEND invalid, returning error\n");
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }

#ifdef BEARSSL_VERBOSE_DEBUG
  {
    char dbg[128];
    msnprintf(dbg, sizeof(dbg), "BearSSL send: len=%u, active=%d\n",
              (unsigned)len, BACKEND->active);
    OutputDebugStringA(dbg);
  }
#endif

  ret = br_sslio_write(&BACKEND->ioc, mem, len);

#ifdef BEARSSL_VERBOSE_DEBUG
  {
    char dbg[128];
    int err = br_ssl_engine_last_error(&BACKEND->sc.eng);
    unsigned state = br_ssl_engine_current_state(&BACKEND->sc.eng);
    msnprintf(dbg, sizeof(dbg), "BearSSL send: write returned %d, err=%d, state=0x%x\n",
              ret, err, state);
    OutputDebugStringA(dbg);
  }
#endif

  if(ret < 0) {
    int err = br_ssl_engine_last_error(&BACKEND->sc.eng);
    /* Mark that we've had an I/O error - skip graceful close later */
    BACKEND->io_error = 1;
    if(err == BR_ERR_OK || err == BR_ERR_IO) {
      *curlcode = CURLE_AGAIN;
    }
    else {
      *curlcode = CURLE_SEND_ERROR;
    }
    return -1;
  }

  /* Flush the data to ensure it's sent immediately */
  flush_ret = br_sslio_flush(&BACKEND->ioc);

#ifdef BEARSSL_VERBOSE_DEBUG
  {
    char dbg[128];
    msnprintf(dbg, sizeof(dbg), "BearSSL send: flush returned %d\n", flush_ret);
    OutputDebugStringA(dbg);
  }
#endif

  if(flush_ret < 0) {
    BACKEND->io_error = 1;
  }

  return (ssize_t)ret;
}

static ssize_t bearssl_recv(struct connectdata *conn, int sockindex,
                            char *buf, size_t buffersize, CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  int ret;

  /* Defensive check - BACKEND must be valid */
  if(!BACKEND || !BACKEND->active) {
    OutputDebugStringA("bearssl_recv: BACKEND invalid, returning error\n");
    *curlcode = CURLE_RECV_ERROR;
    return -1;
  }

#ifdef BEARSSL_VERBOSE_DEBUG
  {
    char dbg[128];
    msnprintf(dbg, sizeof(dbg), "BearSSL recv: buffersize=%u, active=%d\n",
              (unsigned)buffersize, BACKEND->active);
    OutputDebugStringA(dbg);
  }
#endif

  ret = br_sslio_read(&BACKEND->ioc, buf, buffersize);

#ifdef BEARSSL_VERBOSE_DEBUG
  {
    char dbg[128];
    int err = br_ssl_engine_last_error(&BACKEND->sc.eng);
    unsigned state = br_ssl_engine_current_state(&BACKEND->sc.eng);
    msnprintf(dbg, sizeof(dbg), "BearSSL recv: read returned %d, err=%d, state=0x%x\n",
              ret, err, state);
    OutputDebugStringA(dbg);
  }
#endif

  if(ret < 0) {
    int err = br_ssl_engine_last_error(&BACKEND->sc.eng);
    /* Mark that we've had an I/O error - skip graceful close later */
    BACKEND->io_error = 1;
#ifdef BEARSSL_VERBOSE_DEBUG
    {
      char dbg[128];
      msnprintf(dbg, sizeof(dbg), "BearSSL recv: ERROR - setting io_error=1, err=%d\n", err);
      OutputDebugStringA(dbg);
    }
#endif
    if(err == BR_ERR_OK || err == BR_ERR_IO) {
      *curlcode = CURLE_AGAIN;
    }
    else {
      *curlcode = CURLE_RECV_ERROR;
    }
    return -1;
  }

  return (ssize_t)ret;
}

static bool Curl_bearssl_data_pending(const struct connectdata *conn,
                                      int sockindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  unsigned state;

  /* Check if SSL was initialized before accessing BACKEND */
  if(connssl->state == ssl_connection_none)
    return FALSE;

  if(!BACKEND || !BACKEND->active)
    return FALSE;

  state = br_ssl_engine_current_state(&BACKEND->sc.eng);
  return (state & BR_SSL_RECVAPP) ? TRUE : FALSE;
}

static int Curl_bearssl_check_cxn(struct connectdata *conn)
{
  struct ssl_connect_data *connssl = &conn->ssl[FIRSTSOCKET];
  int err;

  /* Check if SSL was initialized before accessing BACKEND */
  if(connssl->state == ssl_connection_none)
    return 0;

  if(!BACKEND || !BACKEND->active)
    return 0;

  err = br_ssl_engine_last_error(&BACKEND->sc.eng);
  return (err == BR_ERR_OK) ? 1 : 0;
}

static void *Curl_bearssl_get_internals(struct ssl_connect_data *connssl,
                                        CURLINFO info)
{
  (void)info;
  /* Check if SSL was initialized before accessing BACKEND */
  if(connssl->state == ssl_connection_none)
    return NULL;
  return BACKEND ? &BACKEND->sc : NULL;
}

static void Curl_bearssl_session_free(void *ptr)
{
  (void)ptr;
  /* BearSSL session handling is different; no dynamic session objects */
}

const struct Curl_ssl Curl_ssl_bearssl = {
  { CURLSSLBACKEND_BEARSSL, "bearssl" }, /* info */
  SSLSUPP_CA_PATH |
  SSLSUPP_SSL_CTX, /* supports */
  sizeof(struct ssl_backend_data),

  Curl_bearssl_init,                /* init */
  Curl_bearssl_cleanup,             /* cleanup */
  Curl_bearssl_version,             /* version */
  Curl_bearssl_check_cxn,           /* check_cxn */
  Curl_bearssl_shutdown,            /* shutdown */
  Curl_bearssl_data_pending,        /* data_pending */
  Curl_bearssl_random,              /* random */
  Curl_none_cert_status_request,    /* cert_status_request */
  Curl_bearssl_connect_blocking,    /* connect_blocking */
  Curl_bearssl_connect_nonblocking, /* connect_nonblocking */
  Curl_bearssl_get_internals,       /* get_internals */
  Curl_bearssl_close,               /* close_one */
  Curl_bearssl_close_all,           /* close_all */
  Curl_bearssl_session_free,        /* session_free */
  Curl_none_set_engine,             /* set_engine */
  Curl_none_set_engine_default,     /* set_engine_default */
  Curl_none_engines_list,           /* engines_list */
  Curl_none_false_start,            /* false_start */
  Curl_none_md5sum,                 /* md5sum */
  NULL                              /* sha256sum */
};

#endif /* USE_BEARSSL */
