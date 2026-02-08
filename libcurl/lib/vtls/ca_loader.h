#pragma once

#include <bearssl_x509.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Runtime CA certificate loader.
 *
 * Parses PEM-encoded CA bundle files (e.g. cacert.pem from curl.se)
 * into br_x509_trust_anchor arrays that BearSSL can use for certificate
 * verification.
 *
 * Also provides auto-update: downloads a fresh CA bundle over HTTPS
 * using the compiled-in trust anchors (with time validation bypassed)
 * and saves it to title-persistent storage on the Xbox HDD.
 */

/* Where to download the CA bundle from */
#define CA_BUNDLE_HOST "curl.se"
#define CA_BUNDLE_PATH "/ca/cacert.pem"
#define CA_BUNDLE_PORT 443

class ca_loader
{
public:
	/*
	 * Load trust anchors from a PEM CA bundle file.
	 * Returns 0 on success, -1 on failure.
	 */
	static int load_pem_file(const char *path,
		br_x509_trust_anchor **anchors_out, size_t *count_out);

	/*
	 * Free trust anchors that were loaded from a PEM file.
	 * Deep-frees DN data and key data, then frees the array.
	 */
	static void free_trust_anchors(br_x509_trust_anchor *anchors,
		size_t count);

	/*
	 * Auto-update the trust store.
	 *
	 * If save_path does not exist, downloads a fresh CA bundle from
	 * curl.se over HTTPS (using the provided trust anchors with time
	 * validation disabled) and saves it to save_path.
	 *
	 * Returns 0 on success (file already existed or was downloaded).
	 * Returns -1 on failure (download failed, file I/O error, etc.).
	 */
	static int update_trust_store(const char *save_path,
		br_x509_trust_anchor *anchors, size_t anchor_count);

private:
	/*
	 * Download an HTTPS resource and save to a file.
	 * Uses BearSSL with the given trust anchors (time check disabled).
	 * Follows up to max_redirects HTTP 301/302 redirects.
	 * Returns 0 on success, -1 on failure.
	 */
	static int download_https(const char *host, const char *path,
		uint16_t port, const char *save_path,
		br_x509_trust_anchor *anchors, size_t anchor_count,
		int max_redirects);
};
