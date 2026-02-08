#pragma once

#include <bearssl_x509.h>

class certificates
{
public:
	static void initialize_trust_anchors();
	static void close_trust_anchors();
	static br_x509_trust_anchor* get_trust_anchors();
	static int get_num_trust_anchors();

	/*
	 * Try to load trust anchors from a PEM CA bundle file.
	 * If successful, replaces the compiled-in trust store.
	 * Returns 0 on success, -1 on failure (compiled-in CAs unchanged).
	 */
	static int load_from_file(const char *path);

private:
	static br_x509_trust_anchor make_rsa_trust_anchor(unsigned char *dn, size_t dn_len, unsigned char *n, size_t n_len, unsigned char *e, size_t e_len);
	static br_x509_trust_anchor make_ec_trust_anchor(unsigned char *dn, size_t dn_len, int curve, unsigned char *q, size_t q_len);
};
