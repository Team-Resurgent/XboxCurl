#include "ca_loader.h"
#include "debug_utility.h"

#include <xtl.h>
#include <winsockx.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bearssl.h>
#include <bearssl_pem.h>
#include <bearssl_x509.h>

#define DOWNLOAD_BUF_SIZE 8192
#define CA_DNS_TIMEOUT_MS 30000

/* ------------------------------------------------------------------ */
/* Inline socket/network helpers (avoids dependency on BearSSL-OG     */
/* socket_utility / network_utility which aren't in libbearssl)       */
/* ------------------------------------------------------------------ */

/* DNS resolution via Xbox XNet async API */
static uint32_t ca_resolve_host(const char *host)
{
	XNDNS *dns = NULL;
	WSAEVENT event_handle;
	uint32_t result = 0;

	if (host == NULL || host[0] == '\0')
	{
		return 0;
	}

	event_handle = WSACreateEvent();
	if (event_handle == NULL)
	{
		return 0;
	}

	if (XNetDnsLookup(host, event_handle, &dns) != 0)
	{
		WSACloseEvent(event_handle);
		return 0;
	}

	if (WaitForSingleObject(event_handle, CA_DNS_TIMEOUT_MS) == WAIT_TIMEOUT)
	{
		WSACloseEvent(event_handle);
		XNetDnsRelease(dns);
		return 0;
	}

	WSACloseEvent(event_handle);

	if (dns->iStatus == 0 && dns->cina > 0)
	{
		result = dns->aina[0].S_un.S_addr;
	}

	XNetDnsRelease(dns);
	return result;
}

/* TCP connect to host:port, returns socket or INVALID_SOCKET.
 * IMPORTANT: Xbox SOCKET handles are kernel pointers (e.g. 0xD001A828)
 * which are negative as signed int -- never check < 0, always use
 * INVALID_SOCKET. */
static SOCKET ca_connect(uint32_t host_ip, uint16_t port)
{
	sockaddr_in addr;
	SOCKET sock;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.S_un.S_addr = host_ip;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		closesocket(sock);
		return INVALID_SOCKET;
	}

	return sock;
}

/* BearSSL I/O callback: read from socket with 2-second select timeout */
static int ca_sock_read(void *ctx, unsigned char *buf, size_t len)
{
	SOCKET sock = *(SOCKET *)ctx;
	fd_set fds;
	struct timeval tv;
	int n;

	while (1)
	{
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		tv.tv_sec = 2;
		tv.tv_usec = 0;

		if (select(0, &fds, NULL, NULL, &tv) == 0)
		{
			return -1; /* timeout */
		}

		n = recv(sock, (char *)buf, (len > 0x7FFFFFFF) ? 0x7FFFFFFF : (int)len, 0);
		if (n == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAEINTR ||
				WSAGetLastError() == WSAEWOULDBLOCK)
			{
				continue;
			}
			return -1;
		}
		return n; /* 0 = peer closed, >0 = bytes read */
	}
}

/* BearSSL I/O callback: write to socket */
static int ca_sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	SOCKET sock = *(SOCKET *)ctx;
	int n;

	while (1)
	{
		n = send(sock, (const char *)buf,
			(len > 0x7FFFFFFF) ? 0x7FFFFFFF : (int)len, 0);
		if (n == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAEINTR ||
				WSAGetLastError() == WSAEWOULDBLOCK)
			{
				continue;
			}
			return -1;
		}
		return n;
	}
}

/* Dynamic byte buffer used for accumulating DER and DN data */
struct byte_buffer
{
	unsigned char *data;
	size_t len;
	size_t cap;
	int error;  /* set to 1 if any append failed (OOM) */
};

static void byte_buffer_init(byte_buffer *bb)
{
	bb->data = NULL;
	bb->len = 0;
	bb->cap = 0;
	bb->error = 0;
}

static void byte_buffer_reset(byte_buffer *bb)
{
	bb->len = 0;
	bb->error = 0;
}

static void byte_buffer_free(byte_buffer *bb)
{
	free(bb->data);
	bb->data = NULL;
	bb->len = 0;
	bb->cap = 0;
	bb->error = 0;
}

static int byte_buffer_append(byte_buffer *bb, const void *src, size_t len)
{
	if (len == 0)
	{
		return 0;
	}
	if (bb->len + len > bb->cap)
	{
		size_t new_cap = (bb->cap == 0) ? 4096 : bb->cap * 2;
		while (new_cap < bb->len + len)
		{
			if (new_cap > ((size_t)-1) / 2)
			{
				return -1;
			}
			new_cap *= 2;
		}
		unsigned char *new_data = (unsigned char *)realloc(bb->data, new_cap);
		if (new_data == NULL)
		{
			return -1;
		}
		bb->data = new_data;
		bb->cap = new_cap;
	}
	memcpy(bb->data + bb->len, src, len);
	bb->len += len;
	return 0;
}

/* PEM decoder callback: accumulates decoded DER bytes */
static void pem_dest_callback(void *dest_ctx, const void *src, size_t len)
{
	byte_buffer *bb = (byte_buffer *)dest_ctx;
	if (byte_buffer_append(bb, src, len) != 0)
	{
		bb->error = 1;
	}
}

/* X.509 decoder callback: accumulates subject DN bytes */
static void dn_append_callback(void *ctx, const void *buf, size_t len)
{
	byte_buffer *bb = (byte_buffer *)ctx;
	if (byte_buffer_append(bb, buf, len) != 0)
	{
		bb->error = 1;
	}
}

/*
 * Deep-copy a decoded certificate into a new trust anchor entry.
 * Returns 0 on success, -1 on allocation failure.
 */
static int add_trust_anchor(
	br_x509_trust_anchor **anchors, size_t *count, size_t *cap,
	byte_buffer *dn, br_x509_decoder_context *dc)
{
	br_x509_pkey *pk = br_x509_decoder_get_pkey(dc);
	if (pk == NULL)
	{
		return -1;
	}

	/* Grow anchor array if needed */
	if (*count >= *cap)
	{
		size_t new_cap = (*cap == 0) ? 32 : *cap * 2;
		br_x509_trust_anchor *new_arr = (br_x509_trust_anchor *)realloc(
			*anchors, new_cap * sizeof(br_x509_trust_anchor));
		if (new_arr == NULL)
		{
			return -1;
		}
		*anchors = new_arr;
		*cap = new_cap;
	}

	br_x509_trust_anchor *ta = &(*anchors)[*count];
	memset(ta, 0, sizeof(*ta));

	/* Deep-copy DN */
	ta->dn.data = (unsigned char *)malloc(dn->len);
	if (ta->dn.data == NULL)
	{
		return -1;
	}
	memcpy(ta->dn.data, dn->data, dn->len);
	ta->dn.len = dn->len;

	/* Set CA flag */
	ta->flags = br_x509_decoder_isCA(dc) ? BR_X509_TA_CA : 0;

	/* Deep-copy public key */
	ta->pkey.key_type = pk->key_type;
	if (pk->key_type == BR_KEYTYPE_RSA)
	{
		ta->pkey.key.rsa.n = (unsigned char *)malloc(pk->key.rsa.nlen);
		ta->pkey.key.rsa.e = (unsigned char *)malloc(pk->key.rsa.elen);
		if (ta->pkey.key.rsa.n == NULL || ta->pkey.key.rsa.e == NULL)
		{
			free(ta->pkey.key.rsa.n);
			free(ta->pkey.key.rsa.e);
			free(ta->dn.data);
			return -1;
		}
		memcpy(ta->pkey.key.rsa.n, pk->key.rsa.n, pk->key.rsa.nlen);
		ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
		memcpy(ta->pkey.key.rsa.e, pk->key.rsa.e, pk->key.rsa.elen);
		ta->pkey.key.rsa.elen = pk->key.rsa.elen;
	}
	else if (pk->key_type == BR_KEYTYPE_EC)
	{
		ta->pkey.key.ec.q = (unsigned char *)malloc(pk->key.ec.qlen);
		if (ta->pkey.key.ec.q == NULL)
		{
			free(ta->dn.data);
			memset(ta, 0, sizeof(*ta));
			return -1;
		}
		memcpy(ta->pkey.key.ec.q, pk->key.ec.q, pk->key.ec.qlen);
		ta->pkey.key.ec.qlen = pk->key.ec.qlen;
		ta->pkey.key.ec.curve = pk->key.ec.curve;
	}
	else
	{
		/* Unknown key type */
		free(ta->dn.data);
		memset(ta, 0, sizeof(*ta));
		return -1;
	}

	(*count)++;
	return 0;
}

int ca_loader::load_pem_file(const char *path,
	br_x509_trust_anchor **anchors_out, size_t *count_out)
{
	*anchors_out = NULL;
	*count_out = 0;

	/* Read entire PEM file into memory */
	FILE *f = fopen(path, "rb");
	if (f == NULL)
	{
		debug_utility::debug_print("ca_loader: cannot open %s\n", path);
		return -1;
	}

	fseek(f, 0, SEEK_END);
	long file_size = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (file_size <= 0 || file_size > 2 * 1024 * 1024)
	{
		debug_utility::debug_print("ca_loader: file too large or empty (%ld bytes)\n", file_size);
		fclose(f);
		return -1;
	}

	unsigned char *file_data = (unsigned char *)malloc((size_t)file_size);
	if (file_data == NULL)
	{
		debug_utility::debug_print("ca_loader: malloc failed for file data\n");
		fclose(f);
		return -1;
	}

	size_t bytes_read = fread(file_data, 1, (size_t)file_size, f);
	fclose(f);

	if (bytes_read != (size_t)file_size)
	{
		debug_utility::debug_print("ca_loader: short read (%u of %ld)\n",
			(unsigned)bytes_read, file_size);
		free(file_data);
		return -1;
	}

	/* Parse PEM, collecting DER blobs for each CERTIFICATE */
	br_pem_decoder_context pem;
	br_pem_decoder_init(&pem);

	br_x509_trust_anchor *anchors = NULL;
	size_t anchor_count = 0;
	size_t anchor_cap = 0;

	byte_buffer der_buf;
	byte_buffer_init(&der_buf);

	byte_buffer dn_buf;
	byte_buffer_init(&dn_buf);

	int in_cert = 0;
	int certs_parsed = 0;
	int certs_failed = 0;

	const unsigned char *pos = file_data;
	size_t remaining = bytes_read;

	while (remaining > 0)
	{
		size_t consumed = br_pem_decoder_push(&pem, pos, remaining);
		pos += consumed;
		remaining -= consumed;

		int event = br_pem_decoder_event(&pem);
		switch (event)
		{
		case BR_PEM_BEGIN_OBJ:
			if (strcmp(br_pem_decoder_name(&pem), "CERTIFICATE") == 0)
			{
				in_cert = 1;
				byte_buffer_reset(&der_buf);
				br_pem_decoder_setdest(&pem, pem_dest_callback, &der_buf);
			}
			else
			{
				/* Skip non-certificate objects (private keys, etc.) */
				in_cert = 0;
				br_pem_decoder_setdest(&pem, NULL, NULL);
			}
			break;

		case BR_PEM_END_OBJ:
			if (in_cert && der_buf.len > 0 && !der_buf.error)
			{
				/* Decode the DER certificate */
				br_x509_decoder_context dc;
				byte_buffer_reset(&dn_buf);
				br_x509_decoder_init(&dc, dn_append_callback, &dn_buf);
				br_x509_decoder_push(&dc, der_buf.data, der_buf.len);

				int err = br_x509_decoder_last_error(&dc);
				if (err == 0 && !dn_buf.error)
				{
					if (add_trust_anchor(&anchors, &anchor_count, &anchor_cap,
						&dn_buf, &dc) == 0)
					{
						certs_parsed++;
					}
					else
					{
						certs_failed++;
					}
				}
				else
				{
					certs_failed++;
				}
			}
			else if (in_cert && (der_buf.error || dn_buf.error))
			{
				certs_failed++;
			}
			in_cert = 0;
			break;

		case BR_PEM_ERROR:
			in_cert = 0;
			break;

		case 0:
			/* No event yet, decoder needs more data but push returned 0.
			 * This shouldn't happen with complete files, but guard against
			 * infinite loop by breaking if no progress was made. */
			if (consumed == 0)
			{
				remaining = 0;
			}
			break;
		}
	}

	byte_buffer_free(&der_buf);
	byte_buffer_free(&dn_buf);
	free(file_data);

	debug_utility::debug_print("ca_loader: loaded %d trust anchors from %s (%d failed)\n",
		certs_parsed, path, certs_failed);

	if (anchor_count == 0)
	{
		free(anchors);
		return -1;
	}

	*anchors_out = anchors;
	*count_out = anchor_count;
	return 0;
}

void ca_loader::free_trust_anchors(br_x509_trust_anchor *anchors, size_t count)
{
	size_t i;

	if (anchors == NULL)
	{
		return;
	}

	for (i = 0; i < count; i++)
	{
		free(anchors[i].dn.data);
		if (anchors[i].pkey.key_type == BR_KEYTYPE_RSA)
		{
			free(anchors[i].pkey.key.rsa.n);
			free(anchors[i].pkey.key.rsa.e);
		}
		else if (anchors[i].pkey.key_type == BR_KEYTYPE_EC)
		{
			free(anchors[i].pkey.key.ec.q);
		}
	}
	free(anchors);
}

/* ------------------------------------------------------------------ */
/* Auto-update: download CA bundle from curl.se over HTTPS            */
/* ------------------------------------------------------------------ */

/* Time check callback: always returns 0 (valid).
 * This lets the compiled-in CAs work even if the Xbox clock is wrong. */
static int download_time_check(void *tctx,
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

/* Find \r\n in a buffer, return offset or -1 */
static int find_line_end(const unsigned char *buf, size_t len)
{
	size_t i;
	if (len < 2) return -1;
	for (i = 0; i < len - 1; i++)
	{
		if (buf[i] == '\r' && buf[i + 1] == '\n')
		{
			return (int)i;
		}
	}
	return -1;
}

/* Case-insensitive prefix match */
static int prefix_icmp(const char *str, const char *prefix)
{
	while (*prefix)
	{
		char a = *str;
		char b = *prefix;
		if (a >= 'A' && a <= 'Z') a += 32;
		if (b >= 'A' && b <= 'Z') b += 32;
		if (a != b) return 0;
		str++;
		prefix++;
	}
	return 1;
}

int ca_loader::download_https(const char *host, const char *path,
	uint16_t port, const char *save_path,
	br_x509_trust_anchor *anchors, size_t anchor_count,
	int max_redirects)
{
	int result = -1;

	/* DNS resolve */
	uint32_t host_ip = ca_resolve_host(host);
	if (host_ip == 0)
	{
		debug_utility::debug_print("ca_loader: DNS failed for %s\n", host);
		return -1;
	}

	/* TCP connect */
	SOCKET sock = ca_connect(host_ip, port);
	if (sock == INVALID_SOCKET)
	{
		debug_utility::debug_print("ca_loader: connect failed to %s:%u\n",
			host, (unsigned)port);
		return -1;
	}

	/* Allocate BearSSL I/O buffer on the heap (too large for Xbox stack) */
	unsigned char *iobuf = (unsigned char *)malloc(BR_SSL_BUFSIZE_BIDI);
	if (iobuf == NULL)
	{
		closesocket(sock);
		return -1;
	}

	/* Set up BearSSL with compiled-in CAs + time check bypass */
	br_ssl_client_context sc;
	br_x509_minimal_context xc;
	br_ssl_client_init_full(&sc, &xc, anchors, anchor_count);
	br_x509_minimal_set_time_callback(&xc, NULL, download_time_check);
	br_ssl_engine_set_buffer(&sc.eng, iobuf, BR_SSL_BUFSIZE_BIDI, 1);
	br_ssl_client_reset(&sc, host, 0);

	br_sslio_context ioc;
	br_sslio_init(&ioc, &sc.eng,
		ca_sock_read, &sock,
		ca_sock_write, &sock);

	/* Send HTTP GET */
	char request[512];
	_snprintf(request, sizeof(request) - 1,
		"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Accept-Encoding: identity\r\n"
		"Connection: close\r\n"
		"\r\n",
		path, host);
	request[sizeof(request) - 1] = '\0';

	br_sslio_write_all(&ioc, request, strlen(request));
	br_sslio_flush(&ioc);

	/* Read response into accumulation buffer */
	unsigned char *readbuf = (unsigned char *)malloc(DOWNLOAD_BUF_SIZE);
	if (readbuf == NULL)
	{
		free(iobuf);
		closesocket(sock);
		return -1;
	}

	/* Accumulate headers */
	byte_buffer hdr;
	byte_buffer_init(&hdr);

	int status_code = 0;
	int64_t content_length = -1;
	char redirect_host[256];
	char redirect_path[512];
	int has_redirect = 0;
	int headers_done = 0;

	redirect_host[0] = '\0';
	redirect_path[0] = '\0';

	while (!headers_done)
	{
		int n = br_sslio_read(&ioc, readbuf, DOWNLOAD_BUF_SIZE);
		if (n < 0) break;
		byte_buffer_append(&hdr, readbuf, (size_t)n);

		/* Parse complete lines from the accumulated buffer */
		while (hdr.len > 0)
		{
			int crlf = find_line_end(hdr.data, hdr.len);
			if (crlf < 0) break;

			/* Null-terminate the line for string operations */
			char *line = (char *)malloc((size_t)crlf + 1);
			if (line == NULL) break;
			memcpy(line, hdr.data, (size_t)crlf);
			line[crlf] = '\0';

			/* Remove the line + CRLF from the buffer */
			{
				size_t remove_len = (size_t)crlf + 2;
				if (remove_len < hdr.len)
				{
					memmove(hdr.data, hdr.data + remove_len,
						hdr.len - remove_len);
				}
				hdr.len -= remove_len;
			}

			/* Empty line = end of headers */
			if (line[0] == '\0')
			{
				free(line);
				headers_done = 1;
				break;
			}

			/* Parse status line: "HTTP/1.x 200 OK" */
			if (status_code == 0 && strncmp(line, "HTTP/", 5) == 0)
			{
				char *sp = strchr(line, ' ');
				if (sp) status_code = atoi(sp + 1);
			}

			/* Parse Content-Length (cap at 10MB - CA bundles are ~250KB) */
			if (prefix_icmp(line, "content-length:"))
			{
				const char *val = line + 15;
				while (*val == ' ') val++;
				content_length = 0;
				while (*val >= '0' && *val <= '9')
				{
					content_length = content_length * 10 + (*val - '0');
					if (content_length > 10 * 1024 * 1024)
					{
						content_length = -1;
						break;
					}
					val++;
				}
			}

			/* Parse Location for redirects */
			if (prefix_icmp(line, "location:"))
			{
				const char *url = line + 9;
				while (*url == ' ') url++;

				/* Parse "https://host/path" */
				if (strncmp(url, "https://", 8) == 0)
				{
					const char *hstart = url + 8;
					const char *slash = strchr(hstart, '/');
					if (slash)
					{
						size_t hlen = (size_t)(slash - hstart);
						if (hlen < sizeof(redirect_host))
						{
							memcpy(redirect_host, hstart, hlen);
							redirect_host[hlen] = '\0';
							_snprintf(redirect_path,
								sizeof(redirect_path) - 1, "%s", slash);
							redirect_path[sizeof(redirect_path) - 1] = '\0';
							has_redirect = 1;
						}
					}
				}
			}

			free(line);
		}
	}

	/* Handle redirect */
	if ((status_code == 301 || status_code == 302 || status_code == 307)
		&& has_redirect && max_redirects > 0)
	{
		debug_utility::debug_print("ca_loader: redirect %d -> %s%s\n",
			status_code, redirect_host, redirect_path);

		byte_buffer_free(&hdr);
		free(readbuf);
		free(iobuf);
		closesocket(sock);

		return download_https(redirect_host, redirect_path, port,
			save_path, anchors, anchor_count, max_redirects - 1);
	}

	if (status_code != 200)
	{
		debug_utility::debug_print("ca_loader: HTTP %d from %s%s\n",
			status_code, host, path);
		byte_buffer_free(&hdr);
		free(readbuf);
		free(iobuf);
		closesocket(sock);
		return -1;
	}

	/* Write body to a temp file, then rename on success */
	char temp_path[280];
	_snprintf(temp_path, sizeof(temp_path) - 1, "%s.tmp", save_path);
	temp_path[sizeof(temp_path) - 1] = '\0';

	FILE *fp = fopen(temp_path, "wb");
	if (fp == NULL)
	{
		debug_utility::debug_print("ca_loader: cannot create %s (err=%lu)\n",
			temp_path, GetLastError());
		byte_buffer_free(&hdr);
		free(readbuf);
		free(iobuf);
		closesocket(sock);
		return -1;
	}

	/* Write any leftover data that was read past the headers */
	int64_t total_written = 0;
	int write_error = 0;
	if (hdr.len > 0)
	{
		if (fwrite(hdr.data, 1, hdr.len, fp) != hdr.len)
		{
			write_error = 1;
		}
		total_written += (int64_t)hdr.len;
	}
	byte_buffer_free(&hdr);

	/* Stream the rest of the body to disk */
	while (!write_error)
	{
		int n = br_sslio_read(&ioc, readbuf, DOWNLOAD_BUF_SIZE);
		if (n < 0) break;
		if (fwrite(readbuf, 1, (size_t)n, fp) != (size_t)n)
		{
			write_error = 1;
			break;
		}
		total_written += (int64_t)n;

		if (content_length > 0 && total_written >= content_length)
		{
			break;
		}
	}

	fclose(fp);
	free(readbuf);
	free(iobuf);
	closesocket(sock);

	/* Check for disk write errors */
	if (write_error)
	{
		debug_utility::debug_print("ca_loader: write error saving to %s\n",
			temp_path);
		remove(temp_path);
		return -1;
	}

	/* Sanity check: CA bundles are typically 200-300 KB */
	if (total_written < 1024)
	{
		debug_utility::debug_print("ca_loader: download too small (%I64d bytes)\n",
			total_written);
		remove(temp_path);
		return -1;
	}

	/* Atomic-ish replace: delete old, rename temp */
	remove(save_path);
	if (rename(temp_path, save_path) != 0)
	{
		debug_utility::debug_print("ca_loader: rename %s -> %s failed\n",
			temp_path, save_path);
		remove(temp_path);
		return -1;
	}

	debug_utility::debug_print("ca_loader: downloaded %I64d bytes to %s\n",
		total_written, save_path);
	result = 0;
	return result;
}

int ca_loader::update_trust_store(const char *save_path,
	br_x509_trust_anchor *anchors, size_t anchor_count)
{
	/* If the CA file already exists on disk, nothing to do */
	FILE *f = fopen(save_path, "rb");
	if (f != NULL)
	{
		fclose(f);
		debug_utility::debug_print("ca_loader: %s already exists, skipping download\n",
			save_path);
		return 0;
	}

	if (anchors == NULL || anchor_count == 0)
	{
		debug_utility::debug_print("ca_loader: no trust anchors for download\n");
		return -1;
	}

	debug_utility::debug_print("ca_loader: downloading CA bundle from %s...\n",
		CA_BUNDLE_HOST);

	return download_https(CA_BUNDLE_HOST, CA_BUNDLE_PATH, CA_BUNDLE_PORT,
		save_path, anchors, anchor_count, 3);
}
