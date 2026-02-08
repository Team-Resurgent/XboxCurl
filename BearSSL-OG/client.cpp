#include "client.h"
#include "url_utility.h"
#include "debug_utility.h"
#include "network_utility.h"
#include "string_utility.h"
#include "socket_utility.h"
#include "certificates.h"
#include "ca_loader.h"
#include "data_store.h"

#include <xtl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <bearssl.h>
#include "ssl_config.h"
#include "ssl_debug.h"
#include "session_cache.h"
#include "cert_pinning.h"

#define READ_BUFFER_SIZE 65536

int client::download_file(const char* url, uint16_t port, const char* file_path)
{
	char *host = NULL;
	char *path = NULL;
	if (url_utility::parse_url(url, &host, &path) == false)
	{
		return -1;
	}

	uint32_t host_ip = network_utility::resolve_host(host);
	if (host_ip == 0)
	{
		ssl_debug::log_error("DNS resolution failed for host: %s\n", host);
		free(host);
		free(path);
		return -3; /* DNS resolution failed */
	}

	int socket = socket_utility::connect_to_host(host_ip, port);
	if (socket < 0)
	{
		ssl_debug::log_error("Failed to connect to %s:%d\n", host, port);
		free(host);
		free(path);
		return -4; /* Connection failed */
	}

	/* Try loading CAs from PEM file on Xbox HDD */
	if (certificates::load_from_file(SSL_DEFAULT_CA_FILE) != 0)
	{
		/* No file on disk — load compiled-in CAs and auto-download */
		certificates::initialize_trust_anchors();
		ca_loader::update_trust_store(SSL_DEFAULT_CA_FILE,
			certificates::get_trust_anchors(),
			(size_t)certificates::get_num_trust_anchors());

		/* If download succeeded, switch to the fresh CAs */
		certificates::load_from_file(SSL_DEFAULT_CA_FILE);
	}

	br_ssl_client_context client_context;
	br_x509_minimal_context cert_context;
	br_ssl_client_init_full(&client_context, &cert_context, certificates::get_trust_anchors(), certificates::get_num_trust_anchors());

    // Enforce TLS 1.2 minimum
#if SSL_ENFORCE_TLS12
    br_ssl_engine_set_versions(&client_context.eng, SSL_MIN_VERSION, SSL_MAX_VERSION);
#endif

    // Restrict to secure cipher suites
#if SSL_RESTRICT_CIPHERS
    br_ssl_engine_set_suites(&client_context.eng, SSL_SECURE_SUITES, SSL_SECURE_SUITES_COUNT);
#endif

	unsigned char io_buffer[BR_SSL_BUFSIZE_BIDI];
	br_ssl_engine_set_buffer(&client_context.eng, io_buffer, BR_SSL_BUFSIZE_BIDI, 1);

    // Try to resume previous session
    br_ssl_session_parameters session_params;
    int resume = 0;
#if SSL_ENABLE_SESSION_CACHE
    if (session_cache::get(host, &session_params)) {
        br_ssl_engine_set_session_parameters(&client_context.eng, &session_params);
        resume = 1;
    }
#endif

	br_ssl_client_reset(&client_context, host, resume);

	br_sslio_context io_context;
	br_sslio_init(&io_context, &client_context.eng, socket_utility::socket_read, &socket, socket_utility::socket_write, &socket);

    // Verify certificate pin if configured
#if SSL_ENABLE_CERT_PINNING
    if (!cert_pinning::verify(host, &client_context.eng)) {
        ssl_debug::log_error("Connection rejected due to certificate pin mismatch\n");
        closesocket(socket);
        certificates::close_trust_anchors();
        free(host);
        free(path);
        return -2; // Pin verification failed
    }
#endif

	char* request = string_utility::format_string("GET %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", path, host);
	if (request == NULL)
	{
		ssl_debug::log_error("Failed to allocate HTTP request string\n");
		closesocket(socket);
		certificates::close_trust_anchors();
		free(host);
		free(path);
		return -5;
	}
	br_sslio_write_all(&io_context, request, strlen(request));
	br_sslio_flush(&io_context);
	free(request);

	data_store* data = new data_store();
	pointer_vector<char*>* headers = new pointer_vector<char*>(false);
	populate_headers(&io_context, data, headers);

	int64_t content_length = -1;
	char* redirect_url = NULL;
	
	bool has_redirect = false;
	for (uint32_t i = 0; i < headers->count(); i++)
	{
		pointer_vector<char*>* parts = string_utility::split_first(headers->get(i), ":", true);
		if (parts->count() != 2)
		{
			continue;
		}
		if (strcmp(parts->get(0), "Content-Length") == 0)
		{
			content_length = string_utility::string_to_int64(parts->get(1));
		}
		if (strcmp(parts->get(0), "Location") == 0)
		{
			has_redirect = true;
			redirect_url = strdup(parts->get(1));
		}
		delete parts;
	}

	delete headers;

	if (has_redirect == true)
	{
		closesocket(socket);
		certificates::close_trust_anchors();
		delete data;
		free(host);
		free(path);

		int result = download_file(redirect_url, port, file_path);
		if (redirect_url != NULL)
		{
			free(redirect_url);
		}
		return result;
	}

	if (redirect_url != NULL)
	{
		free(redirect_url);
	}

	if (content_length < 0)
	{
		chunk_download(&io_context, data, file_path);
	}
	else
	{
		download(&io_context, data, file_path, content_length);
	}

    // Cache session for future resumption
#if SSL_ENABLE_SESSION_CACHE
    br_ssl_engine_get_session_parameters(&client_context.eng, &session_params);
    session_cache::store(host, &session_params);
#endif

	closesocket(socket);
	certificates::close_trust_anchors();
	delete data;

	int result = EXIT_FAILURE;
	if (br_ssl_engine_current_state(&client_context.eng) == BR_SSL_CLOSED)
	{
		int error = br_ssl_engine_last_error(&client_context.eng);
		if (error == 0)
		{
			ssl_debug::log_info("Connection closed cleanly\n");
			ssl_debug::log_handshake_result(&client_context.eng);
			result = EXIT_SUCCESS;
		}
		else
		{
			ssl_debug::log_ssl_error(error);
			result = EXIT_FAILURE;
		}
	}
	else
	{
		ssl_debug::log_error("Socket closed without proper SSL termination\n");
		result = EXIT_FAILURE;
	}

	/* Clean up allocated host and path */
	free(host);
	free(path);

	return result;
}

// Private

/* Helper to check if character is linear whitespace (space or tab) */
static bool is_lws(char c)
{
	return (c == ' ' || c == '\t');
}

void client::populate_headers(br_sslio_context* io_context, data_store* data, pointer_vector<char*>* headers)
{
	unsigned char* read_buffer = (unsigned char*)malloc(READ_BUFFER_SIZE);
	if (read_buffer == NULL)
	{
		ssl_debug::log_error("Failed to allocate read buffer\n");
		return;
	}
	char* pending_header = NULL;  /* For handling line continuations */

    while (true)
    {
		int bytes_read = br_sslio_read(io_context, read_buffer, READ_BUFFER_SIZE);
		if (bytes_read < 0)
		{
			break;
		}

		data->add_range(read_buffer, 0, bytes_read);

		bool eof_headers = false;
		while (true)
		{
			unsigned char* data_buffer = data->get_all();
			int offset = string_utility::find_crlf(data_buffer, data->count());
			if (offset < 0)
			{
				break;
			}

			char* header_line = (char*)malloc(offset + 1);
			if (header_line == NULL)
			{
				break;
			}
			memcpy(header_line, data_buffer, offset);
			header_line[offset] = 0;
			data->remove_range(0, offset + 2);

			/* Empty line signals end of headers */
			if (header_line[0] == 0)
			{
				free(header_line);
				/* Flush any pending header */
				if (pending_header != NULL)
				{
					debug_utility::debug_print("Header Line: %s\n", pending_header);
					headers->add(pending_header);
					pending_header = NULL;
				}
				eof_headers = true;
				break;
			}

			/* RFC 7230: Line continuation - line starts with whitespace */
			if (is_lws(header_line[0]) && pending_header != NULL)
			{
				/* Skip leading whitespace on continuation line */
				char* continuation = header_line;
				while (*continuation && is_lws(*continuation))
				{
					continuation++;
				}

				/* Append to pending header with single space separator */
				size_t pending_len = strlen(pending_header);
				size_t cont_len = strlen(continuation);
				char* merged = (char*)malloc(pending_len + 1 + cont_len + 1);
				if (merged == NULL)
				{
					free(header_line);
					free(pending_header);
					pending_header = NULL;
					break;
				}
				memcpy(merged, pending_header, pending_len);
				merged[pending_len] = ' ';
				memcpy(merged + pending_len + 1, continuation, cont_len + 1);

				free(pending_header);
				free(header_line);
				pending_header = merged;
			}
			else
			{
				/* New header - flush pending if any */
				if (pending_header != NULL)
				{
					debug_utility::debug_print("Header Line: %s\n", pending_header);
					headers->add(pending_header);
				}
				pending_header = header_line;
			}
		}

		if (eof_headers == true)
		{
			break;
		}
    }

	/* Flush any remaining pending header */
	if (pending_header != NULL)
	{
		debug_utility::debug_print("Header Line: %s\n", pending_header);
		headers->add(pending_header);
	}

	free(read_buffer);
}

void client::chunk_download(br_sslio_context* io_context, data_store* data, const char* file_path)
{
	unsigned char* read_buffer = (unsigned char*)malloc(READ_BUFFER_SIZE);
	if (read_buffer == NULL)
	{
		ssl_debug::log_error("Failed to allocate read buffer\n");
		return;
	}

	FILE* file = fopen(file_path, "wb");
	if (file == NULL)
	{
		ssl_debug::log_error("Failed to open file for writing: %s\n", file_path);
		free(read_buffer);
		return;
	}

	int64_t chunk_size = 0;
	bool looking_for_chunk_header = true;

	int64_t bytes_written = 0;
    while (true)
    {
        int bytes_read = br_sslio_read(io_context, read_buffer, READ_BUFFER_SIZE);
		if (bytes_read < 0) 
		{
			break;
		}

		data->add_range(read_buffer, 0, bytes_read);

		if (looking_for_chunk_header == true)
		{
			unsigned char* data_buffer = data->get_all();
			int offset = string_utility::find_crlf(data_buffer, data->count());
			if (offset < 0)
			{
				continue;
			}
			
			char* chunk_hex = (char*)malloc(offset + 1);
			if (chunk_hex == NULL)
			{
				break;
			}
			memcpy(chunk_hex, data_buffer, offset);
			chunk_hex[offset] = 0;

			if (chunk_hex[0] != 0)
			{
				chunk_size = string_utility::hex_to_int64(chunk_hex);
				looking_for_chunk_header = false;
			}

			free(chunk_hex);
			data->remove_range(0, offset + 2);
		}

		if (looking_for_chunk_header == false)
		{
			int64_t bytes_to_get = min(chunk_size, (int64_t)data->count());
			if (bytes_to_get != chunk_size)
			{
				continue;
			}
			if (file != NULL)
			{
				fwrite(data->get_all(), 1, bytes_to_get, file);
			}

			bytes_written += data->count();
			debug_utility::debug_print("Written %lld bytes of unknown bytes\n", bytes_written);

			data->remove_range(0, bytes_to_get);
			looking_for_chunk_header = true;
		}
    }

	fclose(file);
	free(read_buffer);
}

void client::download(br_sslio_context* io_context, data_store* data, const char* file_path, int64_t content_length)
{
	unsigned char* read_buffer = (unsigned char*)malloc(READ_BUFFER_SIZE);
	if (read_buffer == NULL)
	{
		ssl_debug::log_error("Failed to allocate read buffer\n");
		return;
	}

	FILE* file = fopen(file_path, "wb");
	if (file == NULL)
	{
		ssl_debug::log_error("Failed to open file for writing: %s\n", file_path);
		free(read_buffer);
		return;
	}

	int64_t bytes_written = 0;
    while (true)
    {
        int bytes_read = br_sslio_read(io_context, read_buffer, READ_BUFFER_SIZE);
		if (bytes_read < 0) 
		{
			break;
		}

		data->add_range(read_buffer, 0, bytes_read);
		if (file != NULL)
		{
			fwrite(data->get_all(), 1, data->count(), file);
		}

		bytes_written += data->count();
		debug_utility::debug_print("Written %lld bytes of ", bytes_written);
		debug_utility::debug_print("%lld bytes\n", content_length);
		data->remove_range(0, data->count());
    }

	fclose(file);
	free(read_buffer);
}