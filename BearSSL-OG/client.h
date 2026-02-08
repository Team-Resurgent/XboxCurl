#pragma once

#include "pointer_vector.h"
#include "data_store.h"

#include <stdint.h>
#include <bearssl.h>

class client
{
public:
	int download_file(const char* url, uint16_t port, const char* file_path);
private:
	void populate_headers(br_sslio_context* io_context, data_store* data, pointer_vector<char*>* headers);
	void chunk_download(br_sslio_context* io_context, data_store* data, const char* file_path);
	void download(br_sslio_context* io_context, data_store* data, const char* file_path, int64_t content_length);
};