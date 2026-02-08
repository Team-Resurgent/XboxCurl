#pragma once

#include <stdint.h>

/* Default DNS timeout in milliseconds (30 seconds) */
#define DNS_TIMEOUT_MS 30000

class network_utility
{
public:
	static bool init();
	static bool is_ready();
	static bool wait_ready();
	static uint32_t resolve_host(const char* host);
	static uint32_t resolve_host_with_timeout(const char* host, uint32_t timeout_ms);
};
