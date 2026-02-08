#pragma once

#include <stdint.h>

class socket_utility
{
public:
	static int connect_to_host(uint32_t host_ip, uint16_t port);
	static int host_bind(uint16_t port);
	static int get_read_status(int socket);
	static int accept_client(int server_socket);
	static int socket_read(void *context, unsigned char *buffer, size_t length);
	static int socket_write(void *context, const unsigned char *buffer, size_t length);
};
