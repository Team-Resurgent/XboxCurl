#include "socket_utility.h"

#include <xtl.h>
#include <winsockx.h>
#include <stdint.h>

int socket_utility::connect_to_host(uint32_t host_ip, uint16_t port)
{
    sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
	server_addr.sin_addr.S_un.S_addr = host_ip;

    int32_t connect_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (connect_socket == INVALID_SOCKET)
	{
        return -1;
    }

    if (connect(connect_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		closesocket(connect_socket);
        return -1;
    }

	return connect_socket;
}

int socket_utility::host_bind(uint16_t port)
{
	int32_t bind_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (bind_socket == INVALID_SOCKET)
	{
		return -1;
	}

	uint32_t reuse = 1;
	if (setsockopt(bind_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0)
	{
		closesocket(bind_socket);
		return -1;
	}

	uint32_t non_blocking = 1;
	if (ioctlsocket((SOCKET)bind_socket, FIONBIO, &non_blocking) == SOCKET_ERROR)
	{
		closesocket(bind_socket);
		return -1;
	}

	SOCKADDR_IN address_in;
	memset(&address_in, 0, sizeof(SOCKADDR_IN));
	address_in.sin_addr.s_addr = INADDR_ANY;
	address_in.sin_family = AF_INET;
	address_in.sin_port = htons(port);

	if (bind(bind_socket, (struct sockaddr *)&address_in, sizeof(address_in)) == SOCKET_ERROR)
	{
		closesocket(bind_socket);
		return -1;
	}

	if (listen(bind_socket, 5) < 0)
	{
		closesocket(bind_socket);
		return -1;
	}

	return bind_socket;
}

int socket_utility::get_read_status(int socket)
{
	static const timeval instantSpeedPlease = { 0,0 };
	fd_set a = { 1, {(SOCKET)socket} };

	int result = select(0, &a, 0, 0, &instantSpeedPlease);
	if (result == SOCKET_ERROR)
	{
		result = WSAGetLastError();
	}

	if (result != 0 && result != 1)
	{
		return SOCKET_ERROR;
	}
	return result;
}

int socket_utility::accept_client(int server_socket)
{
	sockaddr sock_addr;
	int sock_addr_length = sizeof(sock_addr);
	int32_t socket = accept(server_socket, &sock_addr, &sock_addr_length);
	if (socket == INVALID_SOCKET) 
	{
		return -1;
	}
	return socket;
}

int socket_utility::socket_read(void *context, unsigned char *buffer, size_t length)
{
	int socket = *(int *)context;

	struct timeval tv;
    fd_set read_fds;
	

    while (true)
	{
		FD_ZERO(&read_fds );
		FD_SET(socket, &read_fds );

		tv.tv_sec  = 2;
		tv.tv_usec = 0;

		int ret = select(socket, &read_fds, NULL, NULL, &tv );
		if( ret == 0 )
		{
			return -1;
		}

        int recv_len = (length > 0x7FFFFFFF) ? 0x7FFFFFFF : (int)length;
        int bytes_read = recv(socket, (char *)buffer, recv_len, 0);
        if (bytes_read == SOCKET_ERROR) 
		{
            if (WSAGetLastError() == WSAEINTR || WSAGetLastError() == WSAEWOULDBLOCK) 
			{
                continue;
            }
            return -1;
        }
        if (bytes_read == 0) 
		{
            return 0;
        }
        return bytes_read; 
    }
}

int socket_utility::socket_write(void *context, const unsigned char *buffer, size_t length)
{
    while (true)
	{
        int socket = *(int *)context;
        int send_len = (length > 0x7FFFFFFF) ? 0x7FFFFFFF : (int)length;
        int bytes_written = send(socket, (const char *)buffer, send_len, 0);
        if (bytes_written == SOCKET_ERROR) 
		{
            if (WSAGetLastError() == WSAEINTR || WSAGetLastError() == WSAEWOULDBLOCK) 
			{
                continue; 
            }
            return -1;
        }
        return bytes_written;
    }
}