#include "server.h"
#include "debug_utility.h"
#include "socket_utility.h"

#include <xtl.h>
#include <winsockx.h>
#include <stdio.h>
#include <string.h>
#include <bearssl.h>
#include "ssl_config.h"
#include "ssl_debug.h"

#if !(SERVER_RSA || SERVER_EC || SERVER_MIXED)
#define SERVER_RSA     1
#define SERVER_EC      0
#define SERVER_MIXED   0
#endif

#if SERVER_RSA
#include "chain-rsa.h"
#include "key-rsa.h"
#define SKEY   RSA
#elif SERVER_EC
#include "chain-ec.h"
#include "key-ec.h"
#define SKEY   EC
#elif SERVER_MIXED
#include "chain-ec+rsa.h"
#include "key-ec.h"
#define SKEY   EC
#else
#error Must use one of RSA, EC or MIXED chains.
#endif


#define MAX_NUM_THREADS 5

typedef struct {
    int client_socket;
    int thread_complete;
	uint16_t port;
} thread_info_t;

typedef struct {
    int active;
    thread_info_t data;
    HANDLE thread;
} pthread_info_t;

static pthread_info_t threads[MAX_NUM_THREADS];
static volatile bool server_running = false;
static int listen_socket_global = INVALID_SOCKET;

// Server session cache
static br_ssl_session_cache_lru server_session_cache;
static unsigned char server_session_cache_store[4096];
static bool server_cache_initialized = false;

static const char *HTTP_RES =
	"HTTP/1.1 200 OK\r\n"
	"Cache-Control: no-store, no-cache, must-revalidate\r\n"
	"Pragma: no-cache\r\n"
	"Expires: 0\r\n"
	//"Content-Length: 46\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html; charset=iso-8859-1\r\n"
	"\r\n"
	"<head><link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css\"></head>"
	"<html>\r\n"
	"<body>\r\n"
	"<main class=\"container\"><h1>BearSSL Test by EqUiNoX</h1><a href=\"https://doomonline1.vercel.app/dos.html\" target=\"_blank\">Play Doom</a></main>\r\n"
	"</body>\r\n"
	"</html>\r\n";

static void init_server_session_cache()
{
    if (server_cache_initialized) return;

    br_ssl_session_cache_lru_init(&server_session_cache,
                                   server_session_cache_store,
                                   sizeof(server_session_cache_store));
    server_cache_initialized = true;
    ssl_debug::log_verbose("Server session cache initialized\n");
}

static void client_process(void* data)
{
	thread_info_t *thread_info = (thread_info_t*)data;

	unsigned char io_buffer[BR_SSL_BUFSIZE_BIDI];

	br_ssl_server_context server_context;

#if SERVER_RSA /* RSA */
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
	br_ssl_server_init_mine2c(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#else
	br_ssl_server_init_mine2g(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#endif
#elif SERVER_PROFILE_MIN_NOFS
	br_ssl_server_init_minr2g(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#else
	br_ssl_server_init_full_rsa(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#endif
#elif SERVER_EC /* EC */
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
	br_ssl_server_init_minf2c(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#else
	br_ssl_server_init_minf2g(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#endif
#elif SERVER_PROFILE_MIN_NOFS
	br_ssl_server_init_minv2g(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#else
	br_ssl_server_init_full_ec(&server_context, CHAIN, CHAIN_LEN, BR_KEYTYPE_EC, &SKEY);
#endif
#else /* SERVER_MIXED */
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
	br_ssl_server_init_minf2c(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#else
	br_ssl_server_init_minf2g(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#endif
#elif SERVER_PROFILE_MIN_NOFS
	br_ssl_server_init_minu2g(&server_context, CHAIN, CHAIN_LEN, &SKEY);
#else
	br_ssl_server_init_full_ec(&server_context, CHAIN, CHAIN_LEN, BR_KEYTYPE_RSA, &SKEY);
#endif
#endif

    // Enable session cache
    init_server_session_cache();
    br_ssl_server_set_cache(&server_context, &server_session_cache.vtable);

	br_ssl_engine_set_buffer(&server_context.eng, io_buffer, BR_SSL_BUFSIZE_BIDI, 1);
	br_ssl_server_reset(&server_context);

    // Enforce TLS 1.2 minimum
#if SSL_ENFORCE_TLS12
    br_ssl_engine_set_versions(&server_context.eng, SSL_MIN_VERSION, SSL_MAX_VERSION);
#endif

	br_sslio_context io_context;
	br_sslio_init(&io_context, &server_context.eng, socket_utility::socket_read, &thread_info->client_socket, socket_utility::socket_write, &thread_info->client_socket);

	bool client_dropped = false;

	int feed_count = 0;
	while (true)
	{
		unsigned char current_char;
		if (br_sslio_read(&io_context, &current_char, 1) < 0) 
		{
			client_dropped = true;
			break;
		}
		if (current_char == 0x0D) 
		{
			continue;
		}
		if (current_char == 0x0A) 
		{
			if (feed_count == 1) 
			{
				break;
			}
			feed_count = 1;
		} 
		else 
		{
			feed_count = 0;
		}
	}

	if (client_dropped == false)
	{
		br_sslio_write_all(&io_context, HTTP_RES, strlen(HTTP_RES));
	}

	int error = br_ssl_engine_last_error(&server_context.eng);
	if (error == 0)
	{
		ssl_debug::log_info("Client connection closed cleanly\n");
		ssl_debug::log_handshake_result(&server_context.eng);
	}
	else
	{
		ssl_debug::log_ssl_error(error);
	}

	br_sslio_close(&io_context);
	closesocket(thread_info->client_socket);

	thread_info->thread_complete = 1;
}

static uint64_t WINAPI process(void* data)
{
    uint16_t port = (uint16_t)data;

	int listen_socket = socket_utility::host_bind(port);
	if (listen_socket == INVALID_SOCKET)
	{
		server_running = false;
		return EXIT_FAILURE;
	}

	listen_socket_global = listen_socket;

	while (server_running)
	{
		int read_status = socket_utility::get_read_status(listen_socket);
		if (read_status == SOCKET_ERROR)
		{
			break;
		}

		int client_socket = INVALID_SOCKET;
		if (read_status == 1)
		{
			client_socket = socket_utility::accept_client(listen_socket);
		}
		else
		{
			Sleep(50);
			continue;
		}

		if (client_socket == INVALID_SOCKET)
		{
			continue;
		}

		int i;
		for (i = 0; i < MAX_NUM_THREADS; i++)
		{
			if (threads[i].active == 0)
			{
				break;
			}
			if (threads[i].data.thread_complete == 1)
			{
				CloseHandle(threads[i].thread);
				memset(&threads[i], 0, sizeof(pthread_info_t));
				break;
			}
		}

		if (i == MAX_NUM_THREADS)
		{
			closesocket(client_socket);
			continue;
		}

		threads[i].active = 1;
		threads[i].data.client_socket = client_socket;
		threads[i].data.port = port;
		threads[i].thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)client_process, (void*)&threads[i].data, 0, NULL);
	}

	closesocket(listen_socket);
	listen_socket_global = INVALID_SOCKET;

	return 0;
}


server::server()
	: thread(NULL), running(false)
{
}

void server::start(uint16_t port)
{
	memset(threads, 0, sizeof(threads));
	running = true;
	server_running = true;
	thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)process, (void*)port, 0, NULL);
}

void server::stop()
{
	if (!running)
	{
		return;
	}

	running = false;
	server_running = false;

	// Close the listening socket to unblock accept
	if (listen_socket_global != INVALID_SOCKET)
	{
		closesocket(listen_socket_global);
	}

	// Wait for the main server thread to finish
	if (thread != NULL)
	{
		WaitForSingleObject(thread, 5000);
		CloseHandle(thread);
		thread = NULL;
	}

	// Wait for all client threads to complete
	for (int i = 0; i < MAX_NUM_THREADS; i++)
	{
		if (threads[i].active && threads[i].thread != NULL)
		{
			WaitForSingleObject(threads[i].thread, 2000);
			CloseHandle(threads[i].thread);
		}
	}

	memset(threads, 0, sizeof(threads));
}

bool server::is_running()
{
	return running;
}




