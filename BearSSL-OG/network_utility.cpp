#include "network_utility.h"

#include <xtl.h>
#include <winsockx.h>
#include <stdint.h>

#define RECV_SOCKET_BUFFER_SIZE_IN_K 64
#define RECV_SOCKET_BUFFER_SIZE RECV_SOCKET_BUFFER_SIZE_IN_K * 1024
#define SEND_SOCKET_BUFFER_SIZE_IN_K 64
#define SEND_SOCKET_BUFFER_SIZE SEND_SOCKET_BUFFER_SIZE_IN_K * 1024

static bool initialized = false;

bool network_utility::init()
{
	if (initialized == true)
	{
		return false;
	}

	XNetStartupParams xnsp;
	memset(&xnsp, 0, sizeof(xnsp));
	xnsp.cfgSizeOfStruct = sizeof(XNetStartupParams);
	xnsp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;

	xnsp.cfgPrivatePoolSizeInPages = 64;
	xnsp.cfgEnetReceiveQueueLength = 16;
	xnsp.cfgIpFragMaxSimultaneous = 16;
	xnsp.cfgIpFragMaxPacketDiv256 = 32;
	xnsp.cfgSockMaxSockets = 64;

	xnsp.cfgSockDefaultRecvBufsizeInK = RECV_SOCKET_BUFFER_SIZE_IN_K;
	xnsp.cfgSockDefaultSendBufsizeInK = SEND_SOCKET_BUFFER_SIZE_IN_K;

	int xnet_result = XNetStartup(&xnsp);
	if (xnet_result != 0)
	{
		return false;
	}

	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (result != 0)
	{
		return false;
	}
	initialized = true;
	return true;
}

bool network_utility::is_ready()
{
	if (initialized == false)
	{
		return false;
	}
	XNADDR addr;
	memset(&addr, 0, sizeof(addr));
	DWORD dwState = XNetGetTitleXnAddr(&addr);
	return dwState != XNET_GET_XNADDR_PENDING;
}

bool network_utility::wait_ready()
{
	if (initialized == false)
	{
		return false;
	}
	while (is_ready() == false)
	{
		Sleep(1000);
	}
	return true;
}

uint32_t network_utility::resolve_host(const char* host)
{
	return resolve_host_with_timeout(host, DNS_TIMEOUT_MS);
}

uint32_t network_utility::resolve_host_with_timeout(const char* host, uint32_t timeout_ms)
{
	uint32_t result = 0; /* Return 0 (INADDR_ANY/invalid) on failure */
	XNDNS* dns = NULL;
	WSAEVENT event_handle = NULL;

	/* Validate input */
	if (host == NULL || host[0] == '\0')
	{
		return 0;
	}

	/* Create event for async DNS notification */
	event_handle = WSACreateEvent();
	if (event_handle == NULL)
	{
		return 0;
	}

	/* Initiate DNS lookup */
	int error = XNetDnsLookup(host, event_handle, &dns);
	if (error != 0)
	{
		WSACloseEvent(event_handle);
		return 0;
	}

	/* Wait for DNS response with timeout */
	DWORD wait_result = WaitForSingleObject(event_handle, timeout_ms);
	WSACloseEvent(event_handle);

	/* Check if we timed out */
	if (wait_result == WAIT_TIMEOUT)
	{
		XNetDnsRelease(dns);
		return 0;
	}

	/* Check result and extract address */
	if (dns->iStatus == 0 && dns->cina > 0)
	{
		result = dns->aina[0].S_un.S_addr;
	}

	XNetDnsRelease(dns);
	return result;
}