#pragma once

#include <xtl.h>
#include <stdint.h>

class server
{
public:
	server();
	void start(uint16_t port);
	void stop();
	bool is_running();
private:
	HANDLE thread;
	volatile bool running;
};
