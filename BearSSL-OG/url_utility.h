#pragma once

class url_utility
{
public:
	static bool parse_url(const char* url, char** host, char** path);
};
