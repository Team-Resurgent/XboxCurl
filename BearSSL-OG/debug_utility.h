#pragma once

#ifdef _DEBUG
#define debug_log debug_utility::debug_print
#else
#define debug_log(...) ((void)0)
#endif

class debug_utility
{
public:
	static int debug_print(const char* format, ...);
};
