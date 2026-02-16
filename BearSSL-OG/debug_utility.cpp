#include "debug_utility.h"

#include <xtl.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef _DEBUG

int debug_utility::debug_print(const char* format, ...)
{
	/* Use a fixed buffer since VS2003 doesn't support va_copy */
	char message[512];
	va_list args;
	int length;

	va_start(args, format);
	length = _vsnprintf(message, sizeof(message) - 1, format, args);
	va_end(args);

	/* Ensure null termination */
	if (length < 0 || length >= (int)sizeof(message)) {
		message[sizeof(message) - 1] = '\0';
		length = (int)sizeof(message) - 1;
	} else {
		message[length] = '\0';
	}

	OutputDebugStringA(message);
	return length;
}

#endif