#include "debug.h"
#include <xtl.h>
#include <stdio.h>
#include <stdarg.h>

void debug::print(const char* format, ...)
{
#ifdef _DEBUG
    va_list args;
    va_start(args, format);

    long length = _vsnprintf(NULL, 0, format, args);

    char* message = (char*)malloc(length + 1);
    _vsnprintf(message, length, format, args);
    message[length] = 0;

    va_end(args);

    OutputDebugStringA(message);
    free(message);
#else
    (void)format; 
#endif
}