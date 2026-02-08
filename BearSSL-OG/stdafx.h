#pragma once

#include <xtl.h>
#include <stdint.h>

typedef struct STRING {
	uint16_t Length;
	uint16_t MaximumLength;
	char* Buffer;
} STRING;

extern "C" 
{
	LONG WINAPI IoCreateSymbolicLink(STRING*, STRING*);
}
