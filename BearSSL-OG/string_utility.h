#pragma once

#include "pointer_vector.h"

class string_utility
{
public:
	static char* format_string(const char* format, ...);
	static char* strtok_r(char* str, const char* delimiters, char** save_ptr);
	static char* left_trim(const char* value, const char trim_char);
	static char* right_trim(const char* value, const char trim_char);
	static char* trim(const char* value, const char trim_char);
	static pointer_vector<char*>* split(const char* value, const char* delimiter, bool trim_values);
	static pointer_vector<char*>* split_first(const char* value, const char* delimiter, bool trim_values);
	static int64_t string_to_int64(const char* string);
	static int64_t hex_to_int64(const char* hex);
	static int find_crlf(unsigned char* buffer, uint32_t length);
};
