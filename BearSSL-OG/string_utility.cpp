#include "string_utility.h"
#include "pointer_vector.h"

#include <xtl.h>
#include <stdint.h>
#include <stdio.h>

/* MSVC 7.1 lacks va_copy. On x86, va_list is a char* passed by value,
   so a plain assignment creates an independent copy. */
#ifndef va_copy
#define va_copy(dest, src) ((dest) = (src))
#endif

char* string_utility::format_string(const char* format, ...)
{
    va_list args, args_copy;
    va_start(args, format);
    va_copy(args_copy, args);

	uint32_t length = _vsnprintf(NULL, 0, format, args_copy);
	va_end(args_copy);

	char* result = (char*)malloc(length + 1);
	if (result == NULL)
	{
		va_end(args);
		return NULL;
	}
	_vsnprintf(result, length + 1, format, args);
	result[length] = 0;

    va_end(args);
    return result;
}

char* string_utility::strtok_r(char* str, const char* delimiters, char** save_ptr) 
{
    char* token;

    if (str == NULL)
	{
        str = *save_ptr;
	}

    if (*str == '\0') 
	{
        *save_ptr = str;
        return NULL;
    }

	str += strspn(str, delimiters);

	if (*str == '\0') 
	{
        *save_ptr = str;
        return NULL;
    }

	token = str + strcspn(str, delimiters);
	if (*token == '\0')
    {
      *save_ptr = token;
      return str;
    }

	*token = '\0';
	*save_ptr = token + 1;
	return str;
}

char* string_utility::left_trim(const char* value, const char trim_char)
{
    uint32_t offset = 0;
    while(value[offset] == trim_char && value[offset] != 0) 
    {
        offset++;
    }

    uint32_t length = strlen(value) - offset;

    char* result = (char*)malloc(length + 1);
    if (result == NULL)
    {
        return NULL;
    }

    strncpy(result, value + offset, length);
    result[length] = 0;
    return result;
}

char* string_utility::right_trim(const char* value, const char trim_char)
{
    if (value == NULL) return NULL;

    int32_t length = strlen(value);

    while(length > 0 && value[length - 1] == trim_char)
    {
        length--;
    }

    char* result = (char*)malloc(length + 1);
    if (result == NULL)
    {
        return NULL;
    }

    strncpy(result, value, length);
    result[length] = 0;
    return result;
}

char* string_utility::trim(const char* value, const char trim_char)
{
	char* leftTrimmed = left_trim(value, trim_char);
	char* trimmed = right_trim(leftTrimmed, trim_char);
	free(leftTrimmed);
	return trimmed;
}

pointer_vector<char*>* string_utility::split(const char* value, const char* delimiter, bool trim_values) 
{
	pointer_vector<char*>* result = new pointer_vector<char*>(false);

	char* value_copy = strdup(value);
	char* position = value_copy;
	char* token = strtok_r(value_copy, delimiter, &position);
	while (token != NULL)
	{
		char* value_to_add = trim_values == true ? trim(token, ' ') : strdup(token);
		result->add(value_to_add);
		token = strtok_r(NULL, delimiter, &position);
	}

	free(value_copy);
    return result;
}

pointer_vector<char*>* string_utility::split_first(const char* value, const char* delimiter, bool trim_values) 
{
	pointer_vector<char*>* result = new pointer_vector<char*>(false);

    char* str = new char[strlen(value) + 1]; 
    strcpy(str, value);

	char* save_ptr = NULL;
    char* first_part = string_utility::strtok_r(str, delimiter, &save_ptr);
    char* second_part = string_utility::strtok_r(NULL, "", &save_ptr);

    if (first_part != NULL) 
	{
		result->add(trim_values ? trim(first_part, ' ') : strdup(first_part));
    }

    if (second_part != NULL) 
	{
		result->add(trim_values ? trim(second_part, ' ') : strdup(second_part));
    }

    delete[] str;

	return result;
}

int64_t string_utility::string_to_int64(const char* string) 
{
	int64_t result = 0;
	if (string == NULL)
	{
		return result;
	}

	bool is_negative = false;
	if (*string == '-') 
	{
        is_negative = true;
        string++;
    }

    while (*string != '\0') 
	{
        if (*string < '0' || *string > '9') 
		{
			break; 
		}
        result = result * 10 + (*string - '0');
        string++;
    }

	return is_negative ? -result : result;
}

int64_t string_utility::hex_to_int64(const char* hex)
{
    int64_t result = 0;
    
    while (*hex != '\0') 
	{
        char c = *hex;
        result *= 16; 

        if (c >= '0' && c <= '9') 
		{
            result += c - '0'; 
        } 
        else if (c >= 'A' && c <= 'F') 
		{
            result += c - 'A' + 10; 
        } 
        else if (c >= 'a' && c <= 'f') 
		{
            result += c - 'a' + 10; 
        } 
        else 
		{
            return -1; 
        }
        
        ++hex;
    }
    return result;
}

int string_utility::find_crlf(unsigned char* buffer, uint32_t length)
{
    if (buffer == NULL || length < 2)
	{
		return -1;
	}
    for (uint32_t i = 0; i < length - 1; ++i) 
	{
        if (buffer[i] == '\r' && buffer[i + 1] == '\n') 
		{
            return i;
        }
    }
    return -1; 
}
