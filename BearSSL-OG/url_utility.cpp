#include "url_utility.h"
#include "pointer_vector.h"
#include "string_utility.h"

bool url_utility::parse_url(const char* url, char** host, char** path)
{
	bool result = false;

	pointer_vector<char*>* url_parts = string_utility::split_first(url, "://", true);
	if (url_parts->count() == 2)
	{
		pointer_vector<char*>* domain_parts = string_utility::split_first(url_parts->get(1), "/", true);
		if (domain_parts->count() == 2)
		{
			*host = strdup(domain_parts->get(0));
			*path = string_utility::format_string("/%s", domain_parts->get(1));
			if (*host != NULL && *path != NULL)
			{
				result = true;
			}
			else
			{
				/* Allocation failed — clean up partial results */
				free(*host);
				free(*path);
				*host = NULL;
				*path = NULL;
			}
		}
		delete(domain_parts);
	}
	delete(url_parts);

	return result;
}

