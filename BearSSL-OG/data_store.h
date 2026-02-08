#pragma once

#define DATA_SIZE_INCREMENT 65536

#include <stdint.h>

class data_store
{
public:
	data_store();
	~data_store();

	void add(unsigned char value);
	void add_range(unsigned char* buffer, uint32_t offset, uint32_t length);
	void remove(uint32_t index);
	void remove_range(uint32_t index, uint32_t count);
	unsigned char get(uint32_t index);
	unsigned char* get_all();
	uint32_t count();
	void clear();

private:

    unsigned char* mValueContainer;
    uint32_t mSize;
    uint32_t mMaxSize;
};

