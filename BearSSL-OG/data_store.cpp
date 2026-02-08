#include "data_store.h"

#include <xtl.h>
#include <stdint.h>

data_store::data_store()
{
	mSize = 0;
	mMaxSize = DATA_SIZE_INCREMENT;
	mValueContainer = (unsigned char*)malloc(mMaxSize);
	if (mValueContainer == NULL)
	{
		mMaxSize = 0;
		return;
	}
}

data_store::~data_store()
{
	free(mValueContainer);
}

void data_store::add(unsigned char value)
{
	if (mSize == mMaxSize)
	{
		unsigned char* reallocedValueContainers = (unsigned char*)realloc(mValueContainer, (mMaxSize + DATA_SIZE_INCREMENT));
		if (reallocedValueContainers == NULL)
		{ 
			return;
		}
		mMaxSize += DATA_SIZE_INCREMENT;
		mValueContainer = reallocedValueContainers;
	}

	mValueContainer[mSize] = value;
	mSize++;
}

void data_store::add_range(unsigned char* buffer, uint32_t offset, uint32_t length)
{
	if (buffer == NULL || length == 0)
	{
		return;
	}
	for (uint32_t i = 0; i < length; i++)
	{
		add(buffer[offset + i]);
	}
}

void data_store::remove(uint32_t index)
{
	if (index >= mSize)
	{
		return;
	}
	for (uint32_t j = index; j < mSize - 1; j++)
	{
		mValueContainer[j] = mValueContainer[j + 1];
	}
	mSize--;
}

void data_store::remove_range(uint32_t index, uint32_t count)
{
    if (count == 0)
    {
        return;
    }
    if (index + count > mSize)
    {
        /* Clamp: remove everything from index onward */
        mSize = index;
        return;
    }
    for (uint32_t j = index; j < mSize - count; j++)
    {
        mValueContainer[j] = mValueContainer[j + count];
    }
    mSize -= count;
}

unsigned char data_store::get(uint32_t index)
{
	if (index >= mSize)
	{
		return 0;
	}
	return mValueContainer[index];
}

unsigned char* data_store::get_all()
{
	return mValueContainer;
}

uint32_t data_store::count()
{
	return mSize;
}

void data_store::clear()
{    
	mSize = 0;
}


