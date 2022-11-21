#ifndef MY_ALLOC_H
#define MY_ALLOC_H

#include <sys/types.h>

// this function should be called exactly once before the first call to mm_alloc or mm_free,
// with a block of memory and its size as parameters
void init_mini_malloc(void* buffer, size_t blocksize);

// returns a pointer to size bytes of memory, aligned to 8 bytes
void* mm_alloc(size_t size);

// free a block of memory previously allocated by mm_alloc
void mm_free(void* ptr);

#endif
