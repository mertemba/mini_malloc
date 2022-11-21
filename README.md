# MiniMalloc

Memory allocation library similar to `malloc`, focused on low memory overhead,
using a given memory block (e.g. an arena).

## Usage examples

```c
#include <mini_malloc.h>

#define BLOCKSIZE 1024

int main(void) {
    void* block = malloc(BLOCKSIZE);
    init_mini_malloc(block, BLOCKSIZE);
    void* foo = mm_alloc(32);
    mm_free(foo);
    free(block);
    return 0;
}
```

## Implementation details

The allocator is implemented to have low memory overhead (8 bytes per allocated
block, 272 bytes static in addition). Allocations use one of 60 fixed memory
sizes, divisible by 8 and increasing in size by a factor of `pow(2.0, 0.25)`.
Freed nodes are reinserted into the free memory pool, adjacent free nodes are
joined. Allocation should be quite efficient, though no optimizations regarding
cache locality or multi-threading were considered.

## Limitations

* The library only supports a single provided memory block.
* Multi-threading is not considered and must be handled by the library user.
* Allocations above `1<<19` bytes are currently not supported, but easy to add
  to the largest size bucket.
* A `realloc()` function is not provided.

## License

This repo is released under the BSD 3-Clause License. See LICENSE file for
details.
