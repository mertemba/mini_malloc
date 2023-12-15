#include <math.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "mini_malloc.h"

#define DEBUG 0
#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>

#define REFCOUNT 1

#define ALIGN 8
#define SIZES_COUNT 59

#define MAX_PTRDIFF_VAL ((INT64_C(1) << 31) - 1)

#if REFCOUNT
#define SIZE_BITS 24
#define MAX_REFCOUNT ((1ull << 16) - 1)
#else
#define SIZE_BITS 32
#endif
// TODO: with smarter size storing, this can be increased to (1ull << SIZE_BITS) * ALIGN
#define MAX_ALLOC_SIZE ((1ull << SIZE_BITS) - 1)

// for an allocated node, only the first 8 bytes of the struct are needed.
#define ALLOC_NODE_SIZE 8
#define ALLOCATED_FLAG UINT32_C(1)

typedef uint8_t byte;
typedef uint32_t size_type;
typedef int16_t size_index_type;
typedef int32_t ptrdiff_type;

typedef struct
#if REFCOUNT
        __attribute__((__packed__))
#endif
memnode {
    size_type size: SIZE_BITS; // allocatable size in bytes
    size_type prev_node_size: SIZE_BITS; // 0 if this is the first node in block; MSB set if node is allocated (ALLOCATED_FLAG)
#if REFCOUNT
    uint16_t refcount;
#endif
    ptrdiff_type d_next_free_node;
    ptrdiff_type d_prev_free_node;
} memnode;

static inline bool is_allocated(memnode* node) {
    return (node->prev_node_size & ALLOCATED_FLAG) != 0;
}

static inline void set_allocated(memnode* node) {
    node->prev_node_size |= ALLOCATED_FLAG;
#if REFCOUNT
    node->refcount = 1;
#endif
}

static inline void set_unallocated(memnode* node) {
    node->prev_node_size &= ~ALLOCATED_FLAG;
}

static memnode* get_next_free_node(memnode* node) {
    assert(!is_allocated(node));
    if (node->d_next_free_node == 0) {
        return NULL;
    }
    return (memnode*) (node->d_next_free_node + (byte*) node);
}

static memnode* get_prev_free_node(memnode* node) {
    assert(!is_allocated(node));
    if (node->d_prev_free_node == 0) {
        return NULL;
    }
    return (memnode*) (node->d_prev_free_node + (byte*) node);
}

static void set_next_free_node(memnode* node, memnode* next_free_node) {
    assert(!is_allocated(node));
    if (next_free_node == NULL) {
        node->d_next_free_node = 0;
        return;
    }
    ptrdiff_t ptrdiff = (byte*) next_free_node - (byte*) node;
    assert(ptrdiff > -MAX_PTRDIFF_VAL);
    assert(ptrdiff < MAX_PTRDIFF_VAL);
    node->d_next_free_node = (ptrdiff_type) ptrdiff;
}

static void set_prev_free_node(memnode* node, memnode* prev_free_node) {
    assert(!is_allocated(node));
    if (prev_free_node == NULL) {
        node->d_prev_free_node = 0;
        return;
    }
    ptrdiff_t ptrdiff = (byte*) prev_free_node - (byte*) node;
    assert(ptrdiff > -MAX_PTRDIFF_VAL);
    assert(ptrdiff < MAX_PTRDIFF_VAL);
    node->d_prev_free_node = (ptrdiff_type) ptrdiff;
}

static size_type get_prev_node_size(memnode* node) {
    return node->prev_node_size & ~ALLOCATED_FLAG;
}

static void set_prev_node_size(memnode* node, size_type prev_node_size) {
    assert(is_allocated(node));
    node->prev_node_size = prev_node_size | ALLOCATED_FLAG;
}

#undef ALLOCATED_FLAG

static ptrdiff_type (* free_nodes)[SIZES_COUNT];
static size_type sizes[SIZES_COUNT];

static int uint64_log2(uint64_t n) {
#define S(k) if (n >= (UINT64_C(1) << k)) { i += k; n >>= k; }
    int i = -(n == 0);
    S(32);
    S(16);
    S(8);
    S(4);
    S(2);
    S(1);
    return i;
#undef S
}

static size_index_type get_size_index_upper(size_type size_) {
    assert(size_ % ALIGN == 0);
    uint64_t size = size_ / ALIGN;
    if (size <= 4) {
        return size - 1;
    }
    if (size > (1ull << 16)) {
        return SIZES_COUNT - 1;
    }
    size *= size;
    size *= size;
    return uint64_log2(size - 1ull) - 5;
}

static size_index_type get_size_index_lower(size_type size) {
    size_index_type idx = get_size_index_upper(size);
    while (size < sizes[idx]) {
        --idx;
    }
    return idx;
}

static memnode* get_free_nodes_head(size_index_type size_index) {
    return (memnode*) ((byte*) &((*free_nodes)[size_index]) - ALLOC_NODE_SIZE);
}

static memnode* get_free_nodes_first(size_index_type size_index) {
    return get_next_free_node(get_free_nodes_head(size_index));
}

static void attach_free_nodes(memnode* node1, memnode* node2) {
    if (node1 != NULL) {
        set_next_free_node(node1, node2);
    }
    if (node2 != NULL) {
        set_prev_free_node(node2, node1);
    }
}

static memnode* get_prev_node(memnode* node) {
    size_type prev_node_size = get_prev_node_size(node);
    if (prev_node_size == 0) {
        return NULL;
    }
    return (memnode*) (((byte*) node) - (prev_node_size + ALLOC_NODE_SIZE));
}

static memnode* get_next_node(memnode* node) {
    memnode* next_node = (memnode*) (((byte*) node) + (node->size + ALLOC_NODE_SIZE));
    // last node in a block has size 0
    if (next_node->size == 0) {
        return NULL;
    }
    return next_node;
}

static void check_prev_next_prts(memnode* node) {
#if DEBUG
    printf("Checking node %p.\n", (void*) node);
#endif
    if (node == NULL) {
        return;
    }
#if DEBUG
    printf("  Size %d.\n", node->size);
#endif
    if (is_allocated(node)) {
#if DEBUG
        printf("  Previous node size: %d.\n", get_prev_node_size(node));
        printf("  Previous node: %p.\n", (void*) get_prev_node(node));
#endif
        if (get_prev_node(node) != NULL) {
#if DEBUG
            printf("  node->prev_node_size: %d; get_prev_node(node)->size: %d.\n",
                   get_prev_node_size(node), (int32_t) get_prev_node(node)->size);
#endif
            assert(get_prev_node_size(node) == get_prev_node(node)->size);
            assert(get_next_node(get_prev_node(node)) == node);
        }
#if DEBUG
        printf("  Next node: %p.\n", (void*) get_next_node(node));
#endif
        if (get_next_node(node) != NULL && is_allocated(get_next_node(node))) {
#if DEBUG
            printf("  get_next_node(node)->prev_node_size: %d; node->size: %d.\n",
                   get_prev_node_size(get_next_node(node)), node->size);
#endif
            assert(get_prev_node_size(get_next_node(node)) == node->size);
            assert(get_prev_node(get_next_node(node)) == node);
        }
    } else {
        // unallocated
        if (node->d_prev_free_node != 0) {
            assert(get_next_free_node(get_prev_free_node(node)) == node);
        }
        if (get_next_free_node(node) != NULL) {
            assert(get_prev_free_node(get_next_free_node(node)) == node);
        }
    }
}

static void prepend_free_node(memnode* node, size_index_type size_index) {
    memnode* old_first_free = get_free_nodes_first(size_index);
    attach_free_nodes(get_free_nodes_head(size_index), node);
    attach_free_nodes(node, old_first_free);
    check_prev_next_prts(node);
    check_prev_next_prts(old_first_free);
#if DEBUG
    printf("Prepended new node %p into size index %d.\n", (void*) node, size_index);
    printf("free_nodes[%d] == %p.\n", size_index, (void*) get_free_nodes_first(size_index));
#endif
}

void init_mini_malloc(void* buffer, size_t blocksize) {
    byte* ptr = (byte*) buffer;
#if DEBUG
    printf("Allocated node header size: %u\n", ALLOC_NODE_SIZE);
    printf("Free node header size: %lu\n", sizeof(memnode));
    printf("Max. nodes per block: %lu\n", (blocksize - sizeof(memnode)) / (ALLOC_NODE_SIZE + ALIGN));
#endif
    // ensure 8-byte alignment
    assert((ALLOC_NODE_SIZE % 8) == 0);
    assert(sizeof(memnode) == 16);

    // init block_node_size array
    for (uint32_t bits = 1; bits <= 64; ++bits) {
        uint64_t size = ((uint64_t) (pow(2.0, bits / 4.0) + 0.001)) * ALIGN;
        size_index_type idx = get_size_index_upper(size);
        sizes[idx] = size;
#if DEBUG
        printf("Size %lu at index %d\n", size, idx);
#endif
    }
#if DEBUG
    // self-check
    for (uint64_t size = ALIGN; size <= (1ull << 16) * ALIGN; size += ALIGN) {
        int idx = get_size_index_upper(size);
        uint64_t idx_size = sizes[idx];
        // printf("Size %lu at upper index %d (idx_size: %lu).\n", size, idx, idx_size);
        if (idx_size / ALIGN <= 4) {
            assert (idx_size == size);
        } else {
            assert(idx_size >= size);
            assert(idx_size < size * 1.19);
        }

        idx = get_size_index_lower(size);
        idx_size = sizes[idx];
        // printf("Size %lu at lower index %d (idx_size: %lu).\n", size, idx, idx_size);
        if (idx_size / ALIGN <= 4) {
            assert (idx_size == size);
        } else {
            assert(size >= idx_size);
            assert(size < idx_size * 1.2);
        }
    }
#endif

    free_nodes = NULL;
#if DEBUG
    printf("Allocating new block.\n");
#endif
    size_type block_node_size = blocksize - 2 * ALLOC_NODE_SIZE;
    // fill free_nodes array
    size_t free_nodes_size = ((sizeof(*free_nodes) + sizeof(ptrdiff_type) + ALIGN - 1) / ALIGN) * ALIGN;
    block_node_size -= free_nodes_size;
    free_nodes = (ptrdiff_type (*)[SIZES_COUNT]) ((ptrdiff_type*) ptr + 1);
    ptr += free_nodes_size;
    for (size_index_type size_index = -1; size_index < SIZES_COUNT; size_index++) {
        (*free_nodes)[size_index] = 0;
    }
    assert(ptr >= (byte*) &(*free_nodes)[SIZES_COUNT]);
    // allocate first block
    memnode* block_node = (memnode*) ptr;
    assert(block_node != NULL);
    block_node->d_next_free_node = 0;
    block_node->prev_node_size = 0; // also sets to unallocated
    set_prev_free_node(block_node, get_free_nodes_head(SIZES_COUNT - 1));
    block_node->size = block_node_size;
    memnode* last_node = (memnode*) (((byte*) block_node) + (block_node->size + ALLOC_NODE_SIZE));
    set_allocated(last_node);
    last_node->size = 0;
    set_next_free_node(get_free_nodes_head(SIZES_COUNT - 1), block_node);
    assert((byte*) last_node + ALLOC_NODE_SIZE == (byte*) buffer + blocksize);
    check_prev_next_prts(block_node);
#if DEBUG
    printf("First node size: %d bytes.\n", block_node->size);
    printf("Block overhead: %lu\n", blocksize - (int) get_free_nodes_first(SIZES_COUNT - 1)->size);
#endif
}

void* mm_alloc(size_t size) {
    if (size == 0) return NULL;
    if (size > MAX_ALLOC_SIZE) return NULL;

    if (size % ALIGN) {
        size += ALIGN - size % ALIGN;
    }
    size_index_type size_index = get_size_index_upper(size);
#if DEBUG
    printf("\nAlloc of %ld bytes.\n", size);
    printf("begin: free_nodes[%d] == %p.\n", SIZES_COUNT - 1, (void*) get_free_nodes_first(SIZES_COUNT - 1));
    printf("Searching from size index %d.\n", size_index);
#endif
    memnode* node = NULL;
    // search for first free node
    // TODO: start search at minimum_size_index
    // TODO: if node for requested size_index does not exist, search from
    // highest size_index downwards, to improve memory usage,
    // or skip the second size_index, to avoid giving away 8 bytes
    do {
        node = get_free_nodes_first(size_index);
#if DEBUG
        printf("Size index %d: Node %p.\n", size_index, (void*) node);
#endif
    } while (node == NULL && ++size_index < SIZES_COUNT);

    if (node == NULL) {
#if DEBUG
        printf("Could not find a suitable memory block!\n");
#endif
        return NULL;
    }
    check_prev_next_prts(node);
#if DEBUG
    printf("Got node in size index %d.\n", size_index);
    printf("Node: %p.\n", (void*) node);
    printf("get_next_node(node): %p.\n", (void*) get_next_node(node));
    printf("Node size: %d bytes.\n", node->size);
#endif
    assert(node->size > 0);
    if (node->size < size) {
        // not enough memory left
        // TODO: check the whole last bucket (SIZES_COUNT-1) for a large enough node
        return NULL;
    }

    // split node if big enough
    int32_t left_size = node->size - size - ALLOC_NODE_SIZE;
#if DEBUG
    printf("node->size: %d; size: %ld; ALLOC_NODE_SIZE: %d.\n",
           node->size, size, ALLOC_NODE_SIZE);
    printf("%d bytes left.\n", left_size);
#endif
    assert(left_size >= -ALLOC_NODE_SIZE);
    if (left_size >= ALIGN) {
        size_index_type left_size_index = get_size_index_lower(left_size);
#if DEBUG
        printf("Splitting node.\n");
        printf("Left size index: %d.\n", left_size_index);
#endif
        memnode* new_node = (memnode*) (((byte*) node) + size + ALLOC_NODE_SIZE);
#if DEBUG
        printf("New node is %p.\n", (void*) new_node);
#endif
        new_node->size = left_size;
        node->size = size;
        new_node->d_prev_free_node = 0;
        new_node->d_next_free_node = 0;
        new_node->prev_node_size = node->size; // also sets to unallocated
        memnode* next_node = get_next_node(new_node);
        if (next_node != NULL) {
#if DEBUG
            printf("Next node is %p.\n", (void*) next_node);
#endif
            set_prev_node_size(next_node, new_node->size);
        }
        check_prev_next_prts(node);
        check_prev_next_prts(new_node);

        // prepend new_node to free nodes list:
        prepend_free_node(new_node, left_size_index);
        assert(get_free_nodes_first(left_size_index) == new_node);
    }
    check_prev_next_prts(node);
    // remove node from free nodes list:
    attach_free_nodes(get_prev_free_node(node), get_next_free_node(node));
    check_prev_next_prts(get_next_free_node(node));

#if DEBUG
    printf("end: free_nodes[%d] == %p.\n", SIZES_COUNT - 1, (void*) get_free_nodes_first(SIZES_COUNT - 1));
#endif

    set_allocated(node);
    return ((byte*) node) + ALLOC_NODE_SIZE;
}


static void join_with_next(memnode* node) {
    if (node == NULL || is_allocated(node)) {
        return;
    }
    check_prev_next_prts(node);
    memnode* next_node = get_next_node(node);
    if (next_node == NULL || is_allocated(next_node)) {
        return;
    }
#if DEBUG
    printf("Joining block %p (%d bytes) and block %p (%d bytes).\n",
           (void*) node, node->size, (void*) next_node, next_node->size);
#endif
    check_prev_next_prts(next_node);
    node->size += next_node->size + ALLOC_NODE_SIZE;
    // remove node from free nodes list:
    attach_free_nodes(get_prev_free_node(node), get_next_free_node(node));
    // remove next_node from nodes lists:
    attach_free_nodes(get_prev_free_node(next_node), get_next_free_node(next_node));
    next_node = get_next_node(node);
    if (next_node != NULL) {
        set_prev_node_size(next_node, node->size);
    }
    check_prev_next_prts(next_node);
    // prepend node to free nodes list:
    size_index_type size_index = get_size_index_lower(node->size);
    prepend_free_node(node, size_index);
    check_prev_next_prts(node);
}


void mm_free(void* ptr) {
    if (!ptr) return;

    memnode* node = (memnode*) (((byte*) ptr) - ALLOC_NODE_SIZE);
#if REFCOUNT
#if DEBUG
    printf("Refcount is %d.\n", node->refcount);
#endif
    if (--node->refcount > 0) {
        return;
    }
#endif
#if DEBUG
    printf("\nFreeing block %p.\n", (void*) node);
#endif
    size_index_type size_index = get_size_index_lower(node->size);
#if DEBUG
    printf("Size: %d bytes.\n", node->size);
    printf("Size index: %d.\n", size_index);
#endif
    set_unallocated(node);
    // prepend node to free nodes list:
    prepend_free_node(node, size_index);

    join_with_next(node);
    join_with_next(get_prev_node(node));
}


#if REFCOUNT

void mm_inc_ref(void* ptr) {
    assert(ptr);
    memnode* node = (memnode*) (((byte*) ptr) - ALLOC_NODE_SIZE);
    assert(node->refcount > 0);
    assert(node->refcount < MAX_REFCOUNT);
    ++node->refcount;
}

#endif
