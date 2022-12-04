#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <cassert>

extern "C" {
#include "../mini_malloc.h"
}

#define MAX_SIZE (1ull << 19)
#define ALIGN 8

static std::vector<void*> regions;
static std::unordered_map<void*, size_t> sizes;

void do_malloc(std::mt19937& rng) {
    size_t size;
    std::exponential_distribution<> d(8.0);
    do {
        double s = d(rng);
        size = (size_t) (s * s * s * MAX_SIZE * 1.01) + 1;
        size += ALIGN - size % ALIGN;
    } while (size > MAX_SIZE);
    void* ptr = mm_alloc(size);
    if (ptr == nullptr) {
        return;
    }
    regions.push_back(ptr);
    sizes[ptr] = size;
    uint8_t val = (uint8_t) ((uint64_t) ptr >> 3);
    std::memset(ptr, val, size);
}

void do_free(std::mt19937& rng) {
    if (regions.empty()) {
        return;
    }
    std::uniform_int_distribution<> d(0, regions.size() - 1);
    int idx = d(rng);
    void* ptr = regions[idx];
    size_t size = sizes[ptr];
    uint8_t val = (uint8_t) ((uint64_t) ptr >> 3);
    for (uint8_t* p = (uint8_t*) ptr; p < (uint8_t*) ptr + size; ++p) {
        assert(*p == val);
    }
    mm_free(ptr);
    regions.erase(regions.begin() + idx);
    sizes.erase(ptr);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // first four bytes are seed
    int i = 0;
    void* ptr;
    if (size < 4) {
        return -1;
    }
    for (auto ind = 0; ind < 4; ind++) {
        char ch = ((char*) data)[ind];
        switch (ch) {
            case 'M':
            case 'F':
                return -1;
            default:
                break;
        }
    }
    uint32_t seed = *((uint32_t*) data);
    i += 4;
    printf("seed = %u\n", seed);
    std::mt19937 rng{seed};

    size_t blocksize = 1ull << std::uniform_int_distribution<>(9, 22)(rng);
    void* buffer = malloc(blocksize);
    std::uniform_int_distribution<> d(0, 255);
    for (int j = 0; j < 1024 && j < blocksize; ++j) {
        ((char*) buffer)[j] = (char) d(rng);
    }
    init_mini_malloc(buffer, blocksize);
    // parse input and invoke malloc and free
    while (i < size) {
        switch (data[i]) {
            case 'M': // malloc
                i++;
                do_malloc(rng);
                break;
            case 'F': // free
                i++;
                do_free(rng);
                break;
            default:
                // input error
                i++;
                return -1;
        }
    }
    free(buffer);
    return 0;
}

int main() {
    constexpr int MAX_INPUT_LENGTH = 65536;
    char data[MAX_INPUT_LENGTH];
    std::memset(data, 0, MAX_INPUT_LENGTH);
    auto result = fread(data, MAX_INPUT_LENGTH, 1, stdin);
    if (result == 0) {
        LLVMFuzzerTestOneInput((const uint8_t*) data, strlen(data));
    }
    return 0;
}

