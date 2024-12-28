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
static std::unordered_map<void*, uint8_t> vals;

void do_write(std::mt19937& rng) {
    if (regions.empty()) {
        return;
    }
    std::uniform_int_distribution<> d(0, regions.size() - 1);
    int idx = d(rng);
    void* ptr = regions.at(idx);
    size_t size = sizes.at(ptr);
    uint8_t val = vals.at(ptr);
    std::memset(ptr, val, size);
}

void do_malloc(struct mini_malloc* mm, std::mt19937& rng) {
    do_write(rng);
    size_t size;
    std::exponential_distribution<> d(8.0);
    do {
        double s = d(rng);
        size = (size_t) (s * s * s * MAX_SIZE * 1.01) + 1;
        size += ALIGN - size % ALIGN;
    } while (size > MAX_SIZE);
    void* ptr = mm_alloc(mm, size);
    if (ptr == nullptr) {
        return;
    }
    regions.push_back(ptr);
    sizes[ptr] = size;
    std::uniform_int_distribution<> d2(0, 255);
    uint8_t val = d2(rng);
    vals.emplace(ptr, val);
    std::memset(ptr, val, size);
}

void do_free(struct mini_malloc* mm, std::mt19937& rng) {
    do_write(rng);
    if (regions.empty()) {
        return;
    }
    std::uniform_int_distribution<> d(0, regions.size() - 1);
    int idx = d(rng);
    void* ptr = regions[idx];
    size_t size = sizes[ptr];
    uint8_t val = vals.at(ptr);
    for (uint8_t* p = (uint8_t*) ptr; p < (uint8_t*) ptr + size; ++p) {
        assert(*p == val);
    }
    mm_free(mm, ptr);
    regions.erase(regions.begin() + idx);
    sizes.erase(ptr);
    vals.erase(ptr);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // first four bytes are seed
    int i = 0;
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
    struct mini_malloc* mm = init_mini_malloc(buffer, blocksize);
    // parse input and invoke malloc and free
    while (i < size) {
        switch (data[i]) {
            case 'M': // malloc
                i++;
                do_malloc(mm, rng);
                break;
            case 'F': // free
                i++;
                do_free(mm, rng);
                break;
            default:
                // input error
                free(buffer);
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

