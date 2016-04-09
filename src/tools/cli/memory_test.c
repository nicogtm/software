#include "cli.h"

#include <assert.h>

static int memory_test(struct osd_context *ctx, uint16_t mod,
                       uint8_t region) {
    uint64_t addr;
    uint8_t *wdata, *rdata;
    size_t size;
    size_t blocksize;

    struct osd_memory_descriptor *desc;

    wdata = malloc(1024*1024);
    rdata = malloc(1024*1024);

    osd_get_memory_descriptor(ctx, mod, &desc);
    assert(desc);

    // Bytes per block
    blocksize = desc->data_width >> 3;

    // Perform one aligned write of one word
    addr = desc->regions[region].base_addr;
    size = blocksize;
    for (size_t i = 0; i < size; i++) wdata[i] = i & 0xff;

    osd_memory_write(ctx, mod, addr, wdata, size);

    // Write the next ten blocks
    addr = desc->regions[region].base_addr + blocksize;
    size = blocksize * 10;
    for (size_t i = 0; i < size; i++) wdata[i] = i & 0xff;

    osd_memory_write(ctx, mod, addr, wdata, size);

    // Read back the first block
    addr = desc->regions[region].base_addr;
    size = blocksize;

    osd_memory_read(ctx, mod, addr, rdata, size);

    for (size_t i = 0; i < size; i++) {
        if (wdata[i] != rdata[i]) {
            printf("Test 0 failed\n");
            return -1;
        }
    }

    printf("Test 0 passed\n");

    // Read back the next ten blocks
    addr = desc->regions[region].base_addr + blocksize;
    size = blocksize * 10;

    osd_memory_read(ctx, mod, addr, rdata, size);

    for (size_t i = 0; i < size; i++) {
        if (wdata[i] != rdata[i]) {
            printf("Test 1 failed\n");
            return -1;
        }
    }

    printf("Test 1 passed\n");

    // Test 2: Check writing single bytes

    // First write three blocks
    size = blocksize * 3;

    for (size_t i = 0; i < size; i++) {
        wdata[i] = (0x7c - i) % 0xff;
    }

    addr = 0;
    osd_memory_write(ctx, mod, addr, wdata, size);

    // Now write each a single byte and check it
    // Write into the second block
    addr = blocksize;
    for (size_t b = 0; b < blocksize; b++) {
        uint8_t w = 0xd9 - b;
        osd_memory_write(ctx, mod, addr + b, &w, 1);

        wdata[addr + b] = w;

        osd_memory_read(ctx, mod, 0, rdata, size);

        for (size_t i = 0; i < size; i++) {
            if (wdata[i] != rdata[i]) {
                printf("Test 2 failed in iteration %zu\n", b);
                return -1;
            }
        }
    }

    printf("Test 2 passed\n");

    return 0;
}

int memory_tests(struct osd_context *ctx) {
    // Get list of memories
    uint16_t *memories;
    size_t num_memories;
    int success = 1;

    osd_get_memories(ctx, &memories, &num_memories);

    for (size_t m = 0; m < num_memories; m++) {
        printf("Test memory %d\n", memories[m]);
        if (memory_test(ctx, memories[m], 0) != 0) {
            printf("Failed\n");
            success = 0;
        } else {
            printf("Passed\n");
        }
    }

    return success;
}
