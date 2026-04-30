#include <stdint.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "nyx-lite.h"

static uint8_t *trace_buffer = NULL;
static size_t trace_buffer_size = 0;

static uint8_t *payload_buffer = NULL;
static size_t payload_buffer_size = 0;

size_t nyx_lite_init() {
    static int done = 0;
    if (done) {
        nyx_lite_abort("Error: nyx_lite_init called twice");
    }
    done = 1;

    size_t bitmap_size = 0;

#ifdef TARGET_MAP_SIZE
    bitmap_size = TARGET_MAP_SIZE;
    nyx_lite_debugprint("[init] using TARGET_MAP_SIZE: %d\n", bitmap_size);
#else
    nyx_lite_abort("Error: TARGET_MAP_SIZE unset");
#endif

    key_t key = ftok("/tmp", 'T');
    int shmid = shmget(key, bitmap_size, IPC_CREAT | 0666);
    if (shmid == -1) {
        nyx_lite_abort("Error: Failed to create shared memory segment for trace buffer");
    }

    // Create and register the trace buffer.
    char shmid_str[16];
    memset(shmid_str, 0, sizeof(shmid_str));
    snprintf(shmid_str, sizeof(shmid_str), "%d", shmid);
    setenv("__AFL_SHM_ID", shmid_str, 1);

    char map_size_str[16];
    memset(map_size_str, 0, sizeof(map_size_str));
    snprintf(map_size_str, sizeof(map_size_str), "%d", bitmap_size);
    setenv("AFL_MAP_SIZE", map_size_str, 1);

    trace_buffer = (uint8_t *)shmat(shmid, NULL, 0);
    if (trace_buffer == (void *)-1) {
        nyx_lite_abort("Error: Failed to attach shared memory segment for trace buffer");
    }

    trace_buffer_size = bitmap_size;
    memset(trace_buffer, 0, trace_buffer_size);

    nyx_lite_register_region("trace_buffer", trace_buffer, (uint64_t)trace_buffer_size);

    // Create and register the payload region.
    // TODO: Make payload size configurable.
    size_t max_payload_size = 8388608;

    key_t payload_key = ftok("/tmp", 'P');
    int payload_shmid = shmget(payload_key, max_payload_size, IPC_CREAT | 0666);
    if (payload_shmid == -1) {
        nyx_lite_abort("Error: Failed to create shared memory segment for payload");
    }

    payload_buffer = (uint8_t *)shmat(payload_shmid, NULL, 0);
    if (payload_buffer == (void *)-1) {
        nyx_lite_abort("Error: Failed to attached shared memory segment for payload buffer");
    }

    payload_buffer_size = max_payload_size;
    memset(payload_buffer, 0, payload_buffer_size);

    nyx_lite_register_region("payload_buffer", payload_buffer, (uint64_t)payload_buffer_size);

    return max_payload_size;
}

void nyx_lite_dump_file_to_host(const char *file_name, size_t file_name_len,
                                const uint8_t *data, size_t len) {
    // TODO
}

void nyx_lite_println(const char *message, size_t message_len) {
    // TODO
}

size_t nyx_lite_get_fuzz_input(const uint8_t *data, size_t max_size) {
    // TODO: Have to make our own protocol to put in the payload buffer.
    // similar to run_qemu + wait_qemu? Is it possible to just:
    // 1. copy payload into payload_buffer
    // 2. apply_snapshot
    // NOTE: Still need to know the payload size to truncate though...

    // Reset trace buffer
    memset(trace_buffer, 0, trace_buffer_size);

    // Take snapshot
    nyx_lite_debugprint("[init] taking snapshot\n");
    nyx_lite_snapshot();

    trace_buffer[0] = 1;

    // Copy payload buffer into data
    memcpy((void *)data, payload_buffer, payload_buffer_size);
    return payload_buffer_size; // This won't work.
}

void nyx_lite_skip() {
    memset(trace_buffer, 0, trace_buffer_size);
    trace_buffer[0] = 1;
}

void nyx_lite_release() {
    // TODO
}

void nyx_lite_fail(const char *message) {
    nyx_lite_abort(message);
}
