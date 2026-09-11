// SPDX-License-Identifier: MIT
/*
 * bedrock-agent — the guest half of fuzzamoto's bedrock backend.
 *
 * This is the bedrock counterpart to `fuzzamoto-nyx-sys/src/nyx-agent.c`, and
 * it deliberately exposes the same shape so `fuzzamoto::runners::Runner` can be
 * implemented against either.
 *
 * The whole channel is one shared buffer plus one hypercall:
 *
 *   bedrock_init()            register the buffer, signal boot complete
 *   bedrock_get_fuzz_input()  ask for a testcase (the host checkpoints here)
 *   bedrock_fail()/skip()     report on the testcase just run
 *   bedrock_release()         report success and end the execution
 *
 * `HYPERCALL_FUZZ_NEXT_INPUT` does double duty: it asks for the next testcase
 * *and* tells the host the previous one finished. So every execution costs
 * exactly one VM exit for input and result, with no polling and no copies
 * beyond the host's memcpy into the buffer.
 *
 * Where Nyx resets a snapshot, bedrock forks: the host takes a `Checkpoint` at
 * our first `vmcall_fuzz_next_input()` — with bitcoind already spawned and the
 * chain already mined — and every subsequent testcase runs in a fresh
 * copy-on-write fork of that moment. That is why nothing here has to undo
 * anything: the VM this code runs in is thrown away after one testcase.
 */

#include <dirent.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libvmcall.h"

/*
 * 1 MB — the hypervisor's per-buffer cap. IR programs are far smaller (tens of
 * KB), but the cap costs nothing to ask for and leaves headroom.
 */
#define AGENT_BUF_SIZE VMCALL_FEEDBACK_BUFFER_MAX_SIZE
#define AGENT_INPUT_CAPACITY (AGENT_BUF_SIZE - VMCALL_FUZZ_INPUT_HEADER_LEN)

/*
 * Coverage buffer id. `BedrockHelper` picks the target's coverage map out of
 * the registered buffers by its "cov-" prefix, the same prefix bedrock's own
 * libfeedback uses ("cov-<build-id>").
 */
#define COVERAGE_BUFFER_ID "cov-afl"

/*
 * Where bedrock's libfeedback keeps one bitmap file per process (see
 * bedrock/guest/libfeedback.c). Only used by targets that carry their own
 * coverage frontend rather than AFL++'s; the reset below zeroes those too, so
 * either instrumentation gets Nyx's semantics.
 */
#define COVERAGE_DIR "/bedrock/coverage"

/* Header layout, mirroring VMCALL_FUZZ_INPUT_* in libvmcall.h. */
struct fuzz_header {
	int64_t result;  /* host writes: input length, or EOF */
	uint64_t status; /* guest writes: VMCALL_FUZZ_STATUS_* */
	uint64_t aux;    /* guest writes: failure-message length */
	uint64_t reserved;
};

static volatile struct fuzz_header *g_header;
static uint8_t *g_payload;
static int g_initialized;

#ifdef TARGET_MAP_SIZE
/* The target's AFL++ coverage map: a SysV shm segment we create, register with
 * the hypervisor, and hand to the target over __AFL_SHM_ID. */
static uint8_t *g_trace;
static size_t g_trace_size;
#endif

/*
 * Abort the VM, saying why first.
 *
 * A silent abort here is indistinguishable from a fuzzer making no progress,
 * and the guest console is the only channel out, so complain before dying.
 */
static void agent_abort(const char *why)
{
	if (why) {
		(void)!write(2, "fuzzamoto-bedrock-agent: ", 25);
		(void)!write(2, why, strlen(why));
		(void)!write(2, "\n", 1);
	}
	vmcall_shutdown();
	for (;;)
		__asm__ volatile("hlt");
}

/* Turn a failed buffer registration into a diagnosed abort. */
static void abort_on_registration_error(vmcall_u64 slot, const char *what)
{
	/* Every VMCALL_FB_ERR_* is >= VMCALL_ERR - 4; a real slot is small. */
	if (slot < VMCALL_ERR - 4ULL)
		return;

	if (slot == VMCALL_FB_ERR_BAD_SIZE)
		agent_abort("buffer registration: bad size");
	else if (slot == VMCALL_FB_ERR_BAD_ID_LEN)
		agent_abort("buffer registration: bad id length");
	else if (slot == VMCALL_FB_ERR_ID_NOT_RESIDENT)
		agent_abort("buffer registration: id page not resident");
	else if (slot == VMCALL_FB_ERR_BUFFER_NOT_RESIDENT)
		agent_abort("buffer registration: buffer not resident");
	else if (slot == VMCALL_FB_ERR_NO_SLOTS)
		agent_abort("buffer registration: no slots left");
	else
		agent_abort(what);
}

/*
 * Create the target's coverage map and point AFL++'s runtime at it.
 *
 * The bedrock counterpart to nyx-agent.c's shm setup, and deliberately the same
 * mechanism: a SysV shm segment sized to what the instrumented binary asked for
 * (`TARGET_MAP_SIZE`, dumped at build time by running it with
 * AFL_DUMP_MAP_SIZE=1), handed to the target through __AFL_SHM_ID. The
 * difference is who else sees it: instead of telling Nyx the buffer's address
 * in an agent_config, we register it as a bedrock feedback buffer, so the host
 * reads the same pages the target's inline instrumentation writes.
 *
 * Must run before the harness spawns the target, since it only picks the
 * environment up at exec.
 */
static void coverage_init(void)
{
#ifdef TARGET_MAP_SIZE
	size_t size = (size_t)TARGET_MAP_SIZE;

	/* build.rs rejects an oversized map, so this is belt and braces. */
	if (size == 0 || size > VMCALL_FEEDBACK_BUFFER_MAX_SIZE)
		agent_abort("TARGET_MAP_SIZE does not fit the hypervisor's buffer cap");

	int shmid = shmget(IPC_PRIVATE, size, IPC_CREAT | 0600);
	if (shmid < 0)
		agent_abort("shmget of the coverage map failed (no CONFIG_SYSVIPC?)");

	void *buf = shmat(shmid, NULL, 0);
	if (buf == (void *)-1)
		agent_abort("shmat of the coverage map failed");

	/*
	 * Same residency contract as the input buffer: the hypervisor
	 * translates the buffer by walking the guest page tables and rejects a
	 * non-resident page. memset faults every page in, mlock keeps them
	 * there. The segment itself is never IPC_RMID'd, so its pages stay
	 * allocated for as long as the host may read them.
	 */
	memset(buf, 0, size);
	if (mlock(buf, size) != 0)
		agent_abort("mlock of the coverage map failed");

	/* Stack-staged id, for the residency reason in bedrock_init(). */
	char id[sizeof(COVERAGE_BUFFER_ID)];
	memcpy(id, COVERAGE_BUFFER_ID, sizeof(id));

	vmcall_u64 slot = vmcall_register_feedback_buffer(buf, size, id,
							  sizeof(id) - 1);
	abort_on_registration_error(slot, "coverage buffer registration failed");

	char value[24];
	snprintf(value, sizeof(value), "%d", shmid);
	setenv("__AFL_SHM_ID", value, 1);
	snprintf(value, sizeof(value), "%zu", size);
	setenv("AFL_MAP_SIZE", value, 1);
	/*
	 * Attach the map but never start the forkserver: its handshake writes
	 * to fd 199 and then blocks reading fd 198, and there is no afl-fuzz on
	 * the other end. afl-compiler-rt maps the shm from a constructor that
	 * runs regardless of this variable, so coverage still works.
	 */
	setenv("__AFL_DEFER_FORKSRV", "1", 1);

	g_trace = buf;
	g_trace_size = size;
#endif
}

/*
 * Zero every bitmap file bedrock's libfeedback has published.
 *
 * These are MAP_SHARED mappings of files on the COVERAGE_DIR tmpfs, so a second
 * mapping from this process writes the very pages the hypervisor registered.
 * A missing directory means no such target; that is not an error.
 */
static void coverage_reset_files(void)
{
	DIR *dir = opendir(COVERAGE_DIR);
	if (dir == NULL)
		return;

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

		char path[512];
		int n = snprintf(path, sizeof(path), "%s/%s", COVERAGE_DIR,
				 entry->d_name);
		if (n < 0 || (size_t)n >= sizeof(path))
			continue;

		int fd = open(path, O_RDWR);
		if (fd < 0)
			continue;

		struct stat st;
		if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
			size_t len = (size_t)st.st_size;
			void *map = mmap(NULL, len, PROT_READ | PROT_WRITE,
					 MAP_SHARED, fd, 0);
			if (map != MAP_FAILED) {
				memset(map, 0, len);
				munmap(map, len);
			}
		}
		close(fd);
	}
	closedir(dir);
}

/*
 * Drop the coverage accumulated by setup, so a test case's map is only what
 * that test case did.
 *
 * This is the one thing fork-per-test-case does not give us for free. Nyx
 * memsets its trace buffer immediately before taking the snapshot, so bitcoind's
 * startup — init, chain load, the harness's own handshake — is not part of any
 * test case's coverage. Here the equivalent moment is just before the hypercall
 * the host checkpoints at: zero it there and every fork inherits a clean map.
 *
 * Slightly racy in the same way Nyx's is: the target's background threads can
 * record an edge between the memset and the checkpoint. Those show up as
 * baseline coverage in every fork, which is exactly what happens under Nyx.
 */
static void coverage_reset(void)
{
#ifdef TARGET_MAP_SIZE
	if (g_trace != NULL) {
		/*
		 * The target has been running for a whole setup by now, so an
		 * all-zero map means it never attached ours — a build without
		 * AFL++ instrumentation, or an afl-compiler-rt that took a
		 * different path. Coverage would then be flat for the whole
		 * campaign, which is worth failing loudly over.
		 */
		static int checked;
		if (!checked) {
			checked = 1;
			size_t i = 0;
			while (i < g_trace_size && g_trace[i] == 0)
				i++;
			if (i == g_trace_size)
				agent_abort("coverage map is empty after setup: the target did not attach __AFL_SHM_ID (not built with afl-clang-fast?)");
		}

		memset(g_trace, 0, g_trace_size);
	}
#endif
	coverage_reset_files();
}

/*
 * Mark the map non-empty, after the checkpoint.
 *
 * Nyx sets `trace_buffer[0] = 1` on the far side of its snapshot; index 0 is
 * reserved by AFL++'s instrumentation (guards are numbered from 1), so this
 * costs one always-covered slot and buys a map that is never entirely empty.
 * Only meaningful for the AFL++ map: libfeedback's frontends do use index 0 for
 * a real edge, which is why the files reset above are left alone here.
 */
static void coverage_mark_live(void)
{
#ifdef TARGET_MAP_SIZE
	if (g_trace != NULL)
		g_trace[0] = 1;
#endif
}

/*
 * Register the shared buffer and tell the host we finished booting.
 *
 * Returns the maximum input size the harness may receive. Aborts the VM on any
 * failure — a harness that silently ran without a fuzz channel would look like
 * a fuzzer making no progress, which is far harder to diagnose than a VM that
 * refuses to start.
 */
size_t bedrock_init(void)
{
	if (g_initialized)
		agent_abort("bedrock_init called twice");

	/*
	 * The hypervisor translates the buffer by walking the guest page tables
	 * and rejects a non-resident page, so it must be faulted in and pinned
	 * before registration: MAP_POPULATE faults it, mlock keeps its guest
	 * physical address stable.
	 */
	void *buf = mmap(NULL, AGENT_BUF_SIZE, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (buf == MAP_FAILED)
		agent_abort("mmap of input buffer failed");
	if (mlock(buf, AGENT_BUF_SIZE) != 0)
		agent_abort("mlock of input buffer failed");
	memset(buf, 0, AGENT_BUF_SIZE);

	/*
	 * Stage the buffer id on the stack, not in .rodata.
	 *
	 * The hypervisor reads the id by walking the guest page tables and
	 * cannot fault a not-present page in, so a string literal whose page
	 * this process has never touched fails registration with
	 * VMCALL_FB_ERR_ID_NOT_RESIDENT. The stack is always resident.
	 * (bedrock's own guest/libfeedback.c does the same for the same reason.)
	 */
	char id[sizeof(VMCALL_FUZZ_INPUT_BUFFER_ID)];
	memcpy(id, VMCALL_FUZZ_INPUT_BUFFER_ID, sizeof(id));
	size_t id_len = sizeof(id) - 1;

	vmcall_u64 slot = vmcall_register_feedback_buffer(buf, AGENT_BUF_SIZE,
							  id, id_len);
	abort_on_registration_error(slot, "input buffer registration failed");

	g_header = buf;
	g_payload = (uint8_t *)buf + VMCALL_FUZZ_INPUT_HEADER_LEN;
	g_initialized = 1;

	/*
	 * Before the harness spawns anything: the target reads __AFL_SHM_ID
	 * from its environment at exec, so the map has to exist by now.
	 */
	coverage_init();

	/*
	 * Boot is done. Note this is *not* the fuzzing snapshot point: the
	 * harness still has to spawn its target and set up a chain. The host
	 * checkpoints at the first bedrock_get_fuzz_input() below, so all of
	 * that setup is inherited by every fork instead of being repeated.
	 */
	vmcall_ready();
	return AGENT_INPUT_CAPACITY;
}

/*
 * Copy the next testcase into `data` and return its size.
 *
 * The host checkpoints the VM at this hypercall, so on every forked VM this is
 * where execution begins, with the input already in the buffer.
 */
size_t bedrock_get_fuzz_input(uint8_t *data, size_t max_size)
{
	if (!g_initialized)
		agent_abort("get_fuzz_input before init");

	/*
	 * Setup's coverage belongs to no test case. This is the last instruction
	 * before the checkpoint, so the map the forks inherit is clean.
	 */
	coverage_reset();

	vmcall_fuzz_next_input();

	/* Past the checkpoint: this runs once per forked VM. */
	coverage_mark_live();

	int64_t len = g_header->result;
	if (len == VMCALL_FUZZ_INPUT_EOF) {
		/* The host is done with us; there is no next testcase. */
		agent_abort(NULL);
	}
	if (len < 0 || (uint64_t)len > AGENT_INPUT_CAPACITY)
		agent_abort("host supplied an out-of-range input length");

	size_t n = (size_t)len;
	if (n > max_size)
		n = max_size;
	memcpy(data, g_payload, n);
	return n;
}

/* Record an outcome for the testcase just run, then hand control to the host. */
static void agent_report(uint64_t status)
{
	if (!g_initialized)
		agent_abort("report before init");
	g_header->status = status;
	/*
	 * Asking for the next input is how the host learns this execution
	 * finished. Under fork-per-testcase the host reads our report and drops
	 * the VM, so this call does not return; if it ever does (a host driving
	 * one long-lived VM), there is nothing left for us to do.
	 */
	vmcall_fuzz_next_input();
	agent_abort(NULL);
}

/* Report that the harness detected a bug, with a message for the fuzzer. */
void bedrock_fail(const char *message)
{
	if (!g_initialized)
		agent_abort("fail before init");

	size_t len = message ? strlen(message) : 0;
	if (len > AGENT_INPUT_CAPACITY)
		len = AGENT_INPUT_CAPACITY;
	if (len)
		memcpy(g_payload, message, len);
	g_header->aux = len;
	agent_report(VMCALL_FUZZ_STATUS_FAIL);
}

/* Report that this testcase was unusable and should not be counted. */
void bedrock_skip(void)
{
	agent_report(VMCALL_FUZZ_STATUS_SKIP);
}

/* Report that this testcase completed cleanly. Ends the execution. */
void bedrock_release(void)
{
	agent_report(VMCALL_FUZZ_STATUS_OK);
}

/*
 * Hand a file to the host over HYPERCALL_FILE_STORE.
 *
 * The bedrock counterpart to `nyx_dump_file_to_host`. The IR scenario uses it
 * to publish its program context — the mined chain's headers and spendable
 * outputs — which the fuzzer needs in order to generate programs that reference
 * real state. Without it the context has to be produced by a separate
 * out-of-VM run, and the two chains can drift apart.
 *
 * The transport is a second registered buffer, distinct from the input buffer:
 * the guest frames `name_len | chunk_len | reserved | name | chunk` and the host
 * replies in the same buffer with how many bytes it accepted. `name` must be a
 * plain file name; the host rejects anything with a path in it.
 *
 * Returns 0 on success, -1 on failure. Failure is non-fatal by design — a
 * campaign can still run with a stale context, so this must not kill the VM.
 */
int bedrock_dump_file_to_host(const char *name, size_t name_len,
			      const unsigned char *data, size_t len)
{
	/*
	 * Registered lazily and kept for the process's lifetime: most runs
	 * never dump anything, and a second 1 MB pinned buffer is not worth
	 * reserving on the off chance.
	 */
	static uint8_t *store_buf;
	static int store_failed;

	if (store_failed)
		return -1;

	if (store_buf == NULL) {
		void *buf = mmap(NULL, AGENT_BUF_SIZE, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		if (buf == MAP_FAILED || mlock(buf, AGENT_BUF_SIZE) != 0) {
			store_failed = 1;
			return -1;
		}
		memset(buf, 0, AGENT_BUF_SIZE);

		/* Stack-staged id, for the residency reason in bedrock_init(). */
		char id[sizeof(VMCALL_FILE_STORE_BUFFER_ID)];
		memcpy(id, VMCALL_FILE_STORE_BUFFER_ID, sizeof(id));

		vmcall_u64 slot = vmcall_register_feedback_buffer(
			buf, AGENT_BUF_SIZE, id, sizeof(id) - 1);
		if (slot >= VMCALL_ERR - 4ULL) {
			store_failed = 1;
			return -1;
		}
		store_buf = buf;
	}

	const size_t header = VMCALL_FILE_STORE_HEADER_LEN;
	if (name_len > AGENT_BUF_SIZE - header)
		return -1;
	const size_t chunk_cap = AGENT_BUF_SIZE - header - name_len;

	/*
	 * Chunk the payload: the host truncates the file on the first chunk and
	 * appends subsequent ones, so a context larger than the buffer still
	 * arrives whole.
	 */
	size_t sent = 0;
	do {
		size_t chunk = len - sent;
		if (chunk > chunk_cap)
			chunk = chunk_cap;

		uint32_t nl = (uint32_t)name_len;
		uint32_t cl = (uint32_t)chunk;
		memcpy(store_buf + 0, &nl, sizeof(nl));
		memcpy(store_buf + 4, &cl, sizeof(cl));
		memset(store_buf + 8, 0, 8);
		memcpy(store_buf + header, name, name_len);
		if (chunk)
			memcpy(store_buf + header + name_len, data + sent, chunk);

		vmcall_file_store();

		int64_t result;
		memcpy(&result, store_buf, sizeof(result));
		if (result < 0)
			return -1;

		sent += chunk;
	} while (sent < len);

	return 0;
}

/* Emit a line to the host's serial event stream. */
void bedrock_println(const char *message, size_t size)
{
	(void)message;
	(void)size;
	/*
	 * Guest output reaches the host through bedrock-console.ko, which owns
	 * the registered console page — an agent-owned second console page
	 * would race it. Harness logging therefore goes to stdout/stderr like
	 * any other guest process and is picked up as Serial events.
	 */
	if (size)
		(void)!write(2, message, size);
	(void)!write(2, "\n", 1);
}
