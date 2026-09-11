// SPDX-License-Identifier: MIT
/*
 * Guest init for fuzzamoto's bedrock backend.
 *
 * Runs as PID 1 in the initramfs and does the minimum a fuzzamoto scenario
 * needs before it can spawn a node, then hands over to the scenario binary.
 * Everything here is something nothing else in an initramfs does for you:
 *
 *   - /proc, /sys, /dev: corepc-node and bitcoind both read /proc, and bitcoind
 *     wants /dev/urandom and /dev/null.
 *   - /tmp as a tmpfs: corepc-node puts the node's datadir under the temp dir.
 *     It must be writable and reasonably large or bitcoind fails at startup.
 *   - /bedrock/coverage as a tmpfs: bedrock's own coverage frontend
 *     (guest/libfeedback.c) keeps each process's bitmap in a file there, so
 *     that its pages outlive the process and the agent can zero them between
 *     setup and the checkpoint. Without the directory it falls back to
 *     anonymous memory, which nothing outside the target can reach.
 *   - loopback up: the scenario talks to bitcoind over 127.0.0.1 for both P2P
 *     and RPC. A fresh initramfs leaves `lo` down, so every connect() fails
 *     with ENETUNREACH — an obscure way to watch a harness die.
 *
 * On any failure it issues the bedrock shutdown hypercall rather than looping,
 * so a broken image ends the VM instead of hanging the fuzzer.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libvmcall.h"

/* Where the scenario and the node live in the initramfs. */
#define SCENARIO_PATH "/scenario"
#define BITCOIND_PATH "/bitcoind"

static void die(const char *what)
{
	/* Best-effort diagnostic; the console may not be up yet. */
	fprintf(stderr, "init: %s failed: %s\n", what, strerror(errno));
	fflush(stderr);
	vmcall_shutdown();
	for (;;)
		__asm__ volatile("hlt");
}

static void mount_one(const char *src, const char *dst, const char *fs, const char *opts)
{
	(void)mkdir(dst, 0755);
	if (mount(src, dst, fs, 0, opts) != 0)
		die(dst);
}

/*
 * Bring up the loopback interface. Equivalent to `ip link set lo up`, done with
 * an ioctl so the image needs no iproute2.
 */
static void loopback_up(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		die("socket");

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0)
		die("SIOCGIFFLAGS");
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0)
		die("SIOCSIFFLAGS");
	close(fd);
}

int main(void)
{
	mount_one("proc", "/proc", "proc", NULL);
	mount_one("sysfs", "/sys", "sysfs", NULL);
	mount_one("devtmpfs", "/dev", "devtmpfs", NULL);
	/* The node's datadir goes here; leveldb and the block files need room. */
	mount_one("tmpfs", "/tmp", "tmpfs", "size=2G");
	/* One coverage bitmap per instrumented process; a few MB is plenty. */
	mount_one("tmpfs", "/bedrock", "tmpfs", "size=16M");
	if (mkdir("/bedrock/coverage", 0755) != 0)
		die("mkdir /bedrock/coverage");

	loopback_up();

	/*
	 * The scenario reads its input through the bedrock agent, so it needs no
	 * stdin. Keep stdout/stderr as inherited (the bedrock console) so guest
	 * logs reach the host's serial event stream.
	 */
	char *argv[] = { (char *)SCENARIO_PATH, (char *)BITCOIND_PATH, NULL };
	char *envp[] = {
		(char *)"HOME=/tmp",
		(char *)"TMPDIR=/tmp",
		(char *)"PATH=/",
		/* Surface harness progress on the console; bitcoind's own logging
		 * is controlled by the scenario's build features. */
		(char *)"RUST_LOG=info",
		/*
		 * Same ASan configuration the Nyx backend runs the target under
		 * (fuzzamoto-cli's bitcoind proxy script), minus its
		 * log_path=/tmp/asan.log: that exists so Nyx's crash handler can
		 * read the report back, and this backend has no such handler.
		 * Reports go to stderr instead, where the host's serial event
		 * stream picks them up and the fuzzer stores them with the
		 * crash.
		 */
		(char *)"ASAN_OPTIONS=detect_leaks=1:detect_stack_use_after_return=1:"
			"check_initialization_order=1:strict_init_order=1:"
			"abort_on_error=1:handle_abort=1",
		NULL,
	};
	execve(SCENARIO_PATH, argv, envp);
	die("execve " SCENARIO_PATH);
	return 1;
}
