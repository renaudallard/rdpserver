/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */
/*
 * sandbox.c -- seccomp-bpf sandbox for Linux rdpd workers.
 *
 * Restricts the worker to the minimum syscalls needed for TLS I/O,
 * poll, malloc, and AF_UNIX communication with the session manager.
 */

#include "sandbox.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#if defined(__linux__) && HAVE_SECCOMP

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define SC_ALLOW(nr) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

int
rdp_sandbox_worker(void)
{
	static struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		SC_ALLOW(__NR_read),
		SC_ALLOW(__NR_write),
		SC_ALLOW(__NR_writev),
		SC_ALLOW(__NR_close),
#ifdef __NR_poll
		SC_ALLOW(__NR_poll),
#endif
		SC_ALLOW(__NR_ppoll),
		SC_ALLOW(__NR_recvmsg),
		SC_ALLOW(__NR_sendmsg),
		SC_ALLOW(__NR_sendto),
		SC_ALLOW(__NR_recvfrom),
		SC_ALLOW(__NR_socket),
		SC_ALLOW(__NR_connect),
		SC_ALLOW(__NR_mmap),
		SC_ALLOW(__NR_munmap),
		SC_ALLOW(__NR_mprotect),
		SC_ALLOW(__NR_brk),
		SC_ALLOW(__NR_futex),
		SC_ALLOW(__NR_clock_gettime),
		SC_ALLOW(__NR_getrandom),
		SC_ALLOW(__NR_fcntl),
		SC_ALLOW(__NR_ioctl),
		SC_ALLOW(__NR_exit_group),
		SC_ALLOW(__NR_exit),
		SC_ALLOW(__NR_rt_sigreturn),
		SC_ALLOW(__NR_rt_sigaction),
		SC_ALLOW(__NR_rt_sigprocmask),
		SC_ALLOW(__NR_newfstatat),
#ifdef __NR_fstat
		SC_ALLOW(__NR_fstat),
#endif
		SC_ALLOW(__NR_openat),
		SC_ALLOW(__NR_getpid),
		SC_ALLOW(__NR_gettid),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & 0x7FFF)),
	};
	static struct sock_fprog prog = {
		.len = sizeof filter / sizeof filter[0],
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		rdp_warn("seccomp: PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
		return -1;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
		rdp_warn("seccomp: SECCOMP_MODE_FILTER: %s", strerror(errno));
		return -1;
	}
	rdp_debug("seccomp sandbox active");
	return 0;
}

#else

int
rdp_sandbox_worker(void)
{
	return 0;
}

#endif
