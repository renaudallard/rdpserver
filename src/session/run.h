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
 * run.h -- run a helper program and wait for its exit status.
 */

#ifndef RDP_RUN_H
#define RDP_RUN_H

#include <stddef.h>
#include <sys/types.h>

/*
 * Run path (searched in PATH when it has no slash) with argv, NULL
 * terminated, argv[0] included.  stdin and stderr are /dev/null.  When out
 * is not NULL, stdout is captured into out as a NUL-terminated string,
 * truncated to outsz - 1 bytes, else it goes to /dev/null too.  Returns the
 * captured length (0 without out) when the program exits 0, or -1.
 *
 * The session installs SIGCHLD with SA_NOCLDWAIT, under which a finished
 * child is reaped by the kernel and waitpid cannot report its status, so
 * the default disposition is restored for the duration of the call.
 */
ssize_t rdp_run(const char *path, const char *const argv[], char *out,
		size_t outsz);

#endif /* RDP_RUN_H */
