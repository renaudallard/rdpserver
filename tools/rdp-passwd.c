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
 * rdp-passwd -- manage NT hash entries for NLA authentication.
 *
 * Usage: rdp-passwd username
 * Prompts for password, computes MD4(UTF-16LE(password)), writes
 * to /etc/rdpserver/nthashes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../src/sec/nla_crypto.h"
#include "../src/common/utf16.h"

#define NTHASH_PATH "/etc/rdpserver/nthashes"

int
main(int argc, char *argv[])
{
	char *pw;
	uint8_t pw_utf16[512];
	uint8_t nthash[16];
	size_t pw_len;
	FILE *fp;
	char line[512], tmp[512];
	int found = 0, i;

	if (argc != 2) {
		fprintf(stderr, "usage: %s username\n", argv[0]);
		return 1;
	}

	pw = getpass("Password: ");
	if (pw == NULL || pw[0] == '\0') {
		fprintf(stderr, "empty password\n");
		return 1;
	}

	pw_len = rdp_utf8_to_utf16le(pw_utf16, sizeof pw_utf16,
		pw, strlen(pw));
	if (pw_len == (size_t)-1) {
		fprintf(stderr, "UTF-16 conversion failed\n");
		return 1;
	}
	if (rdp_md4(pw_utf16, pw_len, nthash) != 0) {
		fprintf(stderr, "MD4 failed\n");
		return 1;
	}
	explicit_bzero(pw_utf16, sizeof pw_utf16);

	(void)mkdir("/etc/rdpserver", 0700);
	snprintf(tmp, sizeof tmp, "%s.tmp", NTHASH_PATH);

	{
		FILE *out = fopen(tmp, "w");
		if (out == NULL) {
			perror(tmp);
			return 1;
		}
		(void)fchmod(fileno(out), 0600);

		fp = fopen(NTHASH_PATH, "r");
		if (fp != NULL) {
			while (fgets(line, sizeof line, fp) != NULL) {
				char *colon = strchr(line, ':');
				if (colon != NULL
				    && (size_t)(colon - line) == strlen(argv[1])
				    && strncmp(line, argv[1], strlen(argv[1])) == 0) {
					found = 1;
					fprintf(out, "%s:", argv[1]);
					for (i = 0; i < 16; i++)
						fprintf(out, "%02x", nthash[i]);
					fprintf(out, "\n");
				} else {
					fputs(line, out);
				}
			}
			fclose(fp);
		}
		if (!found) {
			fprintf(out, "%s:", argv[1]);
			for (i = 0; i < 16; i++)
				fprintf(out, "%02x", nthash[i]);
			fprintf(out, "\n");
		}
		fclose(out);
	}

	if (rename(tmp, NTHASH_PATH) != 0) {
		perror("rename");
		return 1;
	}
	explicit_bzero(nthash, sizeof nthash);
	printf("NT hash updated for '%s'\n", argv[1]);
	return 0;
}
