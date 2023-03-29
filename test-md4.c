/*-
 * Copyright (c) 2023, Collin Funk
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md4.h"

static int
md4_test(const char *message, const char *expected, int number)
{
	struct md4_ctx ctx;
	uint8_t digest[16];

	md4_init(&ctx);
	md4_update(&ctx, message, strlen(message));
	md4_final(digest, &ctx);

	printf("Digest #%02d: ", number);
	for (int i = 0; i < 16; ++i)
		printf("%02x", digest[i]);
	printf("\n");

	if (memcmp(digest, expected, 16) != 0) {
		fprintf(stderr, "Test %d failed.\n", number);
		return 1;
	}

	return 0;
}

int
main(void)
{

	/*
	 * Test vectors from RFC 1320.
	 */
	const char test_msg1[] = "";
	const char expected1[16] = "\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31"
		"\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0";

	const char test_msg2[] = "a";
	const char expected2[16] = "\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46"
		"\x24\x5e\x05\xfb\xdb\xd6\xfb\x24";

	const char test_msg3[] = "abc";
	const char expected3[16] = "\xa4\x48\x01\x7a\xaf\x21\xd8\x52"
		"\x5f\xc1\x0a\xe8\x7a\xa6\x72\x9d";

	const char test_msg4[] = "message digest";
	const char expected4[16] = "\xd9\x13\x0a\x81\x64\x54\x9f\xe8"
		"\x18\x87\x48\x06\xe1\xc7\x01\x4b";

	const char test_msg5[] = "abcdefghijklmnopqrstuvwxyz";
	const char expected5[16] = "\xd7\x9e\x1c\x30\x8a\xa5\xbb\xcd"
		"\xee\xa8\xed\x63\xdf\x41\x2d\xa9";

	const char test_msg6[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
		"ghijklmnopqrstuvwxyz0123456789";
	const char expected6[16] = "\x04\x3f\x85\x82\xf2\x41\xdb\x35"
		"\x1c\xe6\x27\xe1\x53\xe7\xf0\xe4";

	const char test_msg7[] = "1234567890123456789012345678901234"
		"5678901234567890123456789012345678901234567890";
	const char expected7[16] = "\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19"
		"\x9c\x3e\x7b\x16\x4f\xcc\x05\x36";

	if (md4_test(test_msg1, expected1, 1) != 0)
		exit(1);
	if (md4_test(test_msg2, expected2, 2) != 0)
		exit(1);
	if (md4_test(test_msg3, expected3, 3) != 0)
		exit(1);
	if (md4_test(test_msg4, expected4, 4) != 0)
		exit(1);
	if (md4_test(test_msg5, expected5, 5) != 0)
		exit(1);
	if (md4_test(test_msg6, expected6, 6) != 0)
		exit(1);
	if (md4_test(test_msg7, expected7, 7) != 0)
		exit(1);

	return 0;
}
