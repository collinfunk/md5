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

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "md4.h"

/*
 * Round functions.
 */
#define R1(a, b, c, d, data, shift) do { \
	(a) += (((b) & (c)) | ((~b) & (d))) + (data); \
	(a) = (((a) << shift) | ((a) >> (32 - (shift)))); \
} while (0)

#define R2(a, b, c, d, data, shift) do { \
	(a) += (((b) & (c)) | ((b) & (d)) | ((c) & (d))) + (data) + \
		0x5a827999; \
	(a) = (((a) << shift) | ((a) >> (32 - (shift)))); \
} while (0)

#define R3(a, b, c, d, data, shift) do { \
	(a) += ((b) ^ (c) ^ (d)) + (data) + 0x6ed9eba1; \
	(a) = (((a) << shift) | ((a) >> (32 - (shift)))); \
} while (0)

static uint8_t md4_padding[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void
md4_init(struct md4_ctx *ctx)
{
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
	ctx->count[0] = 0;
	ctx->count[1] = 0;
}

void
md4_transform(uint32_t state[4], const uint8_t block[64])
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t x[16];

	/*
	 * Little endian can just memcpy blocks[] into x[].
	 * The other mess works wherever but might be slower
	 * on little endian depending on your compiler and optimization
	 * settings.
	 */
#ifdef MD4_LITTLE_ENDIAN
	memcpy(x, block, sizeof(x));
#else
	x[ 0]  =  (uint32_t)block[ 0];
	x[ 0] |= ((uint32_t)block[ 1]) <<  8;
	x[ 0] |= ((uint32_t)block[ 2]) << 16;
	x[ 0] |= ((uint32_t)block[ 3]) << 24;
	x[ 1]  =  (uint32_t)block[ 4];
	x[ 1] |= ((uint32_t)block[ 5]) <<  8;
	x[ 1] |= ((uint32_t)block[ 6]) << 16;
	x[ 1] |= ((uint32_t)block[ 7]) << 24;
	x[ 2]  =  (uint32_t)block[ 8];
	x[ 2] |= ((uint32_t)block[ 9]) <<  8;
	x[ 2] |= ((uint32_t)block[10]) << 16;
	x[ 2] |= ((uint32_t)block[11]) << 24;
	x[ 3]  =  (uint32_t)block[12];
	x[ 3] |= ((uint32_t)block[13]) <<  8;
	x[ 3] |= ((uint32_t)block[14]) << 16;
	x[ 3] |= ((uint32_t)block[15]) << 24;
	x[ 4]  =  (uint32_t)block[16];
	x[ 4] |= ((uint32_t)block[17]) <<  8;
	x[ 4] |= ((uint32_t)block[18]) << 16;
	x[ 4] |= ((uint32_t)block[19]) << 24;
	x[ 5]  =  (uint32_t)block[20];
	x[ 5] |= ((uint32_t)block[21]) <<  8;
	x[ 5] |= ((uint32_t)block[22]) << 16;
	x[ 5] |= ((uint32_t)block[23]) << 24;
	x[ 6]  =  (uint32_t)block[24];
	x[ 6] |= ((uint32_t)block[25]) <<  8;
	x[ 6] |= ((uint32_t)block[26]) << 16;
	x[ 6] |= ((uint32_t)block[27]) << 24;
	x[ 7]  =  (uint32_t)block[28];
	x[ 7] |= ((uint32_t)block[29]) <<  8;
	x[ 7] |= ((uint32_t)block[30]) << 16;
	x[ 7] |= ((uint32_t)block[31]) << 24;
	x[ 8]  =  (uint32_t)block[32];
	x[ 8] |= ((uint32_t)block[33]) <<  8;
	x[ 8] |= ((uint32_t)block[34]) << 16;
	x[ 8] |= ((uint32_t)block[35]) << 24;
	x[ 9]  =  (uint32_t)block[36];
	x[ 9] |= ((uint32_t)block[37]) <<  8;
	x[ 9] |= ((uint32_t)block[38]) << 16;
	x[ 9] |= ((uint32_t)block[39]) << 24;
	x[10]  =  (uint32_t)block[40];
	x[10] |= ((uint32_t)block[41]) <<  8;
	x[10] |= ((uint32_t)block[42]) << 16;
	x[10] |= ((uint32_t)block[43]) << 24;
	x[11]  =  (uint32_t)block[44];
	x[11] |= ((uint32_t)block[45]) <<  8;
	x[11] |= ((uint32_t)block[46]) << 16;
	x[11] |= ((uint32_t)block[47]) << 24;
	x[12]  =  (uint32_t)block[48];
	x[12] |= ((uint32_t)block[49]) <<  8;
	x[12] |= ((uint32_t)block[50]) << 16;
	x[12] |= ((uint32_t)block[51]) << 24;
	x[13]  =  (uint32_t)block[52];
	x[13] |= ((uint32_t)block[53]) <<  8;
	x[13] |= ((uint32_t)block[54]) << 16;
	x[13] |= ((uint32_t)block[55]) << 24;
	x[14]  =  (uint32_t)block[56];
	x[14] |= ((uint32_t)block[57]) <<  8;
	x[14] |= ((uint32_t)block[58]) << 16;
	x[14] |= ((uint32_t)block[59]) << 24;
	x[15]  =  (uint32_t)block[60];
	x[15] |= ((uint32_t)block[61]) <<  8;
	x[15] |= ((uint32_t)block[62]) << 16;
	x[15] |= ((uint32_t)block[63]) << 24;
#endif

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	/* Round 1 */
	R1(a, b, c, d, x[ 0],  3);
	R1(d, a, b, c, x[ 1],  7);
	R1(c, d, a, b, x[ 2], 11);
	R1(b, c, d, a, x[ 3], 19);
	R1(a, b, c, d, x[ 4],  3);
	R1(d, a, b, c, x[ 5],  7);
	R1(c, d, a, b, x[ 6], 11);
	R1(b, c, d, a, x[ 7], 19);
	R1(a, b, c, d, x[ 8],  3);
	R1(d, a, b, c, x[ 9],  7);
	R1(c, d, a, b, x[10], 11);
	R1(b, c, d, a, x[11], 19);
	R1(a, b, c, d, x[12],  3);
	R1(d, a, b, c, x[13],  7);
	R1(c, d, a, b, x[14], 11);
	R1(b, c, d, a, x[15], 19);

	/* Round 2 */
	R2(a, b, c, d, x[ 0],  3);
	R2(d, a, b, c, x[ 4],  5);
	R2(c, d, a, b, x[ 8],  9);
	R2(b, c, d, a, x[12], 13);
	R2(a, b, c, d, x[ 1],  3);
	R2(d, a, b, c, x[ 5],  5);
	R2(c, d, a, b, x[ 9],  9);
	R2(b, c, d, a, x[13], 13);
	R2(a, b, c, d, x[ 2],  3);
	R2(d, a, b, c, x[ 6],  5);
	R2(c, d, a, b, x[10], 9);
	R2(b, c, d, a, x[14], 13);
	R2(a, b, c, d, x[ 3],  3);
	R2(d, a, b, c, x[ 7],  5);
	R2(c, d, a, b, x[11],  9);
	R2(b, c, d, a, x[15], 13);

	/* Round 3 */
	R3(a, b, c, d, x[ 0],  3);
	R3(d, a, b, c, x[ 8],  9);
	R3(c, d, a, b, x[ 4], 11);
	R3(b, c, d, a, x[12], 15);
	R3(a, b, c, d, x[ 2],  3);
	R3(d, a, b, c, x[10],  9);
	R3(c, d, a, b, x[ 6], 11);
	R3(b, c, d, a, x[14], 15);
	R3(a, b, c, d, x[ 1],  3);
	R3(d, a, b, c, x[ 9],  9);
	R3(c, d, a, b, x[ 5], 11);
	R3(b, c, d, a, x[13], 15);
	R3(a, b, c, d, x[ 3],  3);
	R3(d, a, b, c, x[11],  9);
	R3(c, d, a, b, x[ 7], 11);
	R3(b, c, d, a, x[15], 15);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/*
	 * Zero out x.
	 */
	memset(x, 0, sizeof(x));
}

void
md4_update(struct md4_ctx *ctx, const void *inputptr, size_t inputlen)
{
	const uint8_t *input;
	size_t partlen;
	size_t index;
	uint32_t i;

	input = inputptr;

	/* index = (ctx->count[0] / 8) % 64; */
	index = (size_t)((ctx->count[0] >> 3) & 0x3f);

	/*
	 * ctx->count[0] += (inputlen * 8);
	 * If ctx->count[0] overflows increment ctx->count[1].
	 */
	if ((ctx->count[0] += ((uint32_t)inputlen << 3)) < (uint32_t)inputlen)
		ctx->count[1]++;
	ctx->count[1] += ((uint32_t)inputlen >> 29);

	partlen = 64 - index;
	i = 0;

	if (inputlen >= partlen) {
		memcpy(&ctx->buffer[index], input, partlen);
		md4_transform(ctx->state, ctx->buffer);

		for (i = partlen; i + 63 < inputlen; i += 64)
			md4_transform(ctx->state, &input[i]);
		index = 0;
	}

	memcpy(&ctx->buffer[index], &input[i], inputlen - i);
}

void
md4_final(uint8_t digest[16], struct md4_ctx *ctx)
{
	uint8_t bits[8];
	size_t padlen;

	/* Store count in bits[]. */
	bits[0] = (ctx->count[0]) & 0xff;
	bits[1] = (ctx->count[0] >> 8) & 0xff;
	bits[2] = (ctx->count[0] >> 16) & 0xff;
	bits[3] = (ctx->count[0] >> 24) & 0xff;
	bits[4] = (ctx->count[1]) & 0xff;
	bits[5] = (ctx->count[1] >>  8) & 0xff;
	bits[6] = (ctx->count[1] >> 16) & 0xff;
	bits[7] = (ctx->count[1] >> 24) & 0xff;

	/* Pad to 56 mod 64. */
	padlen = 64 - ((ctx->count[0] >> 3) & 0x3f);
	if (padlen <= 8)
		padlen += 64;

	md4_update(ctx, md4_padding, (padlen - 8));
	md4_update(ctx, bits, 8);

	if (digest != NULL) {
		digest[ 0] = (ctx->state[0]) & 0xff;
		digest[ 1] = (ctx->state[0] >> 8) & 0xff;
		digest[ 2] = (ctx->state[0] >> 16) & 0xff;
		digest[ 3] = (ctx->state[0] >> 24)& 0xff;
		digest[ 4] = (ctx->state[1]) & 0xff;
		digest[ 5] = (ctx->state[1] >> 8) & 0xff;
		digest[ 6] = (ctx->state[1] >> 16) & 0xff;
		digest[ 7] = (ctx->state[1] >> 24)& 0xff;
		digest[ 8] = (ctx->state[2]) & 0xff;
		digest[ 9] = (ctx->state[2] >> 8) & 0xff;
		digest[10] = (ctx->state[2] >> 16) & 0xff;
		digest[11] = (ctx->state[2] >> 24)& 0xff;
		digest[12] = (ctx->state[3]) & 0xff;
		digest[13] = (ctx->state[3] >> 8) & 0xff;
		digest[14] = (ctx->state[3] >> 16) & 0xff;
		digest[15] = (ctx->state[3] >> 24)& 0xff;
	}

	/*
	 * Zero out context.
	 */
	memset(ctx, 0, sizeof(*ctx));
}

