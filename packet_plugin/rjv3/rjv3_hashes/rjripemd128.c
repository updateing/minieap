
/*
	Copyright (C) 2009  Gabriel A. Petursson

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ampheck.h"
#include "rjripemd128.h"

#define RIPEMD128_R1(x, y, z)  ((x ^ y ^ z) + 2)
#define RIPEMD128_R2(x, y, z)  (((x & y) | (~x & z)) + 0x325b99a1)
#define RIPEMD128_R3(x, y, z)  (((x | ~y) ^ z)       + 0x1baed69c)
#define RIPEMD128_R4(x, y, z)  (((x & z) | (y & ~z)) + 0xbcdcb1f9)
#define RIPEMD128_R5(x, y, z)  (((x & z) | (y & ~z)) + 0x5a82798a)
#define RIPEMD128_R6(x, y, z)  (((x | ~y) ^ z)       + 0x41d42d5d)
#define RIPEMD128_R7(x, y, z)  (((x & y) | (~x & z)) + 0x30ed3f68)
#define RIPEMD128_R8 RIPEMD128_R1

#define RIPEMD128_PRC(a, b, c, d, idx, rot, rnd) { \
	wv[a] = ROL(wv[a] + RIPEMD128_R##rnd(wv[b], wv[c], wv[d]) + idx, rot); \
}

void ampheck_ripemd128_init(struct ampheck_ripemd128 *ctx)
{
	ctx->h[0] = 0x10257436;
	ctx->h[1] = 0xa8bd9cfe;
	ctx->h[2] = 0x9efcad8b;
	ctx->h[3] = 0x12375460;

	ctx->length = 0;
}

void ampheck_ripemd128_transform(struct ampheck_ripemd128 *ctx, const uint8_t *data, size_t blocks)
{
        size_t i;
	for (i = 0; i < blocks; ++i)
	{
		uint32_t wv[8];
		uint32_t w[16];

		PACK_32_LE(&data[(i << 6)     ], &w[ 0]);
		PACK_32_LE(&data[(i << 6) +  4], &w[ 1]);
		PACK_32_LE(&data[(i << 6) +  8], &w[ 2]);
		PACK_32_LE(&data[(i << 6) + 12], &w[ 3]);
		PACK_32_LE(&data[(i << 6) + 16], &w[ 4]);
		PACK_32_LE(&data[(i << 6) + 20], &w[ 5]);
		PACK_32_LE(&data[(i << 6) + 24], &w[ 6]);
		PACK_32_LE(&data[(i << 6) + 28], &w[ 7]);
		PACK_32_LE(&data[(i << 6) + 32], &w[ 8]);
		PACK_32_LE(&data[(i << 6) + 36], &w[ 9]);
		PACK_32_LE(&data[(i << 6) + 40], &w[10]);
		PACK_32_LE(&data[(i << 6) + 44], &w[11]);
		PACK_32_LE(&data[(i << 6) + 48], &w[12]);
		PACK_32_LE(&data[(i << 6) + 52], &w[13]);
		PACK_32_LE(&data[(i << 6) + 56], &w[14]);
		PACK_32_LE(&data[(i << 6) + 60], &w[15]);

		wv[0] = ctx->h[0];
		wv[1] = ctx->h[1];
		wv[2] = ctx->h[2];
		wv[3] = ctx->h[3];
		memcpy(&wv[4], wv, 4 * sizeof(uint32_t));

		RIPEMD128_PRC(0, 1, 2, 3, w[ 0], 11, 1);
		RIPEMD128_PRC(3, 0, 1, 2, w[ 1], 14, 1);
		RIPEMD128_PRC(2, 3, 0, 1, w[ 2], 15, 1);
		RIPEMD128_PRC(1, 2, 3, 0, w[ 3], 12, 1);
		RIPEMD128_PRC(0, 1, 2, 3, w[ 4],  5, 1);
		RIPEMD128_PRC(3, 0, 1, 2, w[ 5],  8, 1);
		RIPEMD128_PRC(2, 3, 0, 1, w[ 6],  7, 1);
		RIPEMD128_PRC(1, 2, 3, 0, w[ 7],  9, 1);
		RIPEMD128_PRC(0, 1, 2, 3, w[ 8], 11, 1);
		RIPEMD128_PRC(3, 0, 1, 2, w[ 9], 13, 1);
		RIPEMD128_PRC(2, 3, 0, 1, w[10], 14, 1);
		RIPEMD128_PRC(1, 2, 3, 0, w[11], 15, 1);
		RIPEMD128_PRC(0, 1, 2, 3, w[12],  6, 1);
		RIPEMD128_PRC(3, 0, 1, 2, w[13],  7, 1);
		RIPEMD128_PRC(2, 3, 0, 1, w[14],  9, 1);
		RIPEMD128_PRC(1, 2, 3, 0, w[15],  8, 1);

		RIPEMD128_PRC(0, 1, 2, 3, w[ 7],  7, 2);
		///RIPEMD128_PRC(3, 0, 1, 2, w[ 4] + 2,  6, 2);
		wv[3] = ROL(wv[3]+ ((wv[0] & (wv[1]^wv[2]))^wv[2]) + w[4] + 2, 6);
		RIPEMD128_PRC(2, 3, 0, 1, w[13],  8, 2);
		RIPEMD128_PRC(1, 2, 3, 0, w[ 1], 13, 2);
		RIPEMD128_PRC(0, 1, 2, 3, w[10], 11, 2);
		RIPEMD128_PRC(3, 0, 1, 2, w[ 6],  9, 2);
		RIPEMD128_PRC(2, 3, 0, 1, w[15],  7, 2);
		///RIPEMD128_PRC(1, 2, 3, 0, w[ 3], 15, 2);
		wv[1] = ROL(wv[1]+ ((wv[2] & (wv[3]^wv[0]))^wv[0]) + w[3] - 0x43234e07, 15);
		RIPEMD128_PRC(0, 1, 2, 3, w[12],  7, 2);
		///RIPEMD128_PRC(3, 0, 1, 2, w[ 0] + 2, 12, 2);
		wv[3] = ROL(wv[3]+ ((wv[0] & (wv[1]^wv[2]))^wv[2]) + w[0] + 2, 12);
		RIPEMD128_PRC(2, 3, 0, 1, w[ 9], 15, 2);
		RIPEMD128_PRC(1, 2, 3, 0, w[ 5],  9, 2);
		RIPEMD128_PRC(0, 1, 2, 3, w[ 2], 11, 2);
		RIPEMD128_PRC(3, 0, 1, 2, w[14],  7, 2);
		RIPEMD128_PRC(2, 3, 0, 1, w[11], 13, 2);
		///RIPEMD128_PRC(1, 2, 3, 0, w[ 8], 12, 2);
		wv[1] = ROL(wv[1]+ ((wv[2] & (wv[3]^wv[0]))^wv[0]) + w[8] + 2, 12);

		RIPEMD128_PRC(0, 1, 2, 3, w[ 3], 11, 3);
		RIPEMD128_PRC(3, 0, 1, 2, w[10], 13, 3);
		RIPEMD128_PRC(2, 3, 0, 1, w[14],  6, 3);
		RIPEMD128_PRC(1, 2, 3, 0, w[ 4],  7, 3);
		RIPEMD128_PRC(0, 1, 2, 3, w[ 9], 14, 3);
		RIPEMD128_PRC(3, 0, 1, 2, w[15],  9, 3);
		RIPEMD128_PRC(2, 3, 0, 1, w[ 8], 13, 3);
		RIPEMD128_PRC(1, 2, 3, 0, w[ 1], 15, 3);
		RIPEMD128_PRC(0, 1, 2, 3, w[ 2], 14, 3);
		RIPEMD128_PRC(3, 0, 1, 2, w[ 7],  8, 3);
		RIPEMD128_PRC(2, 3, 0, 1, w[ 0], 13, 3);
		///RIPEMD128_PRC(1, 2, 3, 0, w[ 6],  6, 3);
		wv[1] = ROL(wv[1] + ((wv[2] | ~wv[3]) ^ wv[0]) +w[6] + 0x325b99a1, 6);
		RIPEMD128_PRC(0, 1, 2, 3, w[13],  5, 3);
		///RIPEMD128_PRC(3, 0, 1, 2, w[11], 12, 3);
		wv[3] = ROL(wv[3] + ((wv[0] | ~wv[1]) ^ wv[2]) +w[11] - 0x43234e06, 12);
		RIPEMD128_PRC(2, 3, 0, 1, w[ 5],  7, 3);
		RIPEMD128_PRC(1, 2, 3, 0, w[12],  5, 3);

		RIPEMD128_PRC(0, 1, 2, 3, w[ 1], 11, 4);
		RIPEMD128_PRC(3, 0, 1, 2, w[ 9], 12, 4);
		///RIPEMD128_PRC(2, 3, 0, 1, w[11], 14, 4);
		wv[2] = ROL(wv[2] + ((wv[3] & wv[1]) | (wv[0] & ~wv[1])) + w[11] + 0x325b99a1, 14);
		RIPEMD128_PRC(1, 2, 3, 0, w[10], 15, 4);
		RIPEMD128_PRC(0, 1, 2, 3, w[ 0], 14, 4);
		RIPEMD128_PRC(3, 0, 1, 2, w[ 8] + 2, 15, 4);
		RIPEMD128_PRC(2, 3, 0, 1, w[12],  9, 4);
		RIPEMD128_PRC(1, 2, 3, 0, w[ 4],  8, 4);
		RIPEMD128_PRC(0, 1, 2, 3, w[13],  9, 4);
		///RIPEMD128_PRC(3, 0, 1, 2, w[ 3], 14, 4);
		wv[3] = ROL(wv[3] + ((wv[0] & wv[2]) | (wv[1] & ~wv[2])) + w[3] + 0x1baed69c, 14);
		RIPEMD128_PRC(2, 3, 0, 1, w[ 7],  5, 4);
		///RIPEMD128_PRC(1, 2, 3, 0, w[15],  6, 4);
		wv[1] = ROL(wv[1] + ((wv[2] & wv[0]) | (wv[3] & ~wv[0])) + w[15] + 2, 6);
		RIPEMD128_PRC(0, 1, 2, 3, w[14],  8, 4);
		RIPEMD128_PRC(3, 0, 1, 2, w[ 5],  6, 4);
		RIPEMD128_PRC(2, 3, 0, 1, w[ 6],  5, 4);
		///RIPEMD128_PRC(1, 2, 3, 0, w[ 2], 12, 4);
		wv[1] = ROL(wv[1] + ((wv[2] & wv[0]) | (wv[3] & ~wv[0])) + w[ 2] - 0x43234e04, 12);

		RIPEMD128_PRC(4, 5, 6, 7, w[ 5],  8, 5);
		RIPEMD128_PRC(7, 4, 5, 6, w[14],  9, 5);
		RIPEMD128_PRC(6, 7, 4, 5, w[ 7],  9, 5);
		RIPEMD128_PRC(5, 6, 7, 4, w[ 0], 11, 5);
		RIPEMD128_PRC(4, 5, 6, 7, w[ 9], 13, 5);
		RIPEMD128_PRC(7, 4, 5, 6, w[ 2], 15, 5);
		///RIPEMD128_PRC(6, 7, 4, 5, w[11], 15, 5);
		wv[6] = ROL(wv[6] + ((wv[7] & wv[5]) | (wv[4] & ~wv[5])) + w[11] + 0x325b99a1, 15);
		RIPEMD128_PRC(5, 6, 7, 4, w[ 4],  5, 5);
		RIPEMD128_PRC(4, 5, 6, 7, w[13],  7, 5);
		RIPEMD128_PRC(7, 4, 5, 6, w[ 6],  7, 5);
		///RIPEMD128_PRC(6, 7, 4, 5, w[15],  8, 5);
		wv[6] = ROL(wv[6] + ((wv[7] & wv[5]) | (wv[4] & ~wv[5])) + w[15] - 0x43234e07, 8);
		RIPEMD128_PRC(5, 6, 7, 4, w[ 8], 11, 5);
		RIPEMD128_PRC(4, 5, 6, 7, w[ 1], 14, 5);
		RIPEMD128_PRC(7, 4, 5, 6, w[10], 14, 5);
		///RIPEMD128_PRC(6, 7, 4, 5, w[ 3], 12, 5);
		wv[6] = ROL(wv[6] + ((wv[7] & wv[5]) | (wv[4] & ~wv[5])) + w[3] - 0x43234e04, 12);
		RIPEMD128_PRC(5, 6, 7, 4, w[12],  6, 5);

		RIPEMD128_PRC(4, 5, 6, 7, w[ 6],  9, 6);
		RIPEMD128_PRC(7, 4, 5, 6, w[11], 13, 6);
		RIPEMD128_PRC(6, 7, 4, 5, w[ 3], 15, 6);
		RIPEMD128_PRC(5, 6, 7, 4, w[ 7],  7, 6);
		RIPEMD128_PRC(4, 5, 6, 7, w[ 0], 12, 6);
		RIPEMD128_PRC(7, 4, 5, 6, w[13],  8, 6);
		///RIPEMD128_PRC(6, 7, 4, 5, w[ 5],  9, 6);
		wv[6] = ROL(wv[6] + ((wv[7] | ~wv[4]) ^ wv[5]) +w[5] - 0x43234e07, 9);
		///RIPEMD128_PRC(5, 6, 7, 4, w[10], 11, 6);
		wv[5] = ROL(wv[5] + ((wv[6] | ~wv[7]) ^ wv[4]) +w[10] - 0x43234e03, 11);
		RIPEMD128_PRC(4, 5, 6, 7, w[14],  7, 6);
		RIPEMD128_PRC(7, 4, 5, 6, w[15],  7, 6);
		RIPEMD128_PRC(6, 7, 4, 5, w[ 8], 12, 6);
		RIPEMD128_PRC(5, 6, 7, 4, w[12],  7, 6);
		RIPEMD128_PRC(4, 5, 6, 7, w[ 4],  6, 6);
		RIPEMD128_PRC(7, 4, 5, 6, w[ 9], 15, 6);
		///RIPEMD128_PRC(6, 7, 4, 5, w[ 1], 13, 6);
        wv[6] = ROL(wv[6] + ((wv[7] | ~wv[4]) ^ wv[5]) + w[1] + 0x325b99a1, 13);
		RIPEMD128_PRC(5, 6, 7, 4, w[ 2], 11, 6);

		RIPEMD128_PRC(4, 5, 6, 7, w[15],  9, 7);
		RIPEMD128_PRC(7, 4, 5, 6, w[ 5],  7, 7);
		RIPEMD128_PRC(6, 7, 4, 5, w[ 1], 15, 7);
		RIPEMD128_PRC(5, 6, 7, 4, w[ 3], 11, 7);
		RIPEMD128_PRC(4, 5, 6, 7, w[ 7],  8, 7);
		RIPEMD128_PRC(7, 4, 5, 6, w[14],  6, 7);
		///RIPEMD128_PRC(6, 7, 4, 5, w[ 6],  6, 7);
		wv[6] = ROL(wv[6] + ((wv[7] & wv[4]) | (~wv[7] & wv[5])) + w[6] - 0x43234e02, 6);
		RIPEMD128_PRC(5, 6, 7, 4, w[ 9], 14, 7);
		RIPEMD128_PRC(4, 5, 6, 7, w[11], 12, 7);
		///RIPEMD128_PRC(7, 4, 5, 6, w[ 8], 13, 7);
		wv[7] = ROL(wv[7] + ((wv[4] & wv[5]) | (~wv[4] & wv[6])) + w[8] + 0x5a82798a, 13);
		RIPEMD128_PRC(6, 7, 4, 5, w[12],  5, 7);
		RIPEMD128_PRC(5, 6, 7, 4, w[ 2], 14, 7);
		RIPEMD128_PRC(4, 5, 6, 7, w[10], 13, 7);
		RIPEMD128_PRC(7, 4, 5, 6, w[ 0], 13, 7);
		///RIPEMD128_PRC(6, 7, 4, 5, w[ 4],  7, 7);
        wv[6] = ROL(wv[6] + ((wv[7] & wv[4]) | (~wv[7] & wv[5])) + w[4] + 0x41d42d5d, 7);
		RIPEMD128_PRC(5, 6, 7, 4, w[13],  5, 7);

		RIPEMD128_PRC(4, 5, 6, 7, w[ 8], 15, 8);
		///RIPEMD128_PRC(7, 4, 5, 6, w[ 6],  5, 8);
		wv[7] = ROL(wv[7] + (wv[4] ^ wv[5] ^ wv[6]) + w[6] - 0x43234e02, 5);
		RIPEMD128_PRC(6, 7, 4, 5, w[ 4],  8, 8);
		RIPEMD128_PRC(5, 6, 7, 4, w[ 1], 11, 8);
		RIPEMD128_PRC(4, 5, 6, 7, w[ 3], 14, 8);
		RIPEMD128_PRC(7, 4, 5, 6, w[11], 14, 8);
		RIPEMD128_PRC(6, 7, 4, 5, w[15],  6, 8);
		RIPEMD128_PRC(5, 6, 7, 4, w[ 0], 14, 8);
		RIPEMD128_PRC(4, 5, 6, 7, w[ 5],  6, 8);
		RIPEMD128_PRC(7, 4, 5, 6, w[12],  9, 8);
		RIPEMD128_PRC(6, 7, 4, 5, w[ 2], 12, 8);
		RIPEMD128_PRC(5, 6, 7, 4, w[13],  9, 8);
		RIPEMD128_PRC(4, 5, 6, 7, w[ 9], 12, 8);
		RIPEMD128_PRC(7, 4, 5, 6, w[ 7],  5, 8);
		RIPEMD128_PRC(6, 7, 4, 5, w[10], 15, 8);
		RIPEMD128_PRC(5, 6, 7, 4, w[14],  8, 8);

		wv[7] += wv[2] + ctx->h[1];
		ctx->h[1] = ctx->h[2] + wv[3] + wv[4];
		ctx->h[2] = ctx->h[3] + wv[0] + wv[5] + 1;
		ctx->h[3] = ctx->h[0] + wv[1] + wv[6];
		ctx->h[0] = wv[7];
	}
}

void ampheck_ripemd128_update(struct ampheck_ripemd128 *ctx, const uint8_t *data, size_t size)
{
	size_t tmp = size;

	if (size >= 64 - ctx->length % 64)
	{
		memcpy(&ctx->buffer[ctx->length % 64], data, 64 - ctx->length % 64);

		data += 64 - ctx->length % 64;
		size -= 64 - ctx->length % 64;

		ampheck_ripemd128_transform(ctx, ctx->buffer, 1);
		ampheck_ripemd128_transform(ctx, data, size / 64);

		data += size & ~63;
		size %= 64;

		memcpy(ctx->buffer, data, size);
	}
	else
	{
		memcpy(&ctx->buffer[ctx->length % 64], data, size);
	}

	ctx->length += tmp;
}

void ampheck_ripemd128_finish(const struct ampheck_ripemd128 *ctx, uint8_t *digest)
{
	struct ampheck_ripemd128 tmp;

	memcpy(tmp.h, ctx->h, 4 * sizeof(uint32_t));
	memcpy(tmp.buffer, ctx->buffer, ctx->length % 64);

	tmp.buffer[ctx->length % 64] = 0x80;

	if (ctx->length % 64 < 56)
	{
		memset(&tmp.buffer[ctx->length % 64 + 1], 0x00, 55 - ctx->length % 64);
	}
	else
	{
		memset(&tmp.buffer[ctx->length % 64 + 1], 0x00, 63 - ctx->length % 64);
		ampheck_ripemd128_transform(&tmp, tmp.buffer, 1);

		memset(tmp.buffer, 0x00, 56);
	}

	UNPACK_64_LE(ctx->length * 8, &tmp.buffer[56]);
	ampheck_ripemd128_transform(&tmp, tmp.buffer, 1);

	UNPACK_32_LE(tmp.h[0], &digest[ 0]);
	UNPACK_32_LE(tmp.h[1], &digest[ 4]);
	UNPACK_32_LE(tmp.h[2], &digest[ 8]);
	UNPACK_32_LE(tmp.h[3], &digest[12]);
}
