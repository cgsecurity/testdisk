/*

    File: hash_verify.c

    Copyright (C) 2025 TestDisk/PhotoRec forensic hashing module

    SHA-256 implementation following FIPS 180-4.
    No external crypto library dependency — fully portable.

    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

*/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stddef.h>

#include "hash_verify.h"

/* SHA-256 read buffer size for file hashing */
#define SHA256_FILE_BUF	4096

/* ---- FIPS 180-4 SHA-256 constants ---------------------------------- */

/* Initial hash values H0-H7 (first 32 bits of fractional parts of
   square roots of first 8 primes) */
static const uint32_t sha256_H0[8] = {
	0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
	0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

/* Round constants K[0..63] (first 32 bits of fractional parts of
   cube roots of first 64 primes) */
static const uint32_t sha256_K[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
	0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
	0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
	0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
	0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
	0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
	0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
	0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

/* ---- Bit-rotation helpers ------------------------------------------ */

static uint32_t rotr32(uint32_t x, unsigned int n)
{
	return (x >> n) | (x << (32u - n));
}

/* ---- SHA-256 sigma / Sigma functions (FIPS 180-4 §4.1.2) ----------- */

#define CH(x,y,z)	(((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)		(rotr32(x,2)  ^ rotr32(x,13) ^ rotr32(x,22))
#define EP1(x)		(rotr32(x,6)  ^ rotr32(x,11) ^ rotr32(x,25))
#define SIG0(x)		(rotr32(x,7)  ^ rotr32(x,18) ^ ((x) >> 3))
#define SIG1(x)		(rotr32(x,17) ^ rotr32(x,19) ^ ((x) >> 10))

/* ---- Process one 64-byte block ------------------------------------- */

static void sha256_transform(sha256_ctx_t *ctx, const unsigned char block[64])
{
	uint32_t W[64];
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t T1, T2;
	int i;

	/* Prepare message schedule W */
	for (i = 0; i < 16; i++) {
		W[i] = ((uint32_t)block[i * 4    ] << 24)
		      | ((uint32_t)block[i * 4 + 1] << 16)
		      | ((uint32_t)block[i * 4 + 2] <<  8)
		      | ((uint32_t)block[i * 4 + 3]);
	}
	for (i = 16; i < 64; i++) {
		W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
	}

	/* Initialize working variables */
	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	/* 64 rounds */
	for (i = 0; i < 64; i++) {
		T1 = h + EP1(e) + CH(e, f, g) + sha256_K[i] + W[i];
		T2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	/* Add compressed chunk to current hash value */
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

/* ---- Public API ---------------------------------------------------- */

void sha256_init(sha256_ctx_t *ctx)
{
	int i;
	if (!ctx)
		return;
	for (i = 0; i < 8; i++)
		ctx->state[i] = sha256_H0[i];
	ctx->count = 0;
	memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void sha256_update(sha256_ctx_t *ctx, const unsigned char *data, size_t len)
{
	size_t i;
	/* Number of bytes already sitting in ctx->buffer */
	unsigned int buf_used = (unsigned int)((ctx->count / 8) % 64);

	if (!ctx || !data || len == 0)
		return;

	ctx->count += (uint64_t)len * 8;

	/* Fill remainder of current block if any */
	if (buf_used > 0) {
		unsigned int space = 64 - buf_used;
		if (len < space) {
			memcpy(ctx->buffer + buf_used, data, len);
			return;
		}
		memcpy(ctx->buffer + buf_used, data, space);
		sha256_transform(ctx, ctx->buffer);
		data += space;
		len  -= space;
	}

	/* Process full blocks directly from input */
	for (i = 0; i + 64 <= len; i += 64)
		sha256_transform(ctx, data + i);

	/* Buffer remaining bytes */
	if (len - i > 0)
		memcpy(ctx->buffer, data + i, len - i);
}

void sha256_final(sha256_ctx_t *ctx, unsigned char digest[32])
{
	unsigned char pad[64];
	unsigned int buf_used;
	uint64_t bit_count;
	int i;

	if (!ctx || !digest)
		return;

	buf_used  = (unsigned int)((ctx->count / 8) % 64);
	bit_count = ctx->count;

	/* Append bit '1' (0x80 byte) */
	memset(pad, 0, sizeof(pad));
	pad[0] = 0x80u;

	if (buf_used < 56) {
		/* Padding fits in current block */
		sha256_update(ctx, pad, 56 - buf_used);
	} else {
		/* Need an extra block */
		sha256_update(ctx, pad, 64 - buf_used);
		memset(pad, 0, 56);
		sha256_update(ctx, pad, 56);
	}

	/* Append original bit length as 64-bit big-endian */
	pad[0] = (unsigned char)(bit_count >> 56);
	pad[1] = (unsigned char)(bit_count >> 48);
	pad[2] = (unsigned char)(bit_count >> 40);
	pad[3] = (unsigned char)(bit_count >> 32);
	pad[4] = (unsigned char)(bit_count >> 24);
	pad[5] = (unsigned char)(bit_count >> 16);
	pad[6] = (unsigned char)(bit_count >>  8);
	pad[7] = (unsigned char)(bit_count);
	sha256_update(ctx, pad, 8);

	/* Produce final digest in big-endian byte order */
	for (i = 0; i < 8; i++) {
		digest[i * 4    ] = (unsigned char)(ctx->state[i] >> 24);
		digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
		digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >>  8);
		digest[i * 4 + 3] = (unsigned char)(ctx->state[i]);
	}
}

void sha256_to_hex(const unsigned char digest[32], char hex[65])
{
	int i;
	static const char *hexchars = "0123456789abcdef";

	if (!digest || !hex)
		return;
	for (i = 0; i < 32; i++) {
		hex[i * 2    ] = hexchars[(digest[i] >> 4) & 0x0fu];
		hex[i * 2 + 1] = hexchars[ digest[i]       & 0x0fu];
	}
	hex[64] = '\0';
}

int hash_file_sha256(const char *filepath, char hex_out[65])
{
	FILE *fh;
	sha256_ctx_t ctx;
	unsigned char buf[SHA256_FILE_BUF];
	unsigned char digest[32];
	size_t n;

	if (!filepath || !hex_out)
		return -1;

	fh = fopen(filepath, "rb");
	if (!fh)
		return -1;

	sha256_init(&ctx);
	while ((n = fread(buf, 1, sizeof(buf), fh)) > 0)
		sha256_update(&ctx, buf, n);

	if (ferror(fh)) {
		fclose(fh);
		return -1;
	}
	fclose(fh);

	sha256_final(&ctx, digest);
	sha256_to_hex(digest, hex_out);
	return 0;
}
