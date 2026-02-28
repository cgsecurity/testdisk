/*

    File: hash_verify.h

    Copyright (C) 2025 TestDisk/PhotoRec forensic hashing module

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
#ifndef _HASH_VERIFY_H
#define _HASH_VERIFY_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stddef.h>

/* SHA-256 context — FIPS 180-4 */
typedef struct {
	uint32_t	state[8];
	uint64_t	count;		/* total bits processed */
	unsigned char	buffer[64];	/* pending block */
} sha256_ctx_t;

void	sha256_init(sha256_ctx_t *ctx);
void	sha256_update(sha256_ctx_t *ctx, const unsigned char *data, size_t len);
void	sha256_final(sha256_ctx_t *ctx, unsigned char digest[32]);
void	sha256_to_hex(const unsigned char digest[32], char hex[65]);

/* Convenience: hash a file by path; returns 0 on success, -1 on error */
int	hash_file_sha256(const char *filepath, char hex_out[65]);

#endif /* _HASH_VERIFY_H */
