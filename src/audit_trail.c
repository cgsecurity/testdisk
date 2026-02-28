/*

    File: audit_trail.c

    Copyright (C) 2025 TestDisk/PhotoRec forensic audit trail module

    Append-only, cryptographically chained log.

    Entry format (pipe-delimited, one entry per line):
      TIMESTAMP|PREV_HASH|OPERATION|DETAILS|ENTRY_HASH

    ENTRY_HASH = SHA-256( TIMESTAMP "|" PREV_HASH "|" OPERATION "|" DETAILS )
    PREV_HASH  = ENTRY_HASH of the previous line;
                 "0000...0000" (64 zeros) for the very first entry.

    Pipe characters inside OPERATION or DETAILS are escaped as \x7c so the
    format remains unambiguously parseable.

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
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "hash_verify.h"
#include "audit_trail.h"

/* Zero hash used as PREV_HASH for the first log entry */
#define ZERO_HASH \
	"0000000000000000000000000000000000000000000000000000000000000000"

/* Maximum length of an escaped operation or details field */
#define FIELD_MAX	1024

/* Module-level state — single open trail at a time */
static FILE	*trail_fh   = NULL;
static char	 prev_hash[65];		/* hex SHA-256 of previous entry */

/* ---- helpers ------------------------------------------------------- */

/* ISO 8601 timestamp into buf (size >= 32) */
static void iso8601_now(char *buf, size_t bufsize)
{
	time_t now;
	struct tm *tmp;
#if !defined(__MINGW32__)
	struct tm tm_tmp;
#endif
	time(&now);
#if defined(__MINGW32__)
	tmp = localtime(&now);
#else
	tmp = localtime_r(&now, &tm_tmp);
#endif
	if (!tmp || strftime(buf, bufsize, "%Y-%m-%dT%H:%M:%S%z", tmp) == 0)
		snprintf(buf, bufsize, "1970-01-01T00:00:00+0000");
}

/*
 * Copy src into dst (capacity dstsize), replacing every '|' with the
 * literal sequence \x7c so the field delimiter is unambiguous.
 * dst is always NUL-terminated.
 */
static void escape_field(char *dst, size_t dstsize, const char *src)
{
	size_t wi = 0;	/* write index into dst */

	if (!src || dstsize == 0)
		goto done;

	while (*src && wi + 1 < dstsize) {
		if (*src == '|') {
			/* \x7c needs 4 bytes; ensure space */
			if (wi + 4 >= dstsize)
				break;
			dst[wi++] = '\\';
			dst[wi++] = 'x';
			dst[wi++] = '7';
			dst[wi++] = 'c';
		} else {
			dst[wi++] = *src;
		}
		src++;
	}
done:
	if (dstsize > 0)
		dst[wi < dstsize ? wi : dstsize - 1] = '\0';
}

/* ---- Public API ---------------------------------------------------- */

int audit_trail_open(const char *filepath)
{
	if (!filepath)
		return -1;
	if (trail_fh != NULL)
		return -1;	/* already open */

	trail_fh = fopen(filepath, "a");
	if (!trail_fh)
		return -1;

	/* Initialise chain with zero hash */
	strncpy(prev_hash, ZERO_HASH, sizeof(prev_hash));
	prev_hash[64] = '\0';

	/* Log the open event as the first entry */
	return audit_trail_log("OPEN", filepath);
}

int audit_trail_log(const char *operation, const char *details)
{
	char ts[32];
	char op_esc[FIELD_MAX];
	char det_esc[FIELD_MAX];
	/* Buffer holding the canonical string that is hashed:
	 * TIMESTAMP|PREV_HASH|OPERATION|DETAILS  (no trailing pipe) */
	char hashbuf[32 + 1 + 64 + 1 + FIELD_MAX + 1 + FIELD_MAX + 4];
	unsigned char digest[32];
	char entry_hash[65];
	sha256_ctx_t ctx;
	int written;

	if (!trail_fh || !operation || !details)
		return -1;

	iso8601_now(ts, sizeof(ts));
	escape_field(op_esc,  sizeof(op_esc),  operation);
	escape_field(det_esc, sizeof(det_esc), details);

	/* Build the string to hash */
	written = snprintf(hashbuf, sizeof(hashbuf),
		"%s|%s|%s|%s", ts, prev_hash, op_esc, det_esc);
	if (written < 0 || (size_t)written >= sizeof(hashbuf))
		return -1;

	/* Compute ENTRY_HASH */
	sha256_init(&ctx);
	sha256_update(&ctx, (const unsigned char *)hashbuf,
		(size_t)written);
	sha256_final(&ctx, digest);
	sha256_to_hex(digest, entry_hash);

	/* Write the full entry line */
	fprintf(trail_fh, "%s|%s|%s|%s|%s\n",
		ts, prev_hash, op_esc, det_esc, entry_hash);
	fflush(trail_fh);

	/* Advance chain */
	strncpy(prev_hash, entry_hash, sizeof(prev_hash));
	prev_hash[64] = '\0';

	return 0;
}

int audit_trail_close(void)
{
	int rc;

	if (!trail_fh)
		return -1;

	rc = audit_trail_log("CLOSE", "audit trail closed");
	fflush(trail_fh);
	fclose(trail_fh);
	trail_fh = NULL;
	memset(prev_hash, 0, sizeof(prev_hash));
	return rc;
}
