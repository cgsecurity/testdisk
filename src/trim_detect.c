/*

    File: trim_detect.c

    Copyright (C) 2024 TestDisk Contributors

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

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include "trim_detect.h"

/*
 * is_sector_trimmed: return 1 if the entire buffer is zero, 0 otherwise.
 *
 * Uses word-size (uintptr_t) comparisons to scan the bulk of the buffer
 * efficiently before falling back to byte comparison for any tail remainder.
 */
int is_sector_trimmed(const unsigned char *buffer, unsigned int size)
{
	const unsigned char *p;
	const unsigned char *end;
	const uintptr_t *wp;
	const uintptr_t *wend;
	unsigned int word_bytes;

	if(buffer == NULL || size == 0)
		return 0;

	p   = buffer;
	end = buffer + size;

	/* Align pointer up to word boundary */
	while(p < end && ((uintptr_t)p % sizeof(uintptr_t)) != 0)
	{
		if(*p != 0)
			return 0;
		p++;
	}

	/* Word-size scan over aligned region */
	wp    = (const uintptr_t *)p;
	word_bytes = (unsigned int)((end - p) / sizeof(uintptr_t)) * (unsigned int)sizeof(uintptr_t);
	wend  = (const uintptr_t *)(p + word_bytes);

	while(wp < wend)
	{
		if(*wp != 0)
			return 0;
		wp++;
	}

	/* Byte scan over trailing remainder */
	p = (const unsigned char *)wend;
	while(p < end)
	{
		if(*p != 0)
			return 0;
		p++;
	}

	return 1;
}

/*
 * trim_stats_init: initialise a trim_stats_t for a scan covering total_sectors.
 */
void trim_stats_init(trim_stats_t *stats, uint64_t total)
{
	if(stats == NULL)
		return;
	memset(stats, 0, sizeof(*stats));
	stats->total_sectors = total;
}

/*
 * trim_stats_update: record one sector's worth of data.
 *
 * Callers pass the buffer and its size; is_zero should be the return value
 * of is_sector_trimmed() for that buffer (pre-computed so callers can reuse
 * the result for other purposes without a redundant scan).
 */
void trim_stats_update(trim_stats_t *stats, const unsigned char *buffer,
		unsigned int size, int is_zero)
{
	if(stats == NULL || buffer == NULL || size == 0)
		return;

	stats->scanned_sectors++;

	if(is_zero)
		stats->zero_sectors++;

	if(stats->scanned_sectors > 0)
	{
		stats->trim_percentage =
			(double)stats->zero_sectors /
			(double)stats->scanned_sectors * 100.0;
	}
	else
	{
		stats->trim_percentage = 0.0;
	}
}
