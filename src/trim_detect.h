/*

    File: trim_detect.h

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
#ifndef _TRIM_DETECT_H
#define _TRIM_DETECT_H
#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

typedef struct {
  uint64_t total_sectors;
  uint64_t zero_sectors;       /* sectors that are all-zero */
  uint64_t scanned_sectors;
  double   trim_percentage;    /* zero_sectors / scanned_sectors * 100 */
} trim_stats_t;

/*@
  @ requires \valid_read(buffer + (0 .. size-1));
  @ requires size > 0;
  @ assigns \nothing;
  @*/
int is_sector_trimmed(const unsigned char *buffer, unsigned int size);

/*@
  @ requires \valid(stats);
  @ requires total > 0;
  @ assigns *stats;
  @*/
void trim_stats_init(trim_stats_t *stats, uint64_t total);

/*@
  @ requires \valid(stats);
  @ requires \valid_read(buffer + (0 .. size-1));
  @ requires size > 0;
  @ assigns *stats;
  @*/
void trim_stats_update(trim_stats_t *stats, const unsigned char *buffer,
		unsigned int size, int is_zero);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif /* _TRIM_DETECT_H */
