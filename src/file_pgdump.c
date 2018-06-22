/*

    File: file_pgdump.c

    Copyright (C) 2018 Christophe GRENIER <grenier@cgsecurity.org>

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
#include <stdio.h>
#include <time.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "log.h"

/* Information from https://doxygen.postgresql.org/pg__backup__archiver_8h_source.html */
#define 	MAKE_ARCHIVE_VERSION(major, minor, rev)   (((major) * 256 + (minor)) * 256 + (rev))
/* Historical version numbers (checked in code) */
 #define K_VERS_1_0  MAKE_ARCHIVE_VERSION(1, 0, 0)
 #define K_VERS_1_2  MAKE_ARCHIVE_VERSION(1, 2, 0)   /* Allow No ZLIB */
 #define K_VERS_1_3  MAKE_ARCHIVE_VERSION(1, 3, 0)   /* BLOBs */
 #define K_VERS_1_4  MAKE_ARCHIVE_VERSION(1, 4, 0)   /* Date & name in header */
 #define K_VERS_1_5  MAKE_ARCHIVE_VERSION(1, 5, 0)   /* Handle dependencies */
 #define K_VERS_1_6  MAKE_ARCHIVE_VERSION(1, 6, 0)   /* Schema field in TOCs */
 #define K_VERS_1_7  MAKE_ARCHIVE_VERSION(1, 7, 0)   /* File Offset size in
                                                      * header */
 #define K_VERS_1_8  MAKE_ARCHIVE_VERSION(1, 8, 0)   /* change interpretation
                                                      * of ID numbers and
                                                      * dependencies */
 #define K_VERS_1_9  MAKE_ARCHIVE_VERSION(1, 9, 0)   /* add default_with_oids
                                                      * tracking */
 #define K_VERS_1_10 MAKE_ARCHIVE_VERSION(1, 10, 0)  /* add tablespace */
 #define K_VERS_1_11 MAKE_ARCHIVE_VERSION(1, 11, 0)  /* add toc section
                                                      * indicator */
 #define K_VERS_1_12 MAKE_ARCHIVE_VERSION(1, 12, 0)  /* add separate BLOB
                                                      * entries */
 #define K_VERS_1_13 MAKE_ARCHIVE_VERSION(1, 13, 0)  /* change search_path
                                                      * behavior */

struct pgdmp_hdr
{
  char		magic[5];
  uint8_t	vmaj;
  uint8_t	vmin;
  uint8_t	vrev;
  uint8_t	intSize;
  uint8_t	offSize;	/* 1.7+ */
  uint8_t	format;
  /* 1.2 uint8_t 1.4+ uint32_t assuming intSize == 4*/
  uint32_t	compression;
  /* 1.4 uint32_t assuming intSize == 4 */
  uint32_t	tm_sec;
  uint32_t	tm_min;
  uint32_t	tm_hour;
  uint32_t	tm_mday;
  uint32_t	tm_mon;
  uint32_t	tm_year;
  uint32_t	tm_isdst;
  /* connection */
  /* 1.10 */
  /* remoteVersionStr */
  /* PG_VERSION */
} __attribute__ ((gcc_struct, __packed__));

static void register_header_check_pgdump(file_stat_t *file_stat);

const file_hint_t file_hint_pgdump= {
  .extension="dump",
  .description="Postgresql Binary Dump",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pgdump
};

static int header_check_pgdump(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct pgdmp_hdr *hdr=(const struct pgdmp_hdr *)buffer;
  if(hdr->intSize == 0 || hdr->intSize > 32)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_pgdump.extension;
  return 1;
}

static void register_header_check_pgdump(file_stat_t *file_stat)
{
  register_header_check(0, "PGDMP", 5, &header_check_pgdump, file_stat);
}
