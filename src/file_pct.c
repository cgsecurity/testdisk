/*

    File: file_pct.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pct)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "log.h"

#if !defined(SINGLE_FORMAT)
extern const file_hint_t file_hint_indd;
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_pct(file_stat_t *file_stat);

const file_hint_t file_hint_pct= {
  .extension="pct",
  .description="Macintosh Picture",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pct
};

/* We are searching for PICTv2 files
   http://www.fileformat.info/format/macpict/
   SHORT    Version operator (0x0011)
   SHORT    Version number (0x02ff)
   SHORT    Header opcode for Version 2 (0C00)
 */

struct pct_file_entry {
  uint16_t filesize;		/* 0x00 */
  uint16_t XMin;		/* 0x02 72 DPI */
  uint16_t YMin;		/* 0x04 */
  uint16_t XMax;		/* 0x06 */
  uint16_t YMax;		/* 0x08 */
  uint16_t VersionOperator;	/* 0x0A 0x0011 */
  uint16_t VersionNumber;	/* 0x0C 0x02ff */
  uint16_t HeaderOpcode; 	/* 0x0E 0x0C00 */
  uint16_t Val;			/* 0x10 0xFFEF or 0xFFEE */
  uint16_t Reserved; 		/* 0x12 0x0000 */
  uint32_t HDPI;		/* 0x14 */
  uint32_t VDPI;		/* 0x18 */
#if 0
  uint16_t OYMax;	// pbmplus format
  uint16_t OYMin;
  uint16_t OXMax;
  uint16_t OXMin;
#else
  uint16_t OXMin;
  uint16_t OYMin;
  uint16_t OXMax;
  uint16_t OYMax;
#endif
  uint32_t Reserved2;		/* 0x24 */
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->file_check == &file_check_pct;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns  file_recovery->file_size;
  @*/
static void file_check_pct(file_recovery_t *file_recovery)
{
  uint64_t diff;
  if(file_recovery->file_size<0x210 ||
      file_recovery->file_size<file_recovery->min_filesize)
  {
    file_recovery->file_size=0;
    return ;
  }
  /*@ assert file_recovery->file_size >= file_recovery->min_filesize; */
  diff=file_recovery->file_size-file_recovery->min_filesize;
  file_recovery->file_size=file_recovery->min_filesize + (diff&0xffffffffffff0000);
}

/*@
  @ requires buffer_size >= 0x200+sizeof(struct pct_file_entry);
  @ requires separation: \separated(&file_hint_pct, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_pct(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct pct_file_entry *pct=(const struct pct_file_entry *)(&buffer[0x200]);
  if(be16(pct->XMin) <= be16(pct->XMax) &&
      be16(pct->YMin) <= be16(pct->YMax) &&
      ((be16(pct->OXMin) <= be16(pct->OXMax) &&
	be16(pct->OYMin) <= be16(pct->OYMax)) ||
       (be16(pct->OYMax) <= be16(pct->OXMax) &&	/* pbmplus creates boggus files */
	be16(pct->OYMin) <= be16(pct->OXMin))) &&
	be16(pct->XMin)==0 &&			/* Reject some valid but uncommon files */
	be16(pct->YMin)==0 &&
	be16(pct->OYMin)==0 &&
	be16(pct->VersionOperator)==0x0011 &&
	be16(pct->VersionNumber)==0x02ff)
  {
    const unsigned int min_filesize=(buffer[0x200]<<8)+buffer[0x201];
#if !defined(SINGLE_FORMAT)
    if(file_recovery->file_stat != NULL &&
	file_recovery->file_stat->file_hint==&file_hint_indd)
    {
      if(header_ignored_adv(file_recovery, file_recovery_new)==0)
	return 0;
    }
#endif
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_pct.extension;
    /* We only have the low 16bits of the filesystem */
    file_recovery_new->min_filesize=(min_filesize > 0x200+sizeof(struct pct_file_entry) ? min_filesize : 0x200+sizeof(struct pct_file_entry));
    file_recovery_new->file_check=&file_check_pct;
#ifdef DEBUG_PCT
    log_info("X %u-%u, Y %u-%u\n",
	be16(pct->XMin), be16(pct->XMax),
	be16(pct->YMin), be16(pct->YMax));
    log_info("X %u-%u, Y %u-%u\n",
	be16(pct->OXMin), be16(pct->OXMax),
	be16(pct->OYMin), be16(pct->OYMax));
#endif
    return 1;
  }
  return 0;
}

static void register_header_check_pct(file_stat_t *file_stat)
{
  static const unsigned char pct_header[6]= { 0x00, 0x11, 0x02, 0xff, 0x0c, 0x00};
  register_header_check(0x20a, pct_header,sizeof(pct_header), &header_check_pct, file_stat);
}
#endif
