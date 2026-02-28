/*

    File: file_bkf.c

    Copyright (C) 2006-2007 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bkf)
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

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_bkf(file_stat_t *file_stat);

const file_hint_t file_hint_bkf= {
  .extension="bkf",
  .description="MS Backup file",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_bkf
};

/* SQL Server BAK extension (not registered as separate hint) */
static const char *extension_bak = "bak";

struct mtf_db_hdr
{
  uint32_t	type;		/* DBLK type */
  uint32_t	attr;		/* block attributes */
  uint16_t	off;		/* offset to first event */
  uint8_t	osId;		/* OS ID */
  uint8_t	osVer;		/* OS version */
  uint64_t	size;		/* displayable size */
  uint64_t	fla;		/* format logical address */
  uint16_t 	mbc;		/* reserved for MBC */
  uint8_t	rsv1[6];	/* reserved for future use */
  uint32_t	cbId;		/* control block ID */
  uint8_t	rsv2[4];	/* reserved for future use */
  uint32_t	osData;		/* OS-specific data */
  uint8_t	strType;	/* string type */
  uint8_t	rsv3;		/* reserved for future use */
  uint16_t	check;		/* header checksum */
} __attribute__ ((gcc_struct, __packed__));

/* "Microsoft SQL Server" in UTF-16LE (first 14 chars: "Microsof") */
static const unsigned char sql_server_sig[16] = {
  'M',0,'i',0,'c',0,'r',0,'o',0,'s',0,'o',0,'f',0
};

/*@
  @ requires buffer_size > 0;
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ assigns \nothing;
  @*/
static int is_sql_server_backup(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int tape_off)
{
  unsigned int pos;
  /* Scan for SSET DBLK after TAPE header, then look for SQL Server string */
  /*@
    @ loop assigns pos;
    @ loop variant buffer_size - 4 - pos;
    @*/
  for(pos = tape_off; pos + 4 <= buffer_size; pos += 4)
  {
    if(buffer[pos]=='S' && buffer[pos+1]=='S' &&
       buffer[pos+2]=='E' && buffer[pos+3]=='T')
    {
      /* Found SSET DBLK; scan region after it for SQL Server Unicode string */
      unsigned int j;
      const unsigned int search_end = (pos + 1024 < buffer_size) ? pos + 1024 : buffer_size;
      if(search_end < sizeof(sql_server_sig))
        return 0;
      /*@
        @ loop assigns j;
        @ loop variant search_end - sizeof(sql_server_sig) - j;
        @*/
      for(j = pos + 4; j + sizeof(sql_server_sig) <= search_end; j++)
      {
        if(memcmp(&buffer[j], sql_server_sig, sizeof(sql_server_sig)) == 0)
          return 1;
      }
      return 0;
    }
  }
  return 0;
}

/*@
  @ requires file_recovery->file_check == &file_check_bkf;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_bkf(file_recovery_t *file_recovery)
{
  const unsigned char bkf_footer[4]= { 'S', 'F', 'M', 'B'};
  file_search_footer(file_recovery, bkf_footer, sizeof(bkf_footer), 0x400-4);
}

/*@
  @ requires buffer_size >= sizeof(struct mtf_db_hdr);
  @ requires separation: \separated(&file_hint_bkf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> file_recovery_new->file_size == 0;
  @ ensures (\result == 1) ==> (file_recovery_new->time == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 52);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_bkf);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_bkf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct mtf_db_hdr *hdr=(const struct mtf_db_hdr *)buffer;
  /* Microsoft Tape Format
   * The DBLK Type field is set to 'TAPE'.
   * The Format Logical Address field is set to zero.
   * The Control Block ID field is set to zero.
   */
  if(le64(hdr->fla)!=0 || le32(hdr->cbId)!=0 || hdr->strType>2 ||
      le16(hdr->off)<sizeof(struct mtf_db_hdr))
    return 0;
#ifdef DEBUG_BKF
  log_info("off=%u\n", le16(hdr->off));
#endif
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=52;
  file_recovery_new->file_check=&file_check_bkf;
  /* Detect SQL Server backup vs Windows NTBackup */
  if(is_sql_server_backup(buffer, buffer_size, le16(hdr->off)))
    file_recovery_new->extension=extension_bak;
  else
    file_recovery_new->extension=file_hint_bkf.extension;
  return 1;
}

static void register_header_check_bkf(file_stat_t *file_stat)
{
  static const unsigned char bkf_header[4]= { 'T','A','P','E'};
  register_header_check(0, bkf_header,sizeof(bkf_header), &header_check_bkf, file_stat);
}
#endif
