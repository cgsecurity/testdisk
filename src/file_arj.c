/*

    File: file_arj.c

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

static void register_header_check_arj(file_stat_t *file_stat);

const file_hint_t file_hint_arj= {
  .extension="arj",
  .description="ARJ archive",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_SIZE_32,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_arj
};

/*
 * 60 ea 24 00 22 0b 01 02  10 00 02 XX XX XX 50 48
 * ID    HS    FH V  V  OS  FL SV FT R  DATE/TIME
 *
 * Extract from "ARJ TECHNICAL INFORMATION April 1993"
   http://datacompression.info/ArchiveFormats/arj.txt
  Structure of main header (low order byte first):

     Bytes Description
-------------------------------------------------------------------
       2   header id (main and local file) = 0x60 0xEA
       2   basic header size (from 'first_hdr_size' thru 'comment' below)
		 = first_hdr_size + strlen(filename) + 1 + strlen(comment) + 1
		 = 0 if end of archive
		 maximum header size is 2600

       1   first_hdr_size (size up to and including 'extra data')
       1   archiver version number
       1   minimum archiver version to extract
       1   host OS   (0 = MSDOS, 1 = PRIMOS, 2 = UNIX, 3 = AMIGA, 4 = MAC-OS)
		     (5 = OS/2, 6 = APPLE GS, 7 = ATARI ST, 8 = NEXT)
		     (9 = VAX VMS)
       1   arj flags
		     (0x01 = NOT USED)
		     (0x02 = OLD_SECURED_FLAG)
		     (0x04 = VOLUME_FLAG)  indicates presence of succeeding
					   volume
		     (0x08 = NOT USED)
		     (0x10 = PATHSYM_FLAG) indicates archive name translated
					   ("\" changed to "/")
		     (0x20 = BACKUP_FLAG) indicates backup type archive
		     (0x40 = SECURED_FLAG)
       1   security version (2 = current)
       1   file type	    (must equal 2)
       1   reserved
       4   date time when original archive was created
       4   date time when archive was last modified
       4   archive size (currently used only for secured archives)
       4   security envelope file position
       2   filespec position in filename
       2   length in bytes of security envelope data
       2   (currently not used)
       ?   (currently none)

       ?   filename of archive when created (null-terminated string)
       ?   archive comment  (null-terminated string)

       4   basic header CRC

       2   1st extended header size (0 if none)
       ?   1st extended header (currently not used)
       4   1st extended header's CRC (not present when 0 extended header size)
 */
struct arj_main_header {
  uint16_t	header_id;
  uint16_t	basic_header_size;
  uint8_t	first_header_size;
  uint8_t	archiver_ver;
  uint8_t	archiver_ver_min;
  uint8_t	host_os;
  uint8_t	flags;
  uint8_t	security_ver;
  uint8_t	file_type;
  uint8_t	reserved;
  uint32_t	ctime;
  uint32_t	mtime;
  uint32_t	size;
  uint32_t	security_env_pos;
  uint16_t	filespec_pos;
  uint16_t	security_env_size;
  uint16_t	unused;
  char		filename;
} __attribute__ ((__packed__));

static void file_check_arj(file_recovery_t *file_recovery)
{
  static const unsigned char arj_footer[4]={0x60, 0xEA, 0x00, 0x00 };
  file_search_footer(file_recovery, arj_footer, sizeof(arj_footer), 0);
}

static int header_check_arj(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct arj_main_header *arj=(const struct arj_main_header*)buffer;
  if(le16(arj->basic_header_size) > 0 &&
      le16(arj->basic_header_size) <= 2600 &&
      arj->archiver_ver_min <= arj->archiver_ver &&
      arj->archiver_ver <=12 &&
      (arj->flags&0x01)==0 &&
      arj->file_type==2)
  {
    if((arj->flags&0x040)!=0)
    {
      if(le32(arj->size) < sizeof(struct arj_main_header))
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->calculated_file_size=le32(arj->size);
      file_recovery_new->data_check=&data_check_size;
      file_recovery_new->file_check=&file_check_size;
    }
    else
    {
//      if(le32(arj->size)!=0)
//	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->file_check=&file_check_arj;
    }
    file_recovery_new->extension=file_hint_arj.extension;
    file_recovery_new->time=le32(arj->ctime);
    if(file_recovery_new->time < le32(arj->mtime))
      file_recovery_new->time=le32(arj->mtime);
    return 1;
  }
  return 0;
}

static void register_header_check_arj(file_stat_t *file_stat)
{
  static const unsigned char arj_header[2]={0x60, 0xEA};
  register_header_check(0, arj_header,sizeof(arj_header), &header_check_arj, file_stat);
}
