/*

    File: file_indd.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
    Copyright (C) 2007 Peter Turczak <pnospamt@netconsequence.de>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_indd)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_indd(file_stat_t *file_stat);

const file_hint_t file_hint_indd= {
  .extension="indd",
  .description="InDesign File",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_indd
};

/* See http://www.adobe.com/content/dam/Adobe/en/devnet/xmp/pdfs/cs6/XMPSpecificationPart3.pdf
 * for more information about the file format */

// Headers are:  DE393979-5188-4b6c-8E63-EEF8AEE0DD38
// Trailers are: FDCEDB70-F786-4b4f-A4D3-C728B3417106
static const unsigned char kINDDContigObjHeaderGUID [16] =
{ 0xDE, 0x39, 0x39, 0x79, 0x51, 0x88, 0x4B, 0x6C, 0x8E, 0x63, 0xEE, 0xF8, 0xAE, 0xE0, 0xDD, 0x38 };

struct InDesignMasterPage {
  uint8_t  fGUID [16];
  uint8_t  fMagicBytes [8];
  uint8_t  fObjectStreamEndian;
  uint8_t  fIrrelevant1 [239];
  uint64_t fSequenceNumber;
  uint8_t  fIrrelevant2 [8];
  uint32_t fFilePages;
  uint8_t  fIrrelevant3 [3812];
} __attribute__ ((gcc_struct, __packed__));

struct InDesignContigObjMarker {
  uint8_t  fGUID [16];
  uint32_t fObjectUID;
  uint32_t fObjectClassID;
  uint32_t fStreamLength;
  uint32_t fChecksum;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->file_check == &file_check_indd;
  @ requires \separated(file_recovery, file_recovery->handle, file_recovery->extension, &errno, &Frama_C_entropy_source);
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_indd(file_recovery_t *file_recovery)
{
  const uint64_t file_size_org=file_recovery->file_size;
  uint64_t offset;
  if(file_recovery->file_size<file_recovery->calculated_file_size)
  {
    file_recovery->file_size=0;
    return ;
  }
  offset=file_recovery->calculated_file_size;
  /*@
    @ loop assigns *file_recovery->handle, errno, file_recovery->file_size;
    @ loop assigns Frama_C_entropy_source;
    @ loop assigns offset;
    @ loop variant file_size_org - offset;
    @*/
  do
  {
    char buffer[sizeof(struct InDesignContigObjMarker)];
    const struct InDesignContigObjMarker *hdr=(const struct InDesignContigObjMarker *)&buffer;;
#ifdef DEBUG_INDD
    log_info("file_check_indd offset=%llu (0x%llx)\n", (long long unsigned)offset, (long long unsigned)offset);
#endif
    if(my_fseek(file_recovery->handle, offset, SEEK_SET) < 0)
    {
      file_recovery->file_size=0;
      return ;
    }
    if(fread(buffer, sizeof(buffer), 1, file_recovery->handle) != 1)
    {
      file_recovery->file_size=(offset+4096-1)/4096*4096;
      if(file_recovery->file_size>file_size_org)
	file_recovery->file_size=0;
      return ;
    }
#ifdef __FRAMAC__
    Frama_C_make_unknown(buffer, sizeof(buffer));
#endif
    if(memcmp(hdr->fGUID, kINDDContigObjHeaderGUID, sizeof(kINDDContigObjHeaderGUID))!=0)
    {
      file_recovery->file_size=(offset+4096-1)/4096*4096;
      if(file_recovery->file_size>file_size_org)
	file_recovery->file_size=0;
      return ;
    }
    /* header + data + trailer */
    offset+=(uint64_t)le32(hdr->fStreamLength)+2*sizeof(struct InDesignContigObjMarker);
  } while(offset < file_size_org);
  file_recovery->file_size=(offset+4096-1)/4096*4096;
  if(file_recovery->file_size>file_size_org)
    file_recovery->file_size=0;
  return ;
}

/*@
  @ requires buffer_size >= 4096 + sizeof(struct InDesignMasterPage);
  @ requires separation: \separated(&file_hint_indd, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_indd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct InDesignMasterPage *hdr;
  const struct InDesignMasterPage *hdr0 = (const struct InDesignMasterPage *)buffer;
  const struct InDesignMasterPage *hdr1 = (const struct InDesignMasterPage *)&buffer[4096];
  hdr=(le64(hdr0->fSequenceNumber) > le64(hdr1->fSequenceNumber) ? hdr0 : hdr1);
  if(hdr->fObjectStreamEndian!=1 && hdr->fObjectStreamEndian!=2)
    return 0;
  if(le32(hdr->fFilePages)==0)
    return 0;
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_indd)
  {
    if(header_ignored_adv(file_recovery, file_recovery_new)==0)
      return 0;
  }
  reset_file_recovery(file_recovery_new);
#ifdef DJGPP
  file_recovery_new->extension="ind";
#else
  file_recovery_new->extension=file_hint_indd.extension;
#endif
  /* Contiguous object pages may follow, file_check_indd will search for them */
  file_recovery_new->calculated_file_size=(uint64_t)(le32(hdr->fFilePages))*4096;
  file_recovery_new->file_check=&file_check_indd;
#ifdef DEBUG_INDD
  log_info("header_check_indd: Guessed length: %llu.\n", (long long unsigned)file_recovery_new->calculated_file_size);
#endif
  return 1;
}

static void register_header_check_indd(file_stat_t *file_stat)
{
  static const unsigned char indd_header[24]={
    0x06, 0x06, 0xed, 0xf5, 0xd8, 0x1d, 0x46, 0xe5,
    0xbd, 0x31, 0xef, 0xe7, 0xfe, 0x74, 0xb7, 0x1d,
    0x44, 0x4f, 0x43, 0x55, 0x4d, 0x45, 0x4e, 0x54 };
  register_header_check(0, indd_header,sizeof(indd_header), &header_check_indd, file_stat);
}
#endif
