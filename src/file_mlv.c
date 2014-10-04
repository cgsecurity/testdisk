/*

    File: file_mlv.c

    Copyright (C) 2014 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_mlv(file_stat_t *file_stat);

const file_hint_t file_hint_mlv= {
  .extension="mlv",
  .description="Magic Lantern Video",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mlv
};

/* See https://bitbucket.org/hudson/magic-lantern/src/tip/modules/mlv_rec/mlv.h?at=unified */
typedef struct {
  uint8_t     fileMagic[4];	/* Magic Lantern Video file header */
  uint32_t    blockSize;	/* size of the whole header */
  uint8_t     versionString[8];	/* null-terminated C-string of the exact revision of this format */
  uint64_t    fileGuid;		/* UID of the file (group) generated using hw counter, time of day and PRNG */
  uint16_t    fileNum;		/* the ID within fileCount this file has (0 to fileCount-1) */
  uint16_t    fileCount;	/* how many files belong to this group (splitting or parallel) */
  uint32_t    fileFlags;	/* 1=out-of-order data, 2=dropped frames, 4=single image mode, 8=stopped due to error */
  uint16_t    videoClass;	/* 0=none, 1=RAW, 2=YUV, 3=JPEG, 4=H.264 */
  uint16_t    audioClass;	/* 0=none, 1=WAV */
  uint32_t    videoFrameCount;	/* number of video frames in this file. set to 0 on start, updated when finished. */
  uint32_t    audioFrameCount;	/* number of audio frames in this file. set to 0 on start, updated when finished. */
  uint32_t    sourceFpsNom;	/* configured fps in 1/s multiplied by sourceFpsDenom */
  uint32_t    sourceFpsDenom;	/* denominator for fps. usually set to 1000, but may be 1001 for NTSC */
} __attribute__ ((__packed__)) mlv_file_hdr_t;

typedef struct {
  uint8_t     blockType[4];
  uint32_t    blockSize;
  uint64_t    timestamp;
} __attribute__ ((__packed__)) mlv_hdr_t;

static int is_valid_type(const mlv_hdr_t *hdr)
{
  unsigned int i;
  for(i=0; i<4; i++)
  {
    const uint8_t c=hdr->blockType[i];
    if(!((c>='0' && c<='9') || (c>='a' && c<='z') || (c>='A' && c<='Z')))
      return 0;
  }
  return 1;
}

static data_check_t data_check_mlv(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *fr)
{
  while(fr->calculated_file_size + buffer_size/2  >= fr->file_size &&
      fr->calculated_file_size + 8 < fr->file_size + buffer_size/2)
  {
    const unsigned int i=fr->calculated_file_size - fr->file_size + buffer_size/2;
    const mlv_hdr_t *hdr=(const mlv_hdr_t *)&buffer[i];
    if(le32(hdr->blockSize)<0x10 || !is_valid_type(hdr))
      return DC_STOP;
    fr->calculated_file_size+=le32(hdr->blockSize);
  }
  return DC_CONTINUE;
}

static void file_check_mlv(file_recovery_t *file_recovery)
{
  mlv_hdr_t hdr;
  uint64_t fs=0;
  do
  {
    if(
#ifdef HAVE_FSEEKO
	fseeko(file_recovery->handle, fs, SEEK_SET)<0 ||
#else
	fseek(file_recovery->handle, fs, SEEK_SET)<0 ||
#endif
	fread(&hdr, sizeof(hdr), 1, file_recovery->handle)!=1 ||
	le32(hdr.blockSize)<0x10 ||
	!is_valid_type(&hdr) ||
	fs + le32(hdr.blockSize) > file_recovery->file_size)
    {
      file_recovery->file_size=fs;
      return;
    }
    fs+=le32(hdr.blockSize);
  } while(1);
}
static int header_check_mlv(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const mlv_file_hdr_t *hdr=(const mlv_file_hdr_t *)buffer;
  if(le32(hdr->blockSize) < 0x34)
    return 0;
  if(le16(hdr->fileNum) > le16(hdr->fileCount))
    return 0;
  if(le16(hdr->fileNum) >= le16(hdr->fileCount) && le16(hdr->fileCount)>0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_mlv.extension;
  file_recovery_new->file_check=&file_check_mlv;
  if(file_recovery_new->blocksize > 0x10)
    file_recovery_new->data_check=&data_check_mlv;
  return 1;
}

static void register_header_check_mlv(file_stat_t *file_stat)
{
  register_header_check(0, "MLVI", 4, &header_check_mlv, file_stat);
}
