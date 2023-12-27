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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mlv)
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
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_mlv(file_stat_t *file_stat);

const file_hint_t file_hint_mlv= {
  .extension="mlv",
  .description="Magic Lantern Video",
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
} __attribute__ ((gcc_struct, __packed__)) mlv_file_hdr_t;

typedef struct {
  uint8_t     blockType[4];
  uint32_t    blockSize;
  uint64_t    timestamp;
} __attribute__ ((gcc_struct, __packed__)) mlv_hdr_t;

/*@
  @ requires \valid_read(hdr->blockType + (0 .. 3));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static int is_valid_type(const mlv_hdr_t *hdr)
{
  unsigned int i;
  /*@
    @ loop assigns i;
    @ loop variant 4 - i;
    @*/
  for(i=0; i<4; i++)
  {
    const uint8_t c=hdr->blockType[i];
    if(!((c>='0' && c<='9') || (c>='a' && c<='z') || (c>='A' && c<='Z')))
      return 0;
  }
  return 1;
}

/*@
  @ requires fr->data_check==&data_check_mlv;
  @ requires valid_data_check_param(buffer, buffer_size, fr);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, fr);
  @ assigns fr->calculated_file_size;
  @*/
static data_check_t data_check_mlv(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *fr)
{
  /*@ assert fr->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert fr->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns fr->calculated_file_size;
    @ loop variant fr->file_size + buffer_size/2 - (fr->calculated_file_size + 8);
    @*/
  while(fr->calculated_file_size + buffer_size/2  >= fr->file_size &&
      fr->calculated_file_size + 8 < fr->file_size + buffer_size/2)
  {
    const unsigned int i=fr->calculated_file_size + buffer_size/2 - fr->file_size;
    /*@ assert 0 <= i < buffer_size - 8; */
    const mlv_hdr_t *hdr=(const mlv_hdr_t *)&buffer[i];
    if(le32(hdr->blockSize)<0x10 || !is_valid_type(hdr))
      return DC_STOP;
    fr->calculated_file_size+=le32(hdr->blockSize);
  }
  if(fr->calculated_file_size >= PHOTOREC_MAX_FILE_SIZE)
    return DC_STOP;
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->file_check == &file_check_mlv;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_mlv(file_recovery_t *file_recovery)
{
  uint64_t fs=0;
  /*@
    @ loop assigns *file_recovery->handle, errno, file_recovery->file_size;
    @ loop assigns Frama_C_entropy_source, fs;
    @ loop variant 0x8000000000000000 - fs;
    @*/
  while(fs < 0x8000000000000000)
  {
    char buffer[sizeof(mlv_hdr_t)];
    const mlv_hdr_t *hdr=(const mlv_hdr_t *)&buffer;
    if(my_fseek(file_recovery->handle, fs, SEEK_SET)<0 ||
	fread(&buffer, sizeof(buffer), 1, file_recovery->handle)!=1)
    {
      file_recovery->file_size=(fs <= file_recovery->blocksize ? 0 : fs);
      return;
    }
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&buffer, sizeof(buffer));
#endif
    if(le32(hdr->blockSize)<0x10 ||
	!is_valid_type(hdr) ||
	fs + le32(hdr->blockSize) > file_recovery->file_size)
    {
      file_recovery->file_size=(fs <= file_recovery->blocksize ? 0 : fs);
      return;
    }
    fs+=le32(hdr->blockSize);
  }
  file_recovery->file_size=0;
}

/*@
  @ requires file_recovery->file_rename == &file_rename_mlv;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_mlv(file_recovery_t *file_recovery)
{
  FILE *file;
  char buffer[sizeof(mlv_file_hdr_t)];
  const mlv_file_hdr_t *hdr=(const mlv_file_hdr_t *)&buffer;
  char ext[16];
  const char *ext_ptr=(const char *)&ext;
  /*@ assert \separated(file_recovery, ext_ptr); */
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  if(my_fseek(file, 0, SEEK_SET) < 0 ||
      fread(&buffer, sizeof(buffer), 1, file) != 1)
  {
    fclose(file);
    return ;
  }
  fclose(file);
  sprintf(ext, "M%02u", le16(hdr->fileNum));
#if defined(DISABLED_FOR_FRAMAC)
  ext[sizeof(ext)-1]='\0';
#endif
  /*@ assert valid_read_string(ext_ptr); */
  file_rename(file_recovery, NULL, 0, 0, ext_ptr, 1);
}

/*@
  @ requires buffer_size >= sizeof(mlv_file_hdr_t);
  @ requires separation: \separated(&file_hint_mlv, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_mlv(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const mlv_file_hdr_t *hdr=(const mlv_file_hdr_t *)buffer;
  if(le32(hdr->blockSize) < 0x34)
    return 0;
#ifdef DEBUG_MLV
  log_info("header_check_mlv fileCount=%u fileNum=%u\n", le16(hdr->fileCount), le16(hdr->fileNum));
#endif
  if(le16(hdr->fileCount)==0 && le16(hdr->fileNum) > 0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_mlv.extension;
    file_recovery_new->calculated_file_size=(uint64_t)le32(hdr->blockSize);
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->file_rename=&file_rename_mlv;
    return 1;
  }
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
#endif
