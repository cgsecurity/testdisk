/*

    File: file_qbb.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_qbb)
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
#ifdef DEBUG_QBB
#include "log.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_qbb(file_stat_t *file_stat);

const file_hint_t file_hint_qbb= {
  .extension="qbb",
  .description="Quickbooks (qbb/qbw)",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_qbb
};

struct qbb_header
{
 uint16_t magic;
 uint16_t type;
 uint16_t data_len;
 uint16_t unk1;
#if 0
 unsigned char data[0];
#endif
} __attribute__ ((gcc_struct, __packed__));

struct qbb_header02
{
 uint16_t magic;
 uint16_t type;		/* 2 */
 uint16_t data_len;
 uint16_t unk1;
 uint8_t  unk2[6];
 uint32_t size;
 uint8_t  unk3[10];
 uint16_t title_len;
#if 0
 uint8_t  title[0];
#endif
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->file_rename==&file_rename_qbb;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_qbb(file_recovery_t *file_recovery)
{
  FILE *file;
  unsigned int i=0;
  char buffer[4096];
  /*@ assert \valid((char *)&buffer + (0 .. sizeof(buffer)-1)); */
  size_t lu;
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  lu=fread(&buffer, 1, sizeof(buffer), file);
  fclose(file);
  if(lu <= 0)
    return;
  /*@ assert 0 < lu <= sizeof(buffer); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown(buffer, sizeof(buffer));
#endif
  /*@ assert \valid_read((char *)&buffer + (0 .. lu-1)); */
  /*@
    @ loop assigns i;
    @ loop variant lu - (i+sizeof(struct qbb_header02));
    @*/
  while(i+sizeof(struct qbb_header02) <= lu)
  {
    /*@ assert i+sizeof(struct qbb_header02) <= lu; */
    /*@ assert i+sizeof(struct qbb_header) <= lu; */
    const struct qbb_header *hdr=(const struct qbb_header*)&buffer[i];
    const unsigned int data_len=le16(hdr->data_len);
    if(le16(hdr->magic)!=0x8645)
      return ;
    if(le16(hdr->type)==2)
    {
      if(i+sizeof(struct qbb_header)+data_len < lu)
      {
	const struct qbb_header02 *hdr2=(const struct qbb_header02 *)&buffer[i];
	/*@ assert \valid_read(hdr2); */
	const unsigned int title_len=le16(hdr2->title_len);
	if(sizeof(struct qbb_header02)+title_len <= sizeof(struct qbb_header)+data_len)
	{
	  const char *title=&buffer[i+sizeof(struct qbb_header02)];
	  file_rename(file_recovery, title, title_len, 0, NULL, 1);
	}
      }
      return ;
    }
    i+=sizeof(struct qbb_header)+data_len;
  }
}

/*@
  @ requires buffer_size >= 0x10;
  @ requires separation: \separated(&file_hint_qbb, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_qbb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct qbb_header *hdr0=(const struct qbb_header*)buffer;
  uint64_t data_size=0;
  unsigned int i=0;
  if(buffer[0x0e]!=0x45 || buffer[0x0f]!=0x86)
    return 0;
  /*@
    @ loop assigns i, data_size;
    @ loop variant buffer_size - (i+sizeof(struct qbb_header02));
    @*/
  while(i+sizeof(struct qbb_header02) < buffer_size)
  {
    const struct qbb_header *hdr=(const struct qbb_header*)&buffer[i];
    const unsigned int data_len=le16(hdr->data_len);
    if(le16(hdr->magic)!=0x8645)
      break;
    if(le16(hdr->type)==2)
    {
      const struct qbb_header02 *hdr2=(const struct qbb_header02 *)hdr;
      data_size=le32(hdr2->size);
    }
#ifdef DEBUG_QBB
    log_info("i=0x%x size=0x%lx len=0x%x\n", i, sizeof(struct qbb_header), data_len);
#endif
    i+=sizeof(struct qbb_header)+data_len;
  }
#ifdef DEBUG_QBB
  log_info("i=0x%x data_size=0x%lx\n", i, (long unsigned)data_size);
#endif
  if(data_size==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->calculated_file_size=data_size+i;
  if(le16(hdr0->unk1)==1)
    file_recovery_new->extension="qbmb";
  else
    file_recovery_new->extension=file_hint_qbb.extension;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->file_rename=&file_rename_qbb;
  return 1;
}

/*@
  @ requires buffer_size >= 0x64;
  @ requires separation: \separated(&file_hint_qbb, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_qbw(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0x60]=='M' && buffer[0x61]=='A' && buffer[0x62]=='U' && buffer[0x63]=='I')
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="qbw";
    file_recovery_new->calculated_file_size=(((uint64_t)buffer[0x34] + (((uint64_t)buffer[0x34+1])<<8)+
      (((uint64_t)buffer[0x34+2])<<16) + (((uint64_t)buffer[0x34+3])<<24))+1)*1024;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

/*@
  @ requires buffer_size >= 0x87A + 6;
  @ requires separation: \separated(&file_hint_qbb, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_qbw2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(&buffer[0x87A], "Sybase", 6)==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="qbw";
    return 1;
  }
  return 0;
}

static void register_header_check_qbb(file_stat_t *file_stat)
{
  static const unsigned char qbb_header[8]=  {0x45, 0x86, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00};
  static const unsigned char qbmb_header[8]= {0x45, 0x86, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00};
  static const unsigned char qbw2_header[4]= {0x5e, 0xba, 0x7a, 0xda};
  static const unsigned char qbw_header[4]= {0x56, 0x00, 0x00, 0x00};
  register_header_check(0, qbb_header,sizeof(qbb_header), &header_check_qbb, file_stat);
  register_header_check(0, qbmb_header,sizeof(qbmb_header), &header_check_qbb, file_stat);
  register_header_check(4, qbw_header,sizeof(qbw_header), &header_check_qbw, file_stat);
  register_header_check(0x14, qbw2_header,sizeof(qbw2_header), &header_check_qbw2, file_stat);
}
#endif
