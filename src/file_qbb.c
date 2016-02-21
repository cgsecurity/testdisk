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
 unsigned char data[0];
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
 uint8_t  title[0];
} __attribute__ ((gcc_struct, __packed__));

static void file_rename_qbb(file_recovery_t *file_recovery)
{
  FILE *file;
  unsigned int i=0;
  unsigned char buffer[4096];
  size_t lu;
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  lu=fread(&buffer, 1, sizeof(buffer), file);
  fclose(file);
  while(i+sizeof(struct qbb_header02) < lu)
  {
    const struct qbb_header *hdr=(const struct qbb_header*)&buffer[i];
    if(le16(hdr->magic)!=0x8645)
      return ;
    if(le16(hdr->type)==2)
    {
      const struct qbb_header02 *hdr2=(const struct qbb_header02 *)hdr;
      if(sizeof(struct qbb_header02)+le16(hdr2->title_len) <= sizeof(struct qbb_header)+le16(hdr2->data_len) &&
	  i+sizeof(struct qbb_header)+le16(hdr->data_len) < lu)
	file_rename(file_recovery, hdr2->title, le16(hdr2->title_len), 0, NULL, 1);
      return ;
    }
    i+=sizeof(struct qbb_header)+le16(hdr->data_len);
  }
}

static int header_check_qbb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct qbb_header *hdr0=(const struct qbb_header*)buffer;
  uint64_t data_size=0;
  unsigned int i=0;
  if(buffer[0x0e]!=0x45 || buffer[0x0f]!=0x86)
    return 0;
  while(i+sizeof(struct qbb_header02) < buffer_size)
  {
    const struct qbb_header *hdr=(const struct qbb_header*)&buffer[i];
    if(le16(hdr->magic)!=0x8645)
      break;
    if(le16(hdr->type)==2)
    {
      const struct qbb_header02 *hdr2=(const struct qbb_header02 *)hdr;
      data_size=le32(hdr2->size);
    }
#ifdef DEBUG_QBB
    log_info("i=0x%x size=0x%lx len=0x%x\n", i, sizeof(struct qbb_header), le16(hdr->data_len));
#endif
    i+=sizeof(struct qbb_header)+le16(hdr->data_len);
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
