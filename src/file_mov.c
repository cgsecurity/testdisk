/*

    File: file_mov.c

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "log.h"

static void register_header_check_mov(file_stat_t *file_stat);
static int header_check_mov(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static data_check_t data_check_mov(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_mov= {
  .extension="mov",
  .description="mov/mp4/3gp/3g2/jp2",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mov
};

static void register_header_check_mov(file_stat_t *file_stat)
{
  register_header_check(4, (const unsigned char*)"cmov",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"cmvd",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"dcom",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"free",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"ftyp",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"jp2h",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"mdat",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"mdia",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"moov",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"PICT",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"pnot",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"skip",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"stbl",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"trak",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"wide",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"jP  ",4, &header_check_mov, file_stat);
}

struct atom_struct
{
  uint32_t size;
  uint32_t type;
} __attribute__ ((__packed__));

struct atom64_struct
{
  uint32_t size1;
  uint32_t type;
  uint64_t size;
} __attribute__ ((__packed__));

static void file_rename_mov(const char *old_filename)
{
  FILE *file;
  unsigned char buffer[512];
  if((file=fopen(old_filename, "rb"))==NULL)
    return;
  if(fread(&buffer,sizeof(buffer),1,file)!=1)
  {
    fclose(file);
    return ;
  }
  fclose(file);
  buffer[8]='\0';
  file_rename(old_filename, buffer, sizeof(buffer), 4, NULL, 1);
}

static int header_check_mov(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  uint64_t i=0;
  if(buffer[4]=='f' && buffer[5]=='t' && buffer[6]=='y' && buffer[7]=='p')
  {
  }
  else if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_mov &&
      (file_recovery->calculated_file_size == file_recovery->file_size ||
       file_recovery->blocksize < 16))
  { /* PhotoRec is already trying to recover this mov file */
    return 0;
  }
  while(i<buffer_size-16)
  {
    const struct atom_struct *atom=(const struct atom_struct*)&buffer[i];
    uint64_t atom_size=be32(atom->size);
    if(atom_size==1)
    {
      const struct atom64_struct *atom64=(const struct atom64_struct*)&buffer[i];
      atom_size=be64(atom64->size);
      if(atom_size<16)
	return 0;
    }
    else if(atom_size<8)
      return 0;
    /* check for commun atom type */
    if(buffer[i+4]=='p' && buffer[i+5]=='n' && buffer[i+6]=='o' && buffer[i+7]=='t')
    {
      if(atom_size != 20)
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_mov.extension;
      file_recovery_new->file_rename=&file_rename_mov;
      if(file_recovery->blocksize < 16)
	return 1;
      file_recovery_new->data_check=&data_check_mov;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->calculated_file_size=i+atom_size;
      return 1;
    }
    if(buffer[i+4]=='w' && buffer[i+5]=='i' && buffer[i+6]=='d' && buffer[i+7]=='e')
    {
      if(atom_size != 8)
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_mov.extension;
      file_recovery_new->file_rename=&file_rename_mov;
      if(file_recovery->blocksize < 16)
	return 1;
      file_recovery_new->data_check=&data_check_mov;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->calculated_file_size=i+atom_size;
      return 1;
    }
    if(buffer[i+4]=='m' && buffer[i+5]=='o' && buffer[i+6]=='o' && buffer[i+7]=='v')
    {
      if(atom_size > 256*256*256)
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_mov.extension;
      file_recovery_new->file_rename=&file_rename_mov;
      if(file_recovery->blocksize < 16)
	return 1;
      /*
      if(i==0 && buffer[12]=='m' && buffer[13]=='v' && buffer[14]=='h' && buffer[15]=='d')
      {
	file_recovery_new->calculated_file_size=atom_size;
	file_recovery_new->data_check=&data_check_size;
      }
      else
	*/
	file_recovery_new->data_check=&data_check_mov;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->calculated_file_size=i+atom_size;
      return 1;
    }
    if(buffer[i+4]=='f' && buffer[i+5]=='t' && buffer[i+6]=='y' && buffer[i+7]=='p')
    {
      if(atom_size < 20 || (atom_size&3)!=0 || atom_size>256)
	return 0;
      if(memcmp(&buffer[i+8], "isom", 4)==0 ||
	  memcmp(&buffer[i+8], "mp41", 4)==0 ||
	  memcmp(&buffer[i+8], "mp42", 4)==0 ||
	  memcmp(&buffer[i+8], "mmp4", 4)==0 ||
	  memcmp(&buffer[i+8], "M4B", 3)==0 ||
	  memcmp(&buffer[i+8], "M4P", 3)==0)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension="mp4";
	if(file_recovery->blocksize < 16)
	  return 1;
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=i+atom_size;
	return 1;
      }
      else if(memcmp(&buffer[i+8], "M4A ", 4)==0)
      {
	reset_file_recovery(file_recovery_new);
	/* acc ? */
	file_recovery_new->extension="m4p";
	if(file_recovery->blocksize < 16)
	  return 1;
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=i+atom_size;
	return 1;
      }
      else if(memcmp(&buffer[i+8], "3gp", 3)==0)
      {
	/* Video for 3G mobile phone (GSM) */
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension="3gp";
	if(file_recovery->blocksize < 16)
	  return 1;
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=i+atom_size;
	return 1;
      }
      else if(memcmp(&buffer[i+8], "3g2", 3)==0)
      {
	/* Video for 3G mobile phone (CDMA) */
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension="3g2";
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=i+atom_size;
	return 1;
      }
      else if(memcmp(&buffer[i+8], "jp2 ", 4)==0)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension="jp2";
	/* jP + ftyp "jp2 " + jp2h + jp2c (atom_size=0) => no data check */
	return 1;
      }
      else if(memcmp(&buffer[i+8], "qt  ", 4)==0)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension="mov";
	file_recovery_new->file_rename=&file_rename_mov;
	if(file_recovery->blocksize < 16)
	  return 1;
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=i+atom_size;
	return 1;
      }
    }
    if(buffer[i+4]=='m' && buffer[i+5]=='d' && buffer[i+6]=='a' && buffer[i+7]=='t')
    {
      if(memcmp(buffer, "der.mdat\" anim=\"", 16)==0)
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_mov.extension;
      file_recovery_new->file_rename=&file_rename_mov;
      if(file_recovery->blocksize < 16)
	return 1;
      file_recovery_new->data_check=&data_check_mov;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->calculated_file_size=i+atom_size;
      return 1;
    }
    i+=atom_size;
  }
  return 0;
}

static data_check_t data_check_mov(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 <= file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const struct atom_struct *atom=(const struct atom_struct*)&buffer[i];
    uint64_t atom_size=be32(atom->size);
    if(atom_size==1)
    {
      const struct atom64_struct *atom64=(const struct atom64_struct*)&buffer[i];
      if(file_recovery->calculated_file_size + 16 > file_recovery->file_size + buffer_size/2)
	return DC_CONTINUE;
      atom_size=be64(atom64->size);
      if(atom_size<16)
	return DC_STOP;
    }
    else if(atom_size<8)
      return DC_STOP;
#ifdef DEBUG_MOV
    log_trace("file_mov.c: %s atom %c%c%c%c (0x%02x%02x%02x%02x) size %llu, calculated_file_size %llu\n",
	file_recovery->filename,
        buffer[i+4],buffer[i+5],buffer[i+6],buffer[i+7], 
        buffer[i+4],buffer[i+5],buffer[i+6],buffer[i+7], 
        (long long unsigned)atom_size,
        (long long unsigned)file_recovery->calculated_file_size);
#endif
    if(buffer[i+4]=='m' && buffer[i+5]=='d' && buffer[i+6]=='a' && buffer[i+7]=='t')
    {
      file_recovery->calculated_file_size+=atom_size;
#if 0
      if(i+8 == buffer_size)
      {
	return -((atom_size + buffer_size/2 - 1)/ (buffer_size/2));
      }
#endif
    }
    else if( (buffer[i+4]=='c' && buffer[i+5]=='m' && buffer[i+6]=='o' && buffer[i+7]=='v') ||
	(buffer[i+4]=='c' && buffer[i+5]=='m' && buffer[i+6]=='v' && buffer[i+7]=='d') ||
	(buffer[i+4]=='d' && buffer[i+5]=='c' && buffer[i+6]=='o' && buffer[i+7]=='m') ||
	(buffer[i+4]=='f' && buffer[i+5]=='r' && buffer[i+6]=='e' && buffer[i+7]=='e') ||
	(buffer[i+4]=='f' && buffer[i+5]=='t' && buffer[i+6]=='y' && buffer[i+7]=='p') ||
	(buffer[i+4]=='j' && buffer[i+5]=='p' && buffer[i+6]=='2' && buffer[i+7]=='h') ||
	(buffer[i+4]=='m' && buffer[i+5]=='d' && buffer[i+6]=='i' && buffer[i+7]=='a') ||
	(buffer[i+4]=='m' && buffer[i+5]=='o' && buffer[i+6]=='o' && buffer[i+7]=='v') ||
	(buffer[i+4]=='P' && buffer[i+5]=='I' && buffer[i+6]=='C' && buffer[i+7]=='T') ||
	(buffer[i+4]=='p' && buffer[i+5]=='n' && buffer[i+6]=='o' && buffer[i+7]=='t') ||
	(buffer[i+4]=='s' && buffer[i+5]=='k' && buffer[i+6]=='i' && buffer[i+7]=='p') ||
	(buffer[i+4]=='s' && buffer[i+5]=='t' && buffer[i+6]=='b' && buffer[i+7]=='l') ||
	(buffer[i+4]=='t' && buffer[i+5]=='r' && buffer[i+6]=='a' && buffer[i+7]=='k') ||
	(buffer[i+4]=='u' && buffer[i+5]=='u' && buffer[i+6]=='i' && buffer[i+7]=='d') ||
	(buffer[i+4]=='w' && buffer[i+5]=='i' && buffer[i+6]=='d' && buffer[i+7]=='e') )
    {
      file_recovery->calculated_file_size+=atom_size;
    }
    else
    {
      if(!(buffer[i+4]==0 && buffer[i+5]==0 && buffer[i+6]==0 && buffer[i+7]==0))
        log_warning("file_mov.c: unknown atom 0x%02x%02x%02x%02x at %llu\n",
            buffer[i+4],buffer[i+5],buffer[i+6],buffer[i+7],
            (long long unsigned)file_recovery->calculated_file_size);
      return DC_STOP;
    }
  }
#ifdef DEBUG_MOV
  log_trace("file_mov.c: new calculated_file_size %llu\n",
      (long long unsigned)file_recovery->calculated_file_size);
#endif
  return DC_CONTINUE;
}
