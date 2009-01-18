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
#include "memmem.h"

static void register_header_check_mov(file_stat_t *file_stat);
static int header_check_mov(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static int data_check_mov(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

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
}

static int header_check_mov(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i=0;
  unsigned int prev_atom_skip=0;
  if(file_recovery!=NULL && file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_mov &&
      file_recovery->calculated_file_size == file_recovery->file_size)
  { /* PhotoRec is already trying to recover this mov file */
    return 0;
  }
  while(i<buffer_size-8)
  {
    unsigned int atom_size;
    atom_size=(buffer[i+0]<<24)+(buffer[i+1]<<16)+(buffer[i+2]<<8)+buffer[i+3];
    if(atom_size<8 || atom_size>1024*1024*1024)
      return 0;
    /* check for commun atom type */
    if(buffer[i+4]=='p' && buffer[i+5]=='n' && buffer[i+6]=='o' && buffer[i+7]=='t')
    {
      if(atom_size > 256)
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_mov.extension;
      file_recovery_new->data_check=data_check_mov;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->calculated_file_size=i+atom_size;
      return 1;
    }
    if(buffer[i+4]=='w' && buffer[i+5]=='i' && buffer[i+6]=='d' && buffer[i+7]=='e')
    {
      if(atom_size > 256)
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_mov.extension;
      file_recovery_new->data_check=data_check_mov;
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
      file_recovery_new->data_check=data_check_mov;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->calculated_file_size=i+atom_size;
      return 1;
    }
    if(buffer[i+4]=='f' && buffer[i+5]=='t' && buffer[i+6]=='y' && buffer[i+7]=='p')
    {
      unsigned int search_size=atom_size;
      if(search_size>buffer_size-i)
	search_size=buffer_size-i;
      if(td_memmem(&buffer[i+8], search_size-8, "isom", 4)!=NULL ||
	  td_memmem(&buffer[i+8], search_size-8, "mp41", 4)!=NULL ||
	  td_memmem(&buffer[i+8], search_size-8, "mp42", 4)!=NULL ||
	  td_memmem(&buffer[i+8], search_size-8, "mmp4", 4)!=NULL ||
	  td_memmem(&buffer[i+8], search_size-8, "M4A", 3)!=NULL ||
	  td_memmem(&buffer[i+8], search_size-8, "M4B", 3)!=NULL ||
	  td_memmem(&buffer[i+8], search_size-8, "M4P", 3)!=NULL)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension="mp4";
	file_recovery_new->data_check=data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=i+atom_size;
	return 1;
      }
      else if(td_memmem(&buffer[i+8], search_size-8, "3gp", 3)!=NULL)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension="3gp";
	file_recovery_new->data_check=data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=i+atom_size;
	return 1;
      }
      else if(td_memmem(&buffer[i+8], search_size-8, "3g2", 3)!=NULL)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension="3g2";
	file_recovery_new->data_check=data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=i+atom_size;
	return 1;
      }
      else if(td_memmem(&buffer[i+8], search_size-8, "jp2", 3)!=NULL)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension="jp2";
	file_recovery_new->data_check=data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=i+atom_size;
	return 1;
      }
      else if(td_memmem(&buffer[i+8], search_size-8, "qt", 2)!=NULL)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension="mov";
	file_recovery_new->data_check=data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=i+atom_size;
	return 1;
      }
    }
    if(prev_atom_skip==1 && buffer[i+4]=='m' && buffer[i+5]=='d' && buffer[i+6]=='a' && buffer[i+7]=='t')
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_mov.extension;
      file_recovery_new->data_check=data_check_mov;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->calculated_file_size=i+atom_size;
      return 1;
    }
    if(buffer[i+4]=='s' && buffer[i+5]=='k' && buffer[i+6]=='i' && buffer[i+7]=='p')
      prev_atom_skip=1;
    else
      prev_atom_skip=0;

    i+=atom_size;
  }
  return 0;
}

static int data_check_mov(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    unsigned int atom_size;
    unsigned int i;
    i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    atom_size=(buffer[i+0]<<24)+(buffer[i+1]<<16)+(buffer[i+2]<<8)+buffer[i+3];
#ifdef DEBUG_MOV
    log_trace("file_mov.c: atom %c%c%c%c (0x%02x%02x%02x%02x) size %u, calculated_file_size %llu\n",
        buffer[i+4],buffer[i+5],buffer[i+6],buffer[i+7], 
        buffer[i+4],buffer[i+5],buffer[i+6],buffer[i+7], 
        atom_size,
        (long long unsigned)file_recovery->calculated_file_size);
#endif
    if(atom_size>=8 && atom_size<1024*1024*1024 &&
        (
         (buffer[i+4]=='c' && buffer[i+5]=='m' && buffer[i+6]=='o' && buffer[i+7]=='v') ||
         (buffer[i+4]=='c' && buffer[i+5]=='m' && buffer[i+6]=='v' && buffer[i+7]=='d') ||
         (buffer[i+4]=='d' && buffer[i+5]=='c' && buffer[i+6]=='o' && buffer[i+7]=='m') ||
	 (buffer[i+4]=='f' && buffer[i+5]=='r' && buffer[i+6]=='e' && buffer[i+7]=='e') ||
         (buffer[i+4]=='f' && buffer[i+5]=='t' && buffer[i+6]=='y' && buffer[i+7]=='p') ||
         (buffer[i+4]=='j' && buffer[i+5]=='p' && buffer[i+6]=='2' && buffer[i+7]=='h') ||
         (buffer[i+4]=='m' && buffer[i+5]=='d' && buffer[i+6]=='a' && buffer[i+7]=='t') ||
         (buffer[i+4]=='m' && buffer[i+5]=='d' && buffer[i+6]=='i' && buffer[i+7]=='a') ||
         (buffer[i+4]=='m' && buffer[i+5]=='o' && buffer[i+6]=='o' && buffer[i+7]=='v') ||
         (buffer[i+4]=='P' && buffer[i+5]=='I' && buffer[i+6]=='C' && buffer[i+7]=='T') ||
         (buffer[i+4]=='p' && buffer[i+5]=='n' && buffer[i+6]=='o' && buffer[i+7]=='t') ||
         (buffer[i+4]=='s' && buffer[i+5]=='k' && buffer[i+6]=='i' && buffer[i+7]=='p') ||
         (buffer[i+4]=='s' && buffer[i+5]=='t' && buffer[i+6]=='b' && buffer[i+7]=='l') ||
         (buffer[i+4]=='t' && buffer[i+5]=='r' && buffer[i+6]=='a' && buffer[i+7]=='k') ||
         (buffer[i+4]=='u' && buffer[i+5]=='u' && buffer[i+6]=='i' && buffer[i+7]=='d') ||
         (buffer[i+4]=='w' && buffer[i+5]=='i' && buffer[i+6]=='d' && buffer[i+7]=='e')
        )
      )
    {
      file_recovery->calculated_file_size+=(uint64_t)atom_size;
    }
    else
    {
      if(!(buffer[i+4]==0 && buffer[i+5]==0 && buffer[i+6]==0 && buffer[i+7]==0))
        log_warning("file_mov.c: unknown atom 0x%02x%02x%02x%02x at %llu\n",
            buffer[i+4],buffer[i+5],buffer[i+6],buffer[i+7],
            (long long unsigned)file_recovery->calculated_file_size);
      return 2;
    }
  }
#ifdef DEBUG_MOV
  log_trace("file_mov.c: new calculated_file_size %llu\n",
      (long long unsigned)file_recovery->calculated_file_size);
#endif
  return 1;
}

