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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mov) || defined(SINGLE_FORMAT_mov_mdat)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "log.h"
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_mov(file_stat_t *file_stat);
/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_mov_mdat(file_stat_t *file_stat);

const file_hint_t file_hint_mov= {
  .extension="mov",
  .description="mov/mp4/3gp/3g2/jp2",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mov
};

const file_hint_t file_hint_mov_mdat= {
  .extension="mov/mdat",
  .description="Recover mdat atom as a separate file",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=0,
  .register_header_check=&register_header_check_mov_mdat
};

static const char *extension_mp4="mp4";
static const char *extension_m4a="m4a";
static const char *extension_3gp="3gp";
static const char *extension_3g2="3g2";
static const char *extension_heic="heic";
static const char *extension_jp2="jp2";
static const char *extension_cr3="cr3";

struct atom_struct
{
  uint32_t size;
  uint32_t type;
} __attribute__ ((gcc_struct, __packed__));

struct atom64_struct
{
  uint32_t size1;
  uint32_t type;
  uint64_t size;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->file_rename == &file_rename_mov;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_mov(file_recovery_t *file_recovery)
{
  FILE *file;
  unsigned char buffer[512];
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  if(fread(&buffer,sizeof(buffer),1,file)!=1)
  {
    fclose(file);
    return ;
  }
  fclose(file);
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, sizeof(buffer));
#endif
  buffer[8]='\0';
  file_rename(file_recovery, buffer, sizeof(buffer), 4, NULL, 1);
}

/*@
  @ requires \valid_read(atom + (0 .. 3));
  @ terminates \true;
  @ assigns  \nothing;
  @*/
static inline int is_known_atom(const unsigned char *atom)
{
  if( (atom[0]=='c' && atom[1]=='m' && atom[2]=='o' && atom[3]=='v') ||
      (atom[0]=='c' && atom[1]=='m' && atom[2]=='v' && atom[3]=='d') ||
      (atom[0]=='d' && atom[1]=='c' && atom[2]=='o' && atom[3]=='m') ||
      (atom[0]=='f' && atom[1]=='r' && atom[2]=='e' && atom[3]=='a') ||
      (atom[0]=='f' && atom[1]=='r' && atom[2]=='e' && atom[3]=='e') ||
      (atom[0]=='f' && atom[1]=='t' && atom[2]=='y' && atom[3]=='p') ||
      (atom[0]=='j' && atom[1]=='p' && atom[2]=='2' && atom[3]=='h') ||
      (atom[0]=='m' && atom[1]=='d' && atom[2]=='i' && atom[3]=='a') ||
      (atom[0]=='m' && atom[1]=='e' && atom[2]=='t' && atom[3]=='a') ||
      (atom[0]=='m' && atom[1]=='o' && atom[2]=='o' && atom[3]=='v') ||
      (atom[0]=='P' && atom[1]=='I' && atom[2]=='C' && atom[3]=='T') ||
      (atom[0]=='p' && atom[1]=='n' && atom[2]=='o' && atom[3]=='t') ||
      (atom[0]=='s' && atom[1]=='k' && atom[2]=='i' && atom[3]=='p') ||
      (atom[0]=='s' && atom[1]=='t' && atom[2]=='b' && atom[3]=='l') ||
      (atom[0]=='t' && atom[1]=='h' && atom[2]=='u' && atom[3]=='m') ||
      (atom[0]=='t' && atom[1]=='r' && atom[2]=='a' && atom[3]=='k') ||
      (atom[0]=='u' && atom[1]=='u' && atom[2]=='i' && atom[3]=='d') ||
      (atom[0]=='w' && atom[1]=='i' && atom[2]=='d' && atom[3]=='e') )
    return 1;
  return 0;
}

/*@
  @ requires buffer_size >= 16;
  @ requires file_recovery->data_check==&data_check_mov;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_mov(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 8);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 <= file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i <= buffer_size - 8 ; */
    const struct atom_struct *atom=(const struct atom_struct*)&buffer[i];
    /*@ assert \valid_read(atom); */
    uint64_t atom_size=be32(atom->size);
    if(atom_size==1)
    {
      const struct atom64_struct *atom64;
      if(i + 16 > buffer_size)
      {
	return DC_CONTINUE;
      }
      /*@ assert i + 16 <= buffer_size; */
      atom64=(const struct atom64_struct*)&buffer[i];
      /*@ assert \valid_read(atom64); */
      atom_size=be64(atom64->size);
      if(atom_size<16)
	return DC_STOP;
      /*@ assert atom_size >= 16; */
    }
    else if(atom_size<8)
      return DC_STOP;
    /*@ assert atom_size >= 8; */
    if(atom_size >= 0x800000000000)
      return DC_STOP;
    /*@ assert 8 <= atom_size < 0x800000000000; */
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
    else if(is_known_atom(&buffer[i+4]))
    {
      file_recovery->calculated_file_size+=atom_size;
    }
    else
    {
#ifndef DISABLED_FOR_FRAMAC
      if(!(buffer[i+4]==0 && buffer[i+5]==0 && buffer[i+6]==0 && buffer[i+7]==0))
        log_warning("file_mov.c: unknown atom 0x%02x%02x%02x%02x at %llu\n",
            buffer[i+4],buffer[i+5],buffer[i+6],buffer[i+7],
            (long long unsigned)file_recovery->calculated_file_size);
#endif
      return DC_STOP;
    }
  }
#ifdef DEBUG_MOV
  log_trace("file_mov.c: new calculated_file_size %llu\n",
      (long long unsigned)file_recovery->calculated_file_size);
#endif
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 16;
  @ requires separation: \separated(file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->file_stat == \null);
  @ ensures (\result == 1) ==> (file_recovery_new->handle == \null);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_mov.extension ||
				file_recovery_new->extension == extension_3g2 ||
				file_recovery_new->extension == extension_3gp ||
				file_recovery_new->extension == extension_cr3 ||
				file_recovery_new->extension == extension_heic ||
				file_recovery_new->extension == extension_jp2 ||
				file_recovery_new->extension == extension_m4a ||
				file_recovery_new->extension == extension_mp4);
  @ ensures (\result == 1) ==> (file_recovery_new->time == 0);
  @ ensures (\result == 1) ==> (valid_read_string(file_recovery_new->extension));
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == &file_rename_mov || file_recovery_new->file_rename == \null);
  @ ensures (\result == 1 && file_recovery_new->extension == file_hint_mov.extension) ==> (file_recovery_new->file_rename == file_rename_mov);
  @ ensures (\result == 1 && file_recovery_new->extension != file_hint_mov.extension) ==> (file_recovery_new->file_rename == \null);
  @ ensures (\result == 1 && (file_recovery_new->extension == extension_jp2 || file_recovery_new->blocksize < 16)) ==> (file_recovery_new->data_check == \null && file_recovery_new->file_check == \null && file_recovery_new->file_rename == \null && file_recovery_new->min_filesize > 0);
  @ ensures (\result == 1 && file_recovery_new->extension != extension_jp2 && file_recovery_new->blocksize >= 16) ==> (file_recovery_new->calculated_file_size > 0 && file_recovery_new->file_check == &file_check_size && file_recovery_new->data_check == &data_check_mov);
  @ ensures (\result == 1) ==> \separated(file_recovery_new, file_recovery_new->extension);
  @*/
static int header_check_mov_aux(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  uint64_t i=0;
  /*@
    @ loop variant buffer_size-16 - i;
    @*/
  while(i <= buffer_size-16)
  {
    /*@ assert i <= buffer_size - 16; */
    const struct atom_struct *atom=(const struct atom_struct*)&buffer[i];
    uint64_t calculated_file_size;
    uint64_t atom_size=be32(atom->size);
    if(atom_size==1)
    {
      const struct atom64_struct *atom64=(const struct atom64_struct*)&buffer[i];
      atom_size=be64(atom64->size);
      if(atom_size<16)
	return 0;
      /*@ assert atom_size >= 16; */
    }
    else if(atom_size<8)
      return 0;
    /*@ assert 8 <= atom_size; */
    if(atom_size >= 0x800000000000)
      return 0;
    /*@ assert 8 <= atom_size < 0x800000000000; */
    calculated_file_size=atom_size+i;
    /* check for commun atom type */
    if(buffer[i+4]=='p' && buffer[i+5]=='n' && buffer[i+6]=='o' && buffer[i+7]=='t')
    {
      if(atom_size != 20)
	return 0;
      /*@ assert atom_size == 20; */
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_mov.extension;
      file_recovery_new->file_rename=&file_rename_mov;
      if(file_recovery_new->blocksize < 16)
      {
	file_recovery_new->min_filesize=calculated_file_size;
	return 1;
      }
      file_recovery_new->data_check=&data_check_mov;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->calculated_file_size=calculated_file_size;
      return 1;
    }
    if(buffer[i+4]=='w' && buffer[i+5]=='i' && buffer[i+6]=='d' && buffer[i+7]=='e')
    {
      if(atom_size != 8)
	return 0;
      /*@ assert atom_size == 8; */
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_mov.extension;
      file_recovery_new->file_rename=&file_rename_mov;
      if(file_recovery_new->blocksize < 16)
      {
	file_recovery_new->min_filesize=calculated_file_size;
	return 1;
      }
      file_recovery_new->data_check=&data_check_mov;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->calculated_file_size=calculated_file_size;
      return 1;
    }
    if(buffer[i+4]=='m' && buffer[i+5]=='o' && buffer[i+6]=='o' && buffer[i+7]=='v')
    {
      if(atom_size > 256*256*256)
	return 0;
      /*@ assert atom_size <= 256*256*256; */
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_mov.extension;
      file_recovery_new->file_rename=&file_rename_mov;
      if(file_recovery_new->blocksize < 16)
      {
	file_recovery_new->min_filesize=calculated_file_size;
	return 1;
      }
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
      file_recovery_new->calculated_file_size=calculated_file_size;
      return 1;
    }
    if(buffer[i+4]=='f' && buffer[i+5]=='t' && buffer[i+6]=='y' && buffer[i+7]=='p')
    {
      if(atom_size < 20 || (atom_size&3)!=0 || atom_size>256)
	return 0;
      /*@ assert 20 <= atom_size <= 256; */
      if(memcmp(&buffer[i+8], "isom", 4)==0 ||
	  memcmp(&buffer[i+8], "mp41", 4)==0 ||
	  memcmp(&buffer[i+8], "mp42", 4)==0 ||
	  memcmp(&buffer[i+8], "mmp4", 4)==0 ||
	  memcmp(&buffer[i+8], "M4B", 3)==0 ||
	  memcmp(&buffer[i+8], "M4P", 3)==0 ||
	  memcmp(&buffer[i+8], "XAVC", 4)==0)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=extension_mp4;
	if(file_recovery->blocksize < 16)
	{
	  file_recovery_new->min_filesize=calculated_file_size;
	  return 1;
	}
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=calculated_file_size;
	return 1;
      }
      else if(memcmp(&buffer[i+8], "M4A ", 4)==0)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=extension_m4a;
	if(file_recovery->blocksize < 16)
	{
	  file_recovery_new->min_filesize=calculated_file_size;
	  return 1;
	}
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=calculated_file_size;
	return 1;
      }
      else if(memcmp(&buffer[i+8], "3gp", 3)==0)
      {
	/* Video for 3G mobile phone (GSM) */
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=extension_3gp;
	if(file_recovery->blocksize < 16)
	{
	  file_recovery_new->min_filesize=calculated_file_size;
	  return 1;
	}
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=calculated_file_size;
	return 1;
      }
      else if(memcmp(&buffer[i+8], "3g2", 3)==0)
      {
	/* Video for 3G mobile phone (CDMA) */
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=extension_3g2;
	if(file_recovery->blocksize < 16)
	{
	  file_recovery_new->min_filesize=calculated_file_size;
	  return 1;
	}
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=calculated_file_size;
	return 1;
      }
      else if(memcmp(&buffer[i+8], "heic", 4)==0)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=extension_heic;
	if(file_recovery->blocksize < 16)
	{
	  file_recovery_new->min_filesize=calculated_file_size;
	  return 1;
	}
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=calculated_file_size;
	return 1;
      }
      else if(memcmp(&buffer[i+8], "jp2 ", 4)==0)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=extension_jp2;
	file_recovery_new->min_filesize=calculated_file_size;
	/* jP + ftyp "jp2 " + jp2h + jp2c (atom_size=0) => no data check */
	return 1;
      }
      else if(memcmp(&buffer[i+8], "qt  ", 4)==0)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=file_hint_mov.extension;
	file_recovery_new->file_rename=&file_rename_mov;
	if(file_recovery->blocksize < 16)
	{
	  file_recovery_new->min_filesize=calculated_file_size;
	  return 1;
	}
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=calculated_file_size;
	return 1;
      }
      else if(memcmp(&buffer[i+8], "crx ", 4)==0)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=extension_cr3;
	if(file_recovery->blocksize < 16)
	{
	  file_recovery_new->min_filesize=calculated_file_size;
	  return 1;
	}
	file_recovery_new->data_check=&data_check_mov;
	file_recovery_new->file_check=&file_check_size;
	file_recovery_new->calculated_file_size=calculated_file_size;
	return 1;
      }
    }
    if(buffer[i+4]=='m' && buffer[i+5]=='d' && buffer[i+6]=='a' && buffer[i+7]=='t')
    {
      if(memcmp(&buffer[i], "der.mdat\" anim=\"", 16)==0)
	return 0;
      if(file_recovery->file_stat!=NULL &&
	  file_recovery->file_check!=NULL &&
	  buffer[8]=='a' && isprint(buffer[0]) && isprint(buffer[1]) && isprint(buffer[2]) && isprint(buffer[3]))
      {
	header_ignored(file_recovery_new);
	return 0;
      }
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_mov.extension;
      file_recovery_new->file_rename=&file_rename_mov;
      if(file_recovery_new->blocksize < 16)
      {
	file_recovery_new->min_filesize=calculated_file_size;
	return 1;
      }
      file_recovery_new->data_check=&data_check_mov;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->calculated_file_size=calculated_file_size;
      return 1;
    }
    if(atom_size > buffer_size)
      return 0;
    i+=atom_size;
  }
  return 0;
}

/*@
  @ requires buffer_size >= 16;
  @ requires separation: \separated(file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_mov.extension ||
				file_recovery_new->extension == extension_3g2 ||
				file_recovery_new->extension == extension_3gp ||
				file_recovery_new->extension == extension_cr3 ||
				file_recovery_new->extension == extension_heic ||
				file_recovery_new->extension == extension_jp2 ||
				file_recovery_new->extension == extension_m4a ||
				file_recovery_new->extension == extension_mp4);
  @ ensures (\result == 1) ==> (valid_read_string(file_recovery_new->extension));
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == &file_rename_mov || file_recovery_new->file_rename == \null);
  @ ensures (\result == 1 && file_recovery_new->extension == file_hint_mov.extension) ==> (file_recovery_new->file_rename == file_rename_mov);
  @ ensures (\result == 1 && file_recovery_new->extension != file_hint_mov.extension) ==> (file_recovery_new->file_rename == \null);
  @ ensures (\result == 1 && (file_recovery_new->extension == extension_jp2 || file_recovery_new->blocksize < 16)) ==> (file_recovery_new->data_check == \null && file_recovery_new->file_check == \null && file_recovery_new->file_rename == \null && file_recovery_new->min_filesize > 0);
  @ ensures (\result == 1 && file_recovery_new->extension != extension_jp2 && file_recovery_new->blocksize >= 16) ==> (file_recovery_new->calculated_file_size > 0 && file_recovery_new->file_check == &file_check_size && file_recovery_new->data_check == &data_check_mov);
  @*/
static int header_check_mov(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_check!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_mov &&
      file_recovery->calculated_file_size == file_recovery->file_size)
  { /* PhotoRec is already trying to recover this mov file */
    header_ignored(file_recovery_new);
    return 0;
  }
  return header_check_mov_aux(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
}

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_mov_mdat(file_stat_t *file_stat)
{
  register_header_check(4, (const unsigned char*)"mdat",4, &header_check_mov_aux, file_stat);
}

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_mov(file_stat_t *file_stat)
{
  register_header_check(4, (const unsigned char*)"cmov",4, &header_check_mov, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(4, (const unsigned char*)"cmvd",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"dcom",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"free",4, &header_check_mov, file_stat);
  register_header_check(4, (const unsigned char*)"ftyp",4, &header_check_mov_aux, file_stat);
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
#endif
}
#endif

#if defined(MAIN_mov)
#define BLOCKSIZE 65536u
int main()
{
  const char fn[] = "recup_dir.1/f0000000.mov";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  file_recovery.blocksize=BLOCKSIZE;
  file_recovery_new.blocksize=BLOCKSIZE;
  file_recovery_new.data_check=NULL;
  file_recovery_new.file_stat=NULL;
  file_recovery_new.file_check=NULL;
  file_recovery_new.file_rename=NULL;
  file_recovery_new.calculated_file_size=0;
  file_recovery_new.file_size=0;
  file_recovery_new.offset_ok=0;
  file_recovery_new.checkpoint_status=0;
  file_recovery_new.location.start=0;
  file_recovery_new.offset_error=0;

  file_stats.file_hint=&file_hint_mov;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
  register_header_check_mov(&file_stats);
  /*@ assert file_recovery_new.blocksize >= 16; */
  if(header_check_mov(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert file_recovery_new.blocksize >= 16; */
  /*@ assert valid_read_string(file_recovery_new.extension); */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.offset_ok == 0;	*/
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  /*@ assert valid_read_string((char *)&file_recovery_new.filename); */
  /*@ assert file_recovery_new.offset_ok == 0;	*/
  file_recovery_new.file_stat=&file_stats;
  if(file_recovery_new.data_check != NULL)
  {
    /*@ assert file_recovery_new.data_check == &data_check_mov; */
    /*@ assert file_recovery_new.file_check == file_check_size; */
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.file_size == 0; */;
    res_data_check=data_check_mov(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.calculated_file_size > file_recovery_new.file_size - 16; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_mov(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  /*@ assert file_recovery_new.offset_ok == 0;	*/
  {
    file_recovery_t file_recovery_new2;
    /* Test when another file of the same is detected in the next block */
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
    header_check_mov(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert file_recovery_new.offset_ok == 0;	*/
  if(file_recovery_new.file_check != NULL)
  {
    /*@ assert file_recovery_new.file_check == file_check_size; */
    file_recovery_new.handle=fopen(fn, "rb");
    if(file_recovery_new.handle!=NULL)
    {
      file_check_size(&file_recovery_new);
      fclose(file_recovery_new.handle);
    }
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_rename_mov(&file_recovery_new);
  return 0;
}
#endif
