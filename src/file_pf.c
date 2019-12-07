/*

    File: file_pf.c

    Copyright (C) 2016 Christophe GRENIER <grenier@cgsecurity.org>
    and Ralf Almon usd AG 2016
  
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
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

static void register_header_check_pf(file_stat_t *file_stat);

const file_hint_t file_hint_pf= {
  .extension="pf",
  .description="Windows prefetch file",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pf
};

struct pf_header
{
  uint32_t version;
  uint32_t magic;
  uint32_t unknown;
  uint32_t size;
  char     name[60];
  uint32_t hash;
  uint32_t unknown2;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @ requires file_recovery->file_rename==&file_rename_pf;
  @*/
static void file_rename_pf(file_recovery_t *file_recovery)
{
  FILE *file;
  struct pf_header hdr;
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  if(fread(&hdr, sizeof(hdr), 1, file) <= 0)
  {
    fclose(file);
    return ;
  }
  fclose(file);
  file_rename_unicode(file_recovery, &hdr.name, sizeof(hdr.name), 0, "pf", 0);
}

/*@
  @ requires buffer_size >= sizeof(struct pf_header);
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ requires \valid_read(file_recovery);
  @ requires file_recovery->file_stat==\null || valid_read_string((char*)file_recovery->filename);
  @ requires \valid(file_recovery_new);
  @ requires separation: \separated(file_recovery, file_recovery_new);
  @ ensures \result == 0 || \result == 1;
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_pf.extension);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size >= sizeof(struct pf_header));
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename==&file_rename_pf);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check==&data_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check==&file_check_size);
  @*/
static int header_check_pf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct pf_header *pf=(const struct pf_header *)buffer;
  const unsigned int size=le32(pf->size);
  if(size < sizeof(struct pf_header))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_pf.extension;
  file_recovery_new->calculated_file_size=size;
  file_recovery_new->file_rename=&file_rename_pf;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

/*@
  @ requires \valid(file_stat);
  @*/
static void register_header_check_pf(file_stat_t *file_stat)
{
  static const unsigned char pf_header[7] = {0x00, 0x00, 0x00, 'S', 'C', 'C', 'A'};
  register_header_check(1, pf_header,sizeof(pf_header), &header_check_pf, file_stat);
}

#if defined(MAIN_pf)
#define BLOCKSIZE 65536u
int main()
{
  const char fn[] = "recup_dir.1/f0000000.pf";
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
  file_recovery_new.location.start=0;

  file_stats.file_hint=&file_hint_pf;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
  register_header_check_pf(&file_stats);
  if(header_check_pf(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.extension == file_hint_pf.extension; */
  /*@ assert file_recovery_new.file_rename==&file_rename_pf; */
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.data_check == &data_check_size; */
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  if(file_recovery_new.file_stat!=NULL && file_recovery_new.file_stat->file_hint!=NULL &&
    file_recovery_new.data_check!=NULL)
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_size; */
    /*@ assert file_recovery_new.file_size == 0; */;
    res_data_check=data_check_size(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_size(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    /* Test when another file of the same is detected in the next block */
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
  #if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_pf(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  /*@ assert file_recovery_new.file_rename==&file_rename_pf; */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_rename_pf(&file_recovery_new);
  return 0;
}
#endif
