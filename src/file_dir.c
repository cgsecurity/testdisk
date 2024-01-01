/*

    File: file_dir.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dir)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "fat_common.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_dir(file_stat_t *file_stat);

const file_hint_t file_hint_dir= {
  .extension="fat",
  .description="FAT subdirectory",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=0,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dir
};

/*@
  @ requires file_recovery->file_rename==&file_rename_fatdir;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_fatdir(file_recovery_t *file_recovery)
{
  unsigned char buffer[512];
  char buffer_cluster[32];
  FILE *file;
  int buffer_size;
  unsigned int cluster;
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  buffer_size=fread(buffer, 1, sizeof(buffer), file);
  fclose(file);
  if(buffer_size<32)
    return;
  /*@ assert buffer_size >= 32; */
  cluster=fat_get_cluster_from_entry((const struct msdos_dir_entry *)&buffer[0]);
  sprintf(buffer_cluster, "cluster_%u", cluster);
#if defined(DISABLED_FOR_FRAMAC)
  buffer_cluster[sizeof(buffer_cluster)-1]='\0';
#endif
  file_rename(file_recovery, buffer_cluster, strlen(buffer_cluster), 0, NULL, 1);
}

/*@
  @ requires file_recovery->data_check == &data_check_fatdir;
  @ requires buffer_size >= 2;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures \result == DC_STOP;
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_fatdir(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /* Save only one cluster */
  file_recovery->calculated_file_size=buffer_size/2;
  return DC_STOP;
}

/*@
  @ requires buffer_size >= sizeof(struct msdos_dir_entry);
  @ requires separation: \separated(&file_hint_dir, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_dir(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct msdos_dir_entry *de=(const struct msdos_dir_entry*)buffer;
  if(!is_fat_directory(buffer))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_dir.extension;
  file_recovery_new->data_check=&data_check_fatdir;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->file_rename=&file_rename_fatdir;
  file_recovery_new->time=date_dos2unix(le16(de->time),le16(de->date));
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

static void register_header_check_dir(file_stat_t *file_stat)
{
  register_header_check(0, ".          ", 8+3, &header_check_dir, file_stat);
}
#endif
