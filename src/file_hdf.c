/*

    File: file_hdf.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hdf)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#ifdef DEBUG_HDF
#include "log.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_hdf(file_stat_t *file_stat);

const file_hint_t file_hint_hdf= {
  .extension="hdf",
  .description="Hierarchical Data Format 4",
  .max_filesize=PHOTOREC_MAX_SIZE_32,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_hdf
};

struct ddh_struct
{
  uint16_t	size;
  uint32_t	next;
} __attribute__ ((gcc_struct, __packed__));

struct dd_struct
{
  uint16_t	tag;
  uint16_t	ref;
  uint32_t	offset;
  uint32_t	length;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires \valid(handle);
  @ requires \valid(dd_buf + (0 .. 65536 * sizeof(struct dd_struct)-1));
  @ requires \separated(handle, dd_buf + (..), &errno, &Frama_C_entropy_source);
  @ assigns *(dd_buf + (0 .. 65536 * sizeof(struct dd_struct)-1));
  @ assigns Frama_C_entropy_source;
  @ assigns *handle, errno;
  @*/
static uint64_t file_check_hdf_aux(FILE *handle, char *dd_buf)
{
  uint64_t file_size=0;
  uint64_t offset_old;
  uint64_t offset=4;
  const struct dd_struct *dd=(const struct dd_struct *)dd_buf;
  /*@
    @ loop assigns file_size, offset_old, offset;
    @ loop assigns *(dd_buf + (0 .. 65536 * sizeof(struct dd_struct)-1));
    @ loop assigns Frama_C_entropy_source;
    @ loop assigns *handle, errno;
    @*/
  do
  {
    char ddh_buf[sizeof(struct ddh_struct)];
    const struct ddh_struct *ddh=(const struct ddh_struct *)&ddh_buf;
    unsigned int i;
    unsigned int size;
    if(my_fseek(handle, offset, SEEK_SET) < 0 ||
	fread(&ddh_buf, sizeof(ddh_buf), 1, handle) !=1)
    {
      return 0;
    }
#ifdef __FRAMAC__
    Frama_C_make_unknown(&ddh_buf, sizeof(ddh_buf));
#endif
    size=be16(ddh->size);
    /*@ assert 0 <= size < 65536; */
    if(size==0 ||
	fread(dd_buf, sizeof(struct dd_struct)*size, 1, handle) !=1)
    {
      return 0;
    }
#ifdef __FRAMAC__
    Frama_C_make_unknown(dd_buf, sizeof(struct dd_struct)*size);
#endif
    if(file_size < offset + sizeof(struct dd_struct) * size)
      file_size = offset + sizeof(struct dd_struct) * size;
#ifdef DEBUG_HDF
    log_info("size=%u next=%lu\n", size, be32(ddh->next));
#endif
    /*@
      @ loop invariant 0 <= i <= size;
      @ loop assigns i, file_size;
      @ loop variant size - i;
      @*/
    for(i=0; i < size; i++)
    {
      const struct dd_struct *p=&dd[i];
      const unsigned int p_offset=be32(p->offset);
      const unsigned int p_length=be32(p->length);
#ifdef DEBUG_HDF
      log_info("tag=0x%04x, ref=%u, offset=%lu, length=%lu\n",
	  be16(p->tag), be16(p->ref), p_offset, p_length);
#endif
      if(p_offset!=0xffffffff &&
	file_size < (uint64_t)p_offset + (uint64_t)p_length)
	file_size = (uint64_t)p_offset + (uint64_t)p_length;
    }
    offset_old=offset;
    offset=be32(ddh->next);
  } while(offset > offset_old);
  file_size++;
  return file_size;
}

/*@
  @ requires \separated(file_recovery, file_recovery->handle, &errno, &Frama_C_entropy_source, &__fc_heap_status);
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @*/
static void file_check_hdf(file_recovery_t *file_recovery)
{
  uint64_t file_size;
  char *dd;
  dd=(char *)MALLOC(sizeof(struct dd_struct)*65536);
  file_size = file_check_hdf_aux(file_recovery->handle, dd);
  free(dd);
#ifdef DEBUG_HDF
  log_info("file_size %llu\n", (long long unsigned)file_size);
#endif
  if(file_recovery->file_size < file_size || file_size==0)
    file_recovery->file_size=0;
  else
    file_recovery->file_size = file_size;
}

/*@
  @ requires buffer_size >= sizeof(struct ddh_struct);
  @ requires separation: \separated(&file_hint_hdf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_hdf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct ddh_struct *ddh=(const struct ddh_struct *)&buffer[4];
  if(be16(ddh->size)==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_hdf.extension;
  file_recovery_new->file_check=&file_check_hdf;
  return 1;
}

static void register_header_check_hdf(file_stat_t *file_stat)
{
  static const unsigned char hdf_header[4]=  { 0x0e, 0x03, 0x13, 0x01};
  register_header_check(0, hdf_header, sizeof(hdf_header), &header_check_hdf, file_stat);
}
#endif
