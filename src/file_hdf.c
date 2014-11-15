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

static void register_header_check_hdf(file_stat_t *file_stat);

const file_hint_t file_hint_hdf= {
  .extension="hdf",
  .description="Hierarchical Data Format 4",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_SIZE_32,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_hdf
};

struct ddh_struct
{
  uint16_t	size;
  uint32_t	next;
} __attribute__ ((__packed__));

struct dd_struct
{
  uint16_t	tag;
  uint16_t	ref;
  uint32_t	offset;
  uint32_t	length;
} __attribute__ ((__packed__));

static void file_check_hdf(file_recovery_t *file_recovery)
{
  uint64_t file_size=0;
  unsigned int offset_old=4;
  unsigned int offset=4;
  struct dd_struct *dd=(struct dd_struct *)MALLOC(sizeof(struct dd_struct)*65536);
  do
  {
    struct ddh_struct ddh;
    const struct dd_struct *p;
    unsigned int i;
    unsigned int size;
    if(
#ifdef HAVE_FSEEKO
	fseeko(file_recovery->handle, offset, SEEK_SET) < 0 ||
#else
	fseek(file_recovery->handle, offset, SEEK_SET) < 0 ||
#endif
	fread(&ddh, sizeof(ddh), 1, file_recovery->handle) !=1 ||
	be16(ddh.size)==0 ||
	fread(dd, sizeof(struct dd_struct)*be16(ddh.size), 1, file_recovery->handle) !=1)
    {
      free(dd);
      file_recovery->file_size=0;
      return ;
    }
    if(file_size < offset + sizeof(struct dd_struct) * be16(ddh.size))
      file_size = offset + sizeof(struct dd_struct) * be16(ddh.size);
#ifdef DEBUG_HDF
    log_info("size=%u next=%lu\n", be16(ddh.size), be32(ddh.next));
#endif
    size=be16(ddh.size);
    for(i=0, p=dd; i < size; i++,p++)
    {
#ifdef DEBUG_HDF
      log_info("tag=0x%04x, ref=%u, offset=%lu, length=%lu\n",
	  be16(p->tag), be16(p->ref), be32(p->offset), be32(p->length));
#endif
      if((unsigned)be32(p->offset)!=(unsigned)(-1) &&
	file_size < (unsigned)be32(p->offset) + (unsigned)be32(p->length))
	file_size = (unsigned)be32(p->offset) + (unsigned)be32(p->length);
    }
    offset_old=offset;
    offset=be32(ddh.next);
  } while(offset > offset_old);
  free(dd);
  file_size++;
#ifdef DEBUG_HDF
  log_info("file_size %llu\n", (long long unsigned)file_size);
#endif
  if(file_recovery->file_size < file_size)
    file_recovery->file_size=0;
  else
    file_recovery->file_size = file_size;
}

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
