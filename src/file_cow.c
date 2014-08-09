/*

    File: file_cow.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_cow(file_stat_t *file_stat);

const file_hint_t file_hint_cow= {
  .extension="cow",
  .description="Qemu Image",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_cow
};

/* QEMU, open source processor emulator, can be downloaded from http://www.qemu.org/ */

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t backing_file_offset;
    uint32_t backing_file_size;
    uint32_t mtime;
    uint64_t size; /* in bytes */
    uint8_t cluster_bits;
    uint8_t l2_bits;
    uint32_t crypt_method;
    uint64_t l1_table_offset;
} __attribute__ ((__packed__)) QCowHeader_t;

typedef struct QCowHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t backing_file_offset;
    uint32_t backing_file_size;
    uint32_t cluster_bits;
    uint64_t size; /* in bytes */
    uint32_t crypt_method;
    uint32_t l1_size; /* XXX: save number of clusters instead ? */
    uint64_t l1_table_offset;
    uint64_t refcount_table_offset;
    uint32_t refcount_table_clusters;
    uint32_t nb_snapshots;
    uint64_t snapshots_offset;
} QCowHeader2_t;

static int header_check_qcow1(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const QCowHeader_t *header=(const QCowHeader_t*)buffer;
  uint64_t min_size=le64(header->backing_file_offset);
  if(min_size < be64(header->l1_table_offset))
    min_size=be64(header->l1_table_offset);
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_cow.extension;
  file_recovery_new->time=be32(header->mtime);
  file_recovery_new->min_filesize=min_size;
  return 1;
}

static int header_check_qcow2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const QCowHeader2_t *header=(const QCowHeader2_t*)buffer;
  uint64_t min_size=be64(header->backing_file_offset);
  if(min_size < be64(header->l1_table_offset))
    min_size=be64(header->l1_table_offset);
  else if(min_size < be64(header->refcount_table_offset))
    min_size=be64(header->refcount_table_offset);
  else if(min_size < be64(header->snapshots_offset))
    min_size=be64(header->snapshots_offset);
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_cow.extension;
  file_recovery_new->min_filesize=min_size;
#ifdef DEBUG_COW
  log_info("magic %lu\n", 			be32(header->magic));
  log_info("version %lu\n",     		be32(header->version));
  log_info("backing_file_offset %llu\n",     	be64(header->backing_file_offset));
  log_info("backing_file_size %lu\n",     	be32(header->backing_file_size));
  log_info("cluster_bits %lu\n",     		be32(header->cluster_bits));
  log_info("size %llu\n",     		be64(header->size)); /* in bytes */
  log_info("crypt_method %lu\n",     		be32(header->crypt_method));
  log_info("l1_size %lu\n",     		be32(header->l1_size)); /* XXX: save number of clusters instead ? */
  log_info("l1_table_offset %llu\n",     	be64(header->l1_table_offset));
  log_info("refcount_table_offset %llu\n",    be64(header->refcount_table_offset));
  log_info("refcount_table_clusters %lu\n",   be32(header->refcount_table_clusters));
  log_info("nb_snapshots %lu\n",     		be32(header->nb_snapshots));
  log_info("snapshots_offset %llu\n",     	be64(header->snapshots_offset));
#endif
  return 1;
}

static void register_header_check_cow(file_stat_t *file_stat)
{
  static const unsigned char cow_header[8]=  {'Q', 'F', 'I', 0xfb, 0x0, 0x0, 0x0, 0x1};
  static const unsigned char cow_header2[8]= {'Q', 'F', 'I', 0xfb, 0x0, 0x0, 0x0, 0x2};
  register_header_check(0, cow_header,sizeof(cow_header), &header_check_qcow1, file_stat);
  register_header_check(0, cow_header2,sizeof(cow_header2), &header_check_qcow2, file_stat);
}
