/*

    File: sysv.c

    Copyright (C) 2004-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
 
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "sysv.h"
#include "fnctdsk.h"
#include "log.h"

#define SYSV4_SECTOR_SIZE 512
#define SYSV4_SBLOCK 8192
#define SYSV4_MAGIC 0x00011954
#define SYSV4_CIGAM 0x54190100 /* byteswapped MAGIC */


/* HP specific MAGIC values */

#define SYSV4_MAGIC_LFN   0x00095014 /* fs supports filenames > 14 chars */
#define SYSV4_CIGAM_LFN   0x14500900 /* srahc 41 < semanelif stroppus sf */

#define SYSV4_MAGIC_SEC   0x00612195 /* B1 security fs */
#define SYSV4_CIGAM_SEC   0x95216100

#define SYSV4_MAGIC_FEA   0x00195612 /* fs_featurebits supported */
#define SYSV4_CIGAM_FEA   0x12561900

#define SYSV4_MAGIC_4GB   0x05231994 /* fs > 4 GB && fs_featurebits */
#define SYSV4_CIGAM_4GB   0x94192305


static void set_sysv4_info(const struct sysv4_super_block *sbd, partition_t *partition);
static int test_sysv4(const disk_t *disk_car, const struct sysv4_super_block *sbd, const partition_t *partition, const int verbose);

int check_sysv(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(SYSV4_SECTOR_SIZE);
  if(disk_car->pread(disk_car, buffer, SYSV4_SECTOR_SIZE, partition->part_offset + 0x200) != SYSV4_SECTOR_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_sysv4(disk_car, (const struct sysv4_super_block *)buffer, partition, verbose)==0)
  {
    set_sysv4_info((const struct sysv4_super_block *)buffer, partition);
    free(buffer);
    return 0;
  }
  free(buffer);
  return 1;
}

static int test_sysv4(const disk_t *disk_car, const struct sysv4_super_block *sbd, const partition_t *partition, const int verbose)
{
  if (sbd->s_magic != (signed)le32(0xfd187e20) && sbd->s_magic != (signed)be32(0xfd187e20))
    return 1;
  if(verbose>0)
    log_info("\nSYSV4 Marker at %u/%u/%u\n",
        offset2cylinder(disk_car,partition->part_offset),
        offset2head(disk_car,partition->part_offset),
        offset2sector(disk_car,partition->part_offset));
  return 0;
}

int recover_sysv(disk_t *disk_car,  const struct sysv4_super_block *sbd, partition_t *partition,const int verbose, const int dump_ind)
{
  if(test_sysv4(disk_car, sbd,partition, verbose)!=0)
    return 1;
  if(verbose>0 || dump_ind!=0)
  {
    log_info("\nrecover_sysv4\n");
    if(dump_ind!=0)
    {
      dump_log(sbd,sizeof(*sbd));
    }
  }
  switch(sbd->s_magic)
  {
    case le32(0xfd187e20):
      partition->part_size = (uint64_t)le32(sbd->s_fsize)*(512<<(le32(sbd->s_type)-1));
      break;
    case be32(0xfd187e20):
      partition->part_size = (uint64_t)be32(sbd->s_fsize)*(512<<(be32(sbd->s_type)-1));
      break;
  }
  set_sysv4_info(sbd, partition);
  partition->part_type_i386 = P_SYSV;
  return 0;
}

static void set_sysv4_info(const struct sysv4_super_block *sbd, partition_t *partition)
{
  partition->upart_type = UP_SYSV4;
  strncpy(partition->info,"SysV4",sizeof(partition->info));
  set_part_name(partition,sbd->s_fname,sizeof(sbd->s_fname));
}
