/*

    File: bsd.c

    Copyright (C) 1998-2006,2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
 
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "bsd.h"
#include "intrf.h"
#include "log.h"
static int test_BSD(disk_t *disk_car, const struct disklabel*bsd_header, const partition_t *partition, const int verbose, const int dump_ind, const unsigned int max_partitions);

int check_BSD(disk_t *disk_car,partition_t *partition,const int verbose, const unsigned int max_partitions)
{
  unsigned char *buffer;
  buffer=(unsigned char*)MALLOC(BSD_DISKLABEL_SIZE);
  if(disk_car->pread(disk_car, buffer, BSD_DISKLABEL_SIZE, partition->part_offset + 0x200) != BSD_DISKLABEL_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_BSD(disk_car,(const struct disklabel*)buffer,partition,verbose,0,max_partitions))
  {
    free(buffer);
    return 1;
  }
  set_part_name(partition,((const struct disklabel*)buffer)->d_packname,16);
  free(buffer);
  return 0;
}

static int test_BSD(disk_t *disk_car, const struct disklabel*bsd_header, const partition_t *partition,const int verbose, const int dump_ind, const unsigned int max_partitions)
{
  unsigned int i;
  const uint16_t* cp;
  uint16_t crc;
  if(le32(bsd_header->d_magic) != DISKMAGIC || le32(bsd_header->d_magic2)!=DISKMAGIC)
    return 0;
  if(verbose)
    log_info("\nBSD offset %lu, nbr_part %u, CHS=(%u,%u,%u) ",
	(long unsigned)(partition->part_offset/disk_car->sector_size),
	(unsigned int)le16(bsd_header->d_npartitions),
	(unsigned int)le32(bsd_header->d_ncylinders),
	(unsigned int)le32(bsd_header->d_ntracks),
	(unsigned int)le32(bsd_header->d_nsectors));
  if(le16(bsd_header->d_npartitions) > max_partitions)
    return 1;
  crc=0;
  for(cp=(const uint16_t*)bsd_header;
      cp<(const uint16_t*)&bsd_header->d_partitions[le16(bsd_header->d_npartitions)];cp++)
    crc^=*cp;
  if(crc==0)
  {
    if(verbose>0)
    {
      log_info("CRC Ok\n");
    }
  }
  else
    log_error("Bad CRC! CRC must be xor'd by %04X\n",crc);
  for(i=0;i<le16(bsd_header->d_npartitions);i++)
  {
    if(bsd_header->d_partitions[i].p_fstype>0)
    {
      if(verbose>0)
      {
	/* UFS UFS2 SWAP */
	log_info("BSD %c: ", 'a'+i);
	switch(bsd_header->d_partitions[i].p_fstype)
	{
	  case TST_FS_SWAP:
	    log_info("swap");
	    break;
	  case TST_FS_BSDFFS:
	    log_info("4.2BSD fast filesystem");
	    break;
	  case TST_FS_BSDLFS:
	    log_info("4.4BSD log-structured filesystem");
	    break;
	  default:
	    log_info("type %02X", bsd_header->d_partitions[i].p_fstype);
	    break;
	}
	log_info(", offset %9u, size %9u ",
	    (unsigned int)le32(bsd_header->d_partitions[i].p_offset),
	    (unsigned int)le32(bsd_header->d_partitions[i].p_size));
	log_CHS_from_LBA(disk_car,le32(bsd_header->d_partitions[i].p_offset));
	log_info(" -> ");
	log_CHS_from_LBA(disk_car,le32(bsd_header->d_partitions[i].p_offset)+le32(bsd_header->d_partitions[i].p_size)-1);
	log_info("\n");
      }
    }
  }
  if(crc)
    return 1;
  if(dump_ind!=0)
  {
    dump_log(bsd_header,DEFAULT_SECTOR_SIZE);
  }
  return 0;
}

int recover_BSD(disk_t *disk_car, const struct disklabel*bsd_header,partition_t *partition,const int verbose, const int dump_ind)
{
  int i;
  int i_max_p_offset=-1;
  if(test_BSD(disk_car,bsd_header,partition,verbose,dump_ind,BSD_MAXPARTITIONS)==0)
  {
    partition->upart_type=UP_FREEBSD;
    for(i=0;i<BSD_MAXPARTITIONS;i++)
    {
      if(bsd_header->d_partitions[i].p_fstype>0)
      {
	if(i_max_p_offset==-1 || le32(bsd_header->d_partitions[i].p_offset)>le32(bsd_header->d_partitions[i_max_p_offset].p_offset))
	  i_max_p_offset=i;
      }
    }
    if(i_max_p_offset>=0)
      partition->part_size=(uint64_t)(le32(bsd_header->d_partitions[i_max_p_offset].p_size) +
	  le32(bsd_header->d_partitions[i_max_p_offset].p_offset) - 1) * disk_car->sector_size - partition->part_offset;
    else
      partition->part_size=0;
    partition->part_type_i386=P_FREEBSD;
    set_part_name(partition,bsd_header->d_packname,16);
    partition->info[0]='\0';
    return 0;
  }
  if(test_BSD(disk_car,bsd_header,partition,verbose,dump_ind,OPENBSD_MAXPARTITIONS)==0)
  {
    partition->upart_type=UP_OPENBSD;
    for(i=0;i<OPENBSD_MAXPARTITIONS;i++)
    {
      if(bsd_header->d_partitions[i].p_fstype>0)
      {
	if(i_max_p_offset==-1 || le32(bsd_header->d_partitions[i].p_offset)>le32(bsd_header->d_partitions[i_max_p_offset].p_offset))
	  i_max_p_offset=i;
      }
    }
    if(i_max_p_offset>=0)
      partition->part_size=(uint64_t)(le32(bsd_header->d_partitions[i_max_p_offset].p_size) +
	  le32(bsd_header->d_partitions[i_max_p_offset].p_offset) - 1) * disk_car->sector_size - partition->part_offset;
    else
      partition->part_size=0;
    partition->part_type_i386=P_OPENBSD;
    set_part_name(partition,bsd_header->d_packname,16);
    partition->info[0]='\0';
    return 0;
  }
  return 1;
}
