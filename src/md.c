/*

    File: md.c

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
#include "md.h"
#include "fnctdsk.h"
#include "log.h"

int check_MD(disk_t *disk_car, partition_t *partition, const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(MD_SB_BYTES);
  log_info("check_MD\n");
  /* MD version 1.1 */
  if(disk_car->read(disk_car,MD_SB_BYTES, buffer, partition->part_offset)==0)
  {
    const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)buffer;
    if(le32(sb1->major_version)==1 &&
        le64(sb1->super_offset)==0 &&
        test_MD(disk_car,(struct mdp_superblock_s*)buffer,partition,verbose,0)==0)
    {
      log_info("check_MD 1.1\n");
      set_MD_info(disk_car,(struct mdp_superblock_s*)buffer,partition,verbose,0);
      free(buffer);
      return 0;
    }
  }
  /* MD version 1.2 */
  if(disk_car->read(disk_car,MD_SB_BYTES, buffer, partition->part_offset+4096)==0)
  {
    const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)buffer;
    if(le32(sb1->major_version)==1 &&
        le64(sb1->super_offset)==8 &&
        test_MD(disk_car,(struct mdp_superblock_s*)buffer,partition,verbose,0)==0)
    {
      log_info("check_MD 1.2\n");
      set_MD_info(disk_car,(struct mdp_superblock_s*)buffer,partition,verbose,0);
      free(buffer);
      return 0;
    }
  }
  /* MD version 0.90 */
  {
    const struct mdp_superblock_s *sb=(const struct mdp_superblock_s *)buffer;
    const uint64_t offset=MD_NEW_SIZE_SECTORS(partition->part_size/512)*512;
    if(verbose>1)
    {
      log_verbose("Raid md 0.90 offset %llu\n", (long long unsigned)offset/512);
    }
    if(disk_car->read(disk_car,MD_SB_BYTES, buffer, partition->part_offset+offset)==0)
    {
      if(le32(sb->major_version)==0 &&
          test_MD(disk_car,(struct mdp_superblock_s*)buffer,partition,verbose,0)==0)
      {
        log_info("check_MD 0.90\n");
        set_MD_info(disk_car,(struct mdp_superblock_s*)buffer,partition,verbose,0);
        free(buffer);
        return 0;
      }
    }
  }
  /* MD version 1.0 */
  if(partition->part_size > 8*2*512)
  {
    const uint64_t offset=(uint64_t)(((partition->part_size/512)-8*2) & ~(4*2-1))*512;
    if(verbose>1)
    {
      log_verbose("Raid md 1.0 offset %llu\n", (long long unsigned)offset/512);
    }
    if(disk_car->read(disk_car,MD_SB_BYTES, buffer, partition->part_offset+offset)==0)
    {
      const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)buffer;
      if(le32(sb1->major_version)==1 &&
          le64(sb1->super_offset)==(offset/512) &&
          test_MD(disk_car,(struct mdp_superblock_s*)buffer,partition,verbose,0)==0)
      {
        log_info("check_MD 1.0\n");
        set_MD_info(disk_car,(struct mdp_superblock_s*)buffer,partition,verbose,0);
        free(buffer);
        return 0;
      }
    }
  }
  free(buffer);
  log_info("check_MD end\n");
  return 1;
}

int recover_MD_from_partition(disk_t *disk_car, partition_t *partition, const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(MD_SB_BYTES);
  /* MD version 0.90 */
  {
    uint64_t offset=MD_NEW_SIZE_SECTORS(partition->part_size/512)*512;
    if(disk_car->read(disk_car,MD_SB_BYTES, buffer, partition->part_offset+offset)==0)
    {
      if(recover_MD(disk_car,(struct mdp_superblock_s*)buffer,partition,verbose,0)==0)
      {
        free(buffer);
        return 0;
      }
    }
  }
  /* MD version 1.0 */
  if(partition->part_size > 8*2*512)
  {
    uint64_t offset=(((partition->part_size/512)-8*2) & ~(4*2-1))*512;
    if(disk_car->read(disk_car,MD_SB_BYTES, buffer, partition->part_offset+offset)==0)
    {
      const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)buffer;
      if(le32(sb1->major_version)==1 &&
          recover_MD(disk_car,(struct mdp_superblock_s*)buffer,partition,verbose,0)==0)
      {
        partition->part_offset-=le64(sb1->super_offset)*512-offset;
        free(buffer);
        return 0;
      }
    }
  }
  /* md 1.1 & 1.2 don't need special operation to be recovered */
  free(buffer);
  return 1;
}

int recover_MD(disk_t *disk_car, const struct mdp_superblock_s *sb, partition_t *partition, const int verbose, const int dump_ind)
{
  if(test_MD(disk_car,sb,partition,verbose,dump_ind)!=0)
    return 1;
  set_MD_info(disk_car,sb,partition,verbose,dump_ind);
  partition->part_type_i386=P_RAID;
  partition->part_type_sun=PSUN_RAID;
  partition->part_type_gpt=GPT_ENT_TYPE_LINUX_RAID;
  if(le32(sb->major_version)==0)
  {
    partition->part_size=(uint64_t)(le32(sb->size)<<1)*disk_car->sector_size+MD_RESERVED_BYTES;
    memcpy(&partition->part_uuid, &sb->set_uuid0, 4);
    memcpy(&partition->part_uuid+4, &sb->set_uuid1, 3*4);
  }
  else
  {
    const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)sb;
    partition->part_size=(uint64_t)le64(sb1->size) * (uint64_t)disk_car->sector_size+4096;
    memcpy(&partition->part_uuid, &sb1->set_uuid, 16);
  }
  return 0;
}

int set_MD_info(disk_t *disk_car, const struct mdp_superblock_s *sb, partition_t *partition, const int verbose, const int dump_ind)
{
  unsigned int i,d;
  if(le32(sb->major_version)==0)
  {
    sprintf(partition->fsname,"md%u",(unsigned int)le32(sb->md_minor));
    sprintf(partition->info,"md %u.%u.%u Raid %u: devices",
        (unsigned int)le32(sb->major_version),
        (unsigned int)le32(sb->minor_version),
        (unsigned int)le32(sb->patch_version),
        (unsigned int)le32(sb->level));
    for(i=0;i<MD_SB_DISKS;i++)
    {
      if(sb->disks[i].major!=0 && sb->disks[i].minor!=0)
      {
        if(strlen(partition->info)<sizeof(partition->info)-26)
        { 
          sprintf(&partition->info[strlen(partition->info)]," %u(%u,%u)",
              (unsigned int)sb->disks[i].number,
              (unsigned int)sb->disks[i].major,(unsigned int)sb->disks[i].minor);
          if(sb->disks[i].major==sb->this_disk.major && sb->disks[i].minor==sb->this_disk.minor)
            sprintf(&partition->info[strlen(partition->info)],"*");
        }
      }
    }
  }
  else
  {
    const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)sb;
    set_part_name(partition,sb1->set_name,32);
    sprintf(partition->info,"md %u.x Raid %u - Array Slot : %d (",
	(unsigned int)le32(sb1->major_version),
	(unsigned int)le32(sb1->level),
	le32(sb1->dev_number));
    for (i= le32(sb1->max_dev); i> 0 ; i--)
      if (le16(sb1->dev_roles[i-1]) != 0xffff)
	break;
    for (d=0; d < i; d++)
    {
      int role = le16(sb1->dev_roles[d]);
      if (d)
	strcat(partition->info, ", ");
      if (role == 0xffff)
	strcat(partition->info, "empty");
      else if(role == 0xfffe)
	strcat(partition->info, "failed");
      else
	sprintf(&partition->info[strlen(partition->info)], "%d", role);
    }
    strcat(partition->info, ")");
  }
  if(verbose>0)
    log_info("%s %s\n", partition->fsname, partition->info);
  return 0;
}

int test_MD(disk_t *disk_car, const struct mdp_superblock_s *sb,partition_t *partition,const int verbose, const int dump_ind)
{
  if(le32(sb->md_magic)==(unsigned int)MD_SB_MAGIC)
  {
    log_info("\nRaid magic value at %u/%u/%u\n",
        offset2cylinder(disk_car,partition->part_offset),
        offset2head(disk_car,partition->part_offset),
        offset2sector(disk_car,partition->part_offset));
    log_info("Raid apparent size: %llu sectors\n",(long long unsigned)(sb->size<<1));
    if(le32(sb->major_version)==0)
    {
      log_info("Raid chunk size: %llu bytes\n",(long long unsigned)le32(sb->chunk_size));
      /* chunk_size may be 0 */
      partition->upart_type=UP_MD;
    }
    else if(le32(sb->major_version)==1)
    {
      partition->upart_type=UP_MD1;
    }
    else
      return 1;
    if(dump_ind!=0)
    {
      /* There is a little offset ... */
      dump_log(sb,DEFAULT_SECTOR_SIZE);
    }
    return 0;
  }
  return 1;
}
