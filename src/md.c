/*

    File: md.c

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
static int test_MD(disk_t *disk_car, const struct mdp_superblock_s *sb, const partition_t *partition, const int dump_ind);
static int test_MD_be(disk_t *disk_car, const struct mdp_superblock_s *sb, const partition_t *partition, const int dump_ind);
static void set_MD_info(const struct mdp_superblock_s *sb, partition_t *partition, const int verbose);
static void set_MD_info_be(const struct mdp_superblock_s *sb, partition_t *partition, const int verbose);

int check_MD(disk_t *disk_car, partition_t *partition, const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(MD_SB_BYTES);
  /* MD version 1.1 */
  if(disk_car->pread(disk_car, buffer, MD_SB_BYTES, partition->part_offset) == MD_SB_BYTES)
  {
    const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)buffer;
    if(le32(sb1->md_magic)==(unsigned int)MD_SB_MAGIC &&
	le32(sb1->major_version)==1 &&
	le64(sb1->super_offset)==0 &&
	test_MD(disk_car, (struct mdp_superblock_s*)buffer, partition, 0)==0)
    {
      log_info("check_MD 1.1\n");
      set_MD_info((struct mdp_superblock_s*)buffer, partition, verbose);
      free(buffer);
      return 0;
    }
    if(be32(sb1->md_magic)==(unsigned int)MD_SB_MAGIC &&
	 be32(sb1->major_version)==1 &&
	 be64(sb1->super_offset)==0 &&
        test_MD_be(disk_car, (struct mdp_superblock_s*)buffer, partition, 0)==0)
    {
      log_info("check_MD 1.1 (BigEndian)\n");
      set_MD_info_be((struct mdp_superblock_s*)buffer, partition, verbose);
      free(buffer);
      return 0;
    }
  }
  /* MD version 1.2 */
  if(disk_car->pread(disk_car, buffer, MD_SB_BYTES, partition->part_offset + 4096) == MD_SB_BYTES)
  {
    const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)buffer;
    if(le32(sb1->md_magic)==(unsigned int)MD_SB_MAGIC &&
	le32(sb1->major_version)==1 &&
        le64(sb1->super_offset)==8 &&
        test_MD(disk_car, (struct mdp_superblock_s*)buffer, partition, 0)==0)
    {
      log_info("check_MD 1.2\n");
      set_MD_info((struct mdp_superblock_s*)buffer, partition, verbose);
      free(buffer);
      return 0;
    }
    if(be32(sb1->md_magic)==(unsigned int)MD_SB_MAGIC &&
	be32(sb1->major_version)==1 &&
        be64(sb1->super_offset)==8 &&
        test_MD_be(disk_car, (struct mdp_superblock_s*)buffer, partition, 0)==0)
    {
      log_info("check_MD 1.2 (BigEndian)\n");
      set_MD_info_be((struct mdp_superblock_s*)buffer, partition, verbose);
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
    if(disk_car->pread(disk_car, buffer, MD_SB_BYTES, partition->part_offset + offset) == MD_SB_BYTES)
    {
      if(le32(sb->md_magic)==(unsigned int)MD_SB_MAGIC &&
	  le32(sb->major_version)==0 &&
	  test_MD(disk_car, (struct mdp_superblock_s*)buffer, partition, 0)==0)
      {
        log_info("check_MD 0.90\n");
        set_MD_info((struct mdp_superblock_s*)buffer, partition, verbose);
        free(buffer);
        return 0;
      }
      if(be32(sb->md_magic)==(unsigned int)MD_SB_MAGIC &&
	  be32(sb->major_version)==0 &&
	  test_MD_be(disk_car, (struct mdp_superblock_s*)buffer, partition, 0)==0)
      {
        log_info("check_MD 0.90 (BigEndian)\n");
        set_MD_info_be((struct mdp_superblock_s*)buffer, partition, verbose);
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
    if(disk_car->pread(disk_car, buffer, MD_SB_BYTES, partition->part_offset + offset) == MD_SB_BYTES)
    {
      const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)buffer;
      if(le32(sb1->md_magic)==(unsigned int)MD_SB_MAGIC &&
	  le32(sb1->major_version)==1 &&
          le64(sb1->super_offset)==(offset/512) &&
          test_MD(disk_car, (struct mdp_superblock_s*)buffer, partition, 0)==0)
      {
        log_info("check_MD 1.0\n");
        set_MD_info((struct mdp_superblock_s*)buffer, partition, verbose);
        free(buffer);
        return 0;
      }
      if(be32(sb1->md_magic)==(unsigned int)MD_SB_MAGIC &&
	  be32(sb1->major_version)==1 &&
          be64(sb1->super_offset)==(offset/512) &&
          test_MD_be(disk_car, (struct mdp_superblock_s*)buffer, partition, 0)==0)
      {
        log_info("check_MD 1.0 (BigEndian)\n");
        set_MD_info_be((struct mdp_superblock_s*)buffer, partition, verbose);
        free(buffer);
        return 0;
      }
    }
  }
  free(buffer);
  return 1;
}

int recover_MD_from_partition(disk_t *disk_car, partition_t *partition, const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(MD_SB_BYTES);
  /* MD version 0.90 */
  {
    uint64_t offset=MD_NEW_SIZE_SECTORS(partition->part_size/512)*512;
    if(disk_car->pread(disk_car, buffer, MD_SB_BYTES, partition->part_offset + offset) == MD_SB_BYTES)
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
    if(disk_car->pread(disk_car, buffer, MD_SB_BYTES, partition->part_offset + offset) == MD_SB_BYTES)
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
  if(test_MD(disk_car, sb, partition, dump_ind)==0)
  {
    set_MD_info(sb, partition, verbose);
    partition->part_type_i386=P_RAID;
    partition->part_type_sun=PSUN_RAID;
    partition->part_type_gpt=GPT_ENT_TYPE_LINUX_RAID;
    if(le32(sb->major_version)==0)
    {
      partition->part_size=(uint64_t)(le32(sb->size)<<1)*512+MD_RESERVED_BYTES;	/* 512-byte sectors */
      memcpy(&partition->part_uuid, &sb->set_uuid0, 4);
      memcpy((char*)(&partition->part_uuid)+4, &sb->set_uuid1, 3*4);
    }
    else
    {
      const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)sb;
      partition->part_size=(uint64_t)le64(sb1->size) * 512 + 4096;	/* 512-byte sectors */
      memcpy(&partition->part_uuid, &sb1->set_uuid, 16);
    }
    return 0;
  }
  if(test_MD_be(disk_car, sb, partition, dump_ind)==0)
  {
    set_MD_info_be(sb, partition, verbose);
    partition->part_type_i386=P_RAID;
    partition->part_type_sun=PSUN_RAID;
    partition->part_type_gpt=GPT_ENT_TYPE_LINUX_RAID;
    if(be32(sb->major_version)==0)
    {
      partition->part_size=(uint64_t)(be32(sb->size)<<1)*512+MD_RESERVED_BYTES;	/* 512-byte sectors */
      memcpy(&partition->part_uuid, &sb->set_uuid0, 4);
      memcpy((char*)(&partition->part_uuid)+4, &sb->set_uuid1, 3*4);
    }
    else
    {
      const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)sb;
      partition->part_size=(uint64_t)be64(sb1->size) * 512 + 4096;	/* 512-byte sectors */
      memcpy(&partition->part_uuid, &sb1->set_uuid, 16);
    }
    return 0;
  }
  return 1;
}

static void set_MD_info(const struct mdp_superblock_s *sb, partition_t *partition, const int verbose)
{
  if(le32(sb->major_version)==0)
  {
    unsigned int i;
    partition->upart_type=UP_MD;
    sprintf(partition->fsname,"md%u",(unsigned int)le32(sb->md_minor));
    sprintf(partition->info,"md %u.%u.%u L.Endian Raid %u: devices",
        (unsigned int)le32(sb->major_version),
        (unsigned int)le32(sb->minor_version),
        (unsigned int)le32(sb->patch_version),
        (unsigned int)le32(sb->level));
    for(i=0;i<MD_SB_DISKS;i++)
    {
      if(le32(sb->disks[i].major)!=0 && le32(sb->disks[i].minor)!=0)
      {
        if(strlen(partition->info)<sizeof(partition->info)-26)
        {
          sprintf(&partition->info[strlen(partition->info)]," %u(%u,%u)",
              (unsigned int)le32(sb->disks[i].number),
              (unsigned int)le32(sb->disks[i].major),
	      (unsigned int)le32(sb->disks[i].minor));
          if(le32(sb->disks[i].major)==le32(sb->this_disk.major) &&
	    le32(sb->disks[i].minor)==le32(sb->this_disk.minor))
            sprintf(&partition->info[strlen(partition->info)],"*");
        }
      }
    }
  }
  else
  {
    const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)sb;
    partition->upart_type=UP_MD1;
    set_part_name(partition,sb1->set_name,32);
    sprintf(partition->info,"md %u.x L.Endian Raid %u - Array Slot : %lu",
	(unsigned int)le32(sb1->major_version),
	(unsigned int)le32(sb1->level),
	(long unsigned)le32(sb1->dev_number));
    if(le32(sb1->max_dev) <= 384)
    {
      unsigned int i,d;
      for (i= le32(sb1->max_dev); i> 0 ; i--)
	if (le16(sb1->dev_roles[i-1]) != 0xffff)
	  break;
      strcat(partition->info, " (");
      for (d=0; d < i && strlen(partition->info) < sizeof(partition->info) - 9; d++)
      {
	const int role = le16(sb1->dev_roles[d]);
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
  }
  if(verbose>0)
    log_info("%s %s\n", partition->fsname, partition->info);
}

static void set_MD_info_be(const struct mdp_superblock_s *sb, partition_t *partition, const int verbose)
{
  if(be32(sb->major_version)==0)
  {
    unsigned int i;
    partition->upart_type=UP_MD;
    sprintf(partition->fsname,"md%u",(unsigned int)be32(sb->md_minor));
    sprintf(partition->info,"md %u.%u.%u B.Endian Raid %u: devices",
        (unsigned int)be32(sb->major_version),
        (unsigned int)be32(sb->minor_version),
        (unsigned int)be32(sb->patch_version),
        (unsigned int)be32(sb->level));
    for(i=0;i<MD_SB_DISKS;i++)
    {
      if(be32(sb->disks[i].major)!=0 && be32(sb->disks[i].minor)!=0)
      {
        if(strlen(partition->info)<sizeof(partition->info)-26)
        {
          sprintf(&partition->info[strlen(partition->info)]," %u(%u,%u)",
              (unsigned int)be32(sb->disks[i].number),
              (unsigned int)be32(sb->disks[i].major),
	      (unsigned int)be32(sb->disks[i].minor));
          if(be32(sb->disks[i].major)==be32(sb->this_disk.major) &&
	      be32(sb->disks[i].minor)==be32(sb->this_disk.minor))
            sprintf(&partition->info[strlen(partition->info)],"*");
        }
      }
    }
  }
  else
  {
    const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)sb;
    partition->upart_type=UP_MD1;
    set_part_name(partition,sb1->set_name,32);
    sprintf(partition->info,"md %u.x B.Endian Raid %u - Array Slot : %lu",
	(unsigned int)be32(sb1->major_version),
	(unsigned int)be32(sb1->level),
	(long unsigned)be32(sb1->dev_number));
    if(be32(sb1->max_dev) <= 384)
    {
      unsigned int i,d;
      for (i= be32(sb1->max_dev); i> 0 ; i--)
	if (be16(sb1->dev_roles[i-1]) != 0xffff)
	  break;
      strcat(partition->info, " (");
      for (d=0; d < i && strlen(partition->info) < sizeof(partition->info) - 9; d++)
      {
	const int role = be16(sb1->dev_roles[d]);
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
  }
  if(verbose>0)
    log_info("%s %s\n", partition->fsname, partition->info);
}

static int test_MD(disk_t *disk_car, const struct mdp_superblock_s *sb, const partition_t *partition, const int dump_ind)
{
  if(le32(sb->md_magic)!=(unsigned int)MD_SB_MAGIC)
    return 1;
  log_info("\nRaid magic value at %u/%u/%u\n",
      offset2cylinder(disk_car,partition->part_offset),
      offset2head(disk_car,partition->part_offset),
      offset2sector(disk_car,partition->part_offset));
  log_info("Raid apparent size: %llu sectors\n", (long long unsigned)(sb->size<<1));
  if(le32(sb->major_version)==0)
  {
    /* chunk_size may be 0 */
    log_info("Raid chunk size: %llu bytes\n", (long long unsigned)le32(sb->chunk_size));
  }
  if(le32(sb->major_version)>1)
    return 1;
  if(dump_ind!=0)
  {
    /* There is a little offset ... */
    dump_log(sb,DEFAULT_SECTOR_SIZE);
  }
  return 0;
}

static int test_MD_be(disk_t *disk_car, const struct mdp_superblock_s *sb, const partition_t *partition, const int dump_ind)
{
  if(be32(sb->md_magic)!=(unsigned int)MD_SB_MAGIC)
    return 1;
  log_info("\nRaid magic value at %u/%u/%u\n",
      offset2cylinder(disk_car,partition->part_offset),
      offset2head(disk_car,partition->part_offset),
      offset2sector(disk_car,partition->part_offset));
  log_info("Raid apparent size: %llu sectors\n", (long long unsigned)(sb->size<<1));
  if(be32(sb->major_version)==0)
  {
    /* chunk_size may be 0 */
    log_info("Raid chunk size: %llu bytes\n",(long long unsigned)be32(sb->chunk_size));
  }
  if(be32(sb->major_version)>1)
    return 1;
  if(dump_ind!=0)
  {
    /* There is a little offset ... */
    dump_log(sb,DEFAULT_SECTOR_SIZE);
  }
  return 0;
}
