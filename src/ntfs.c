/*

    File: ntfs.c

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
/*
#define NTFS_DEBUG 1
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
#include <ctype.h>
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "ntfs.h"
#include "fnctdsk.h"
#include "lang.h"
#include "log.h"
/* #include "guid_cmp.h" */
extern const arch_fnct_t arch_i386;

static int set_NTFS_info(disk_t *disk_car, const struct ntfs_boot_sector*ntfs_header,partition_t *partition,const int verbose);
static int ntfs_read_MFT(disk_t *disk_car, partition_t *partition, const struct ntfs_boot_sector*ntfs_header, const int my_type, const int verbose);
static int ntfs_get_attr_aux(const char *attr_record, const int my_type, partition_t *partition, const char *end, const int verbose, const char*file_name_to_find);

unsigned int ntfs_sector_size(const struct ntfs_boot_sector *ntfs_header)
{ return (ntfs_header->sector_size[1]<<8)+ntfs_header->sector_size[0]; }

int check_NTFS(disk_t *disk_car,partition_t *partition,const int verbose,const int dump_ind)
{
  unsigned char *buffer=(unsigned char*)MALLOC(DEFAULT_SECTOR_SIZE);
/*  log_trace("check_NTFS part_offset=%llu\n",(long long unsigned)partition->part_offset); */
  if(disk_car->pread(disk_car, buffer, DEFAULT_SECTOR_SIZE, partition->part_offset) != DEFAULT_SECTOR_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_NTFS(disk_car,(struct ntfs_boot_sector*)buffer,partition,verbose,dump_ind)!=0)
  {
    free(buffer);
    return 1;
  }
  set_NTFS_info(disk_car, (struct ntfs_boot_sector*)buffer, partition, verbose);
  free(buffer);
  return 0;
}

int recover_NTFS(disk_t *disk_car, const struct ntfs_boot_sector*ntfs_header,partition_t *partition,const int verbose, const int dump_ind, const int backup)
{
  uint64_t part_size;
  if(test_NTFS(disk_car,ntfs_header,partition,verbose,dump_ind)!=0)
    return 1;
  if(verbose>0)
  {
    log_ntfs_info(ntfs_header);
  }
  part_size=(uint64_t)(le64(ntfs_header->sectors_nbr)+1)*ntfs_sector_size(ntfs_header);
  partition->sborg_offset=0;
  partition->sb_size=512;
  if(backup>0)
  {
    if(partition->part_offset+disk_car->sector_size<part_size)
    {
      log_warning("NTFS part_offset=%llu, part_size=%llu, sector_size=%u\n",
	  (long long unsigned)partition->part_offset, (long long unsigned)part_size,
	  disk_car->sector_size);
      log_warning("NTFS partition cannot be added (part_offset<part_size).\n");
      return 1;
    }
    if(verbose>1)
      log_info("NTFS part_offset=%llu, part_size=%llu, sector_size=%u\n",
	  (long long unsigned)partition->part_offset, (long long unsigned)part_size,
	  disk_car->sector_size);
    partition->sb_offset=part_size-disk_car->sector_size;
    partition->part_offset-=partition->sb_offset;
    if(verbose>1)
      log_info("part_offset=%llu\n",(long long unsigned)partition->part_offset);
  }
  partition->part_size=part_size;
  partition->part_type_i386=P_NTFS;
  partition->part_type_gpt=GPT_ENT_TYPE_MS_BASIC_DATA;
  set_NTFS_info(disk_car, ntfs_header, partition, verbose);
  return 0;
}

static int set_NTFS_info(disk_t *disk_car, const struct ntfs_boot_sector*ntfs_header,partition_t *partition,const int verbose)
{
  partition->fsname[0]='\0';
  partition->blocksize=ntfs_header->sectors_per_cluster*ntfs_sector_size(ntfs_header);
  if(partition->sb_offset==0)
    snprintf(partition->info, sizeof(partition->info), "NTFS, blocksize=%u", partition->blocksize);
  else
    snprintf(partition->info, sizeof(partition->info), "NTFS found using backup sector, blocksize=%u", partition->blocksize);
  return ntfs_read_MFT(disk_car, partition, ntfs_header, 0x60, verbose);
}

int test_NTFS(const disk_t *disk_car,const struct ntfs_boot_sector*ntfs_header, partition_t *partition,const int verbose, const int dump_ind)
{
  if(le16(ntfs_header->marker)!=0xAA55 ||
      le16(ntfs_header->reserved)>0 ||
      ntfs_header->fats>0 ||
      ntfs_header->dir_entries[0]!=0 || ntfs_header->dir_entries[1]!=0 ||
      ntfs_header->sectors[0]!=0 || ntfs_header->sectors[1]!=0 ||
      le16(ntfs_header->fat_length)!=0 || le32(ntfs_header->total_sect)!=0 ||
      memcmp(ntfs_header->system_id,"NTFS",4)!=0 ||
      le64(ntfs_header->sectors_nbr)==0)
    return 1;
  switch(ntfs_header->sectors_per_cluster)
  {
    case 1: case 2: case 4: case 8: case 16: case 32: case 64: case 128:
      break;
    default:
      return 1;
  }
  if(verbose>0 || dump_ind!=0)
  {
    log_info("NTFS at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
  }
  if(le16(ntfs_header->heads)!=disk_car->geom.heads_per_cylinder)
  {
    screen_buffer_add("Warning: number of heads/cylinder mismatches %u (NTFS) != %u (HD)\n",
	le16(ntfs_header->heads), disk_car->geom.heads_per_cylinder);
    log_warning("heads/cylinder %u (NTFS) != %u (HD)\n",
	le16(ntfs_header->heads), disk_car->geom.heads_per_cylinder);
  }
  if(le16(ntfs_header->secs_track)!=disk_car->geom.sectors_per_head)
  {
    screen_buffer_add("Warning: number of sectors per track mismatches %u (NTFS) != %u (HD)\n",
	le16(ntfs_header->secs_track), disk_car->geom.sectors_per_head);
    log_warning("sect/track %u (NTFS) != %u (HD)\n",
	le16(ntfs_header->secs_track), disk_car->geom.sectors_per_head);
  }
  if(ntfs_sector_size(ntfs_header)!=disk_car->sector_size)
  {
    screen_buffer_add("Warning: number of bytes per sector mismatches %u (NTFS) != %u (HD)\n",
	ntfs_sector_size(ntfs_header), disk_car->sector_size);
    log_warning("Warning: number of bytes per sector mismatches %u (NTFS) != %u (HD)\n",
	ntfs_sector_size(ntfs_header), disk_car->sector_size);
  }

  if(partition->part_size>0)
  {
    uint64_t part_size;
    part_size=le64(ntfs_header->sectors_nbr)+1;

    if(part_size*ntfs_sector_size(ntfs_header)>partition->part_size)
    {
      screen_buffer_add("Error: size boot_sector %lu > partition %lu\n",(long unsigned)part_size,(long unsigned)(partition->part_size/disk_car->sector_size));
      log_error("Error: size boot_sector %lu > partition %lu\n",(long unsigned)part_size,(long unsigned)(partition->part_size/disk_car->sector_size));
      return 1;
    }
    if(verbose>0 && (part_size!=partition->part_size/disk_car->sector_size))
    {
      log_info("Info: size boot_sector %lu, partition %lu\n",(long unsigned)part_size,(long unsigned)(partition->part_size/disk_car->sector_size));
    }
  }
  partition->upart_type=UP_NTFS;
  return 0;
}

/* */
int ntfs_get_attr(const char *mft_record, const int my_type, partition_t *partition, const char *end, const int verbose, const char*file_name_to_find)
{
  const char *attr_record;
  /* Only check for magic DWORD here, fixup should have happened before */
  if(memcmp(mft_record,"FILE",4)) return 2;	/* NTFS_RECORD_TYPES == magic_FILE ?*/
  if(NTFS_GETU16(mft_record + 0x14)%8!=0)
    return 2;
  if(NTFS_GETU16(mft_record + 0x14)<42)		/* sizeof(MFT_RECORD)>=42 */
    return 2;
  /*	screen_buffer_add("FILE\n"); */
  /*	screen_buffer_add("seq nbr %lu ",NTFS_GETU16(mft_record+0x10)); */
  /*	screen_buffer_add("main MFT record %lu ",NTFS_GETU64(mft_record+0x20)); */
  /* location of first attribute */
  attr_record= mft_record + NTFS_GETU16(mft_record + 0x14);
  return ntfs_get_attr_aux(attr_record, my_type, partition, end, verbose, file_name_to_find);
}

static int ntfs_get_attr_aux(const char *attr_record, const int my_type, partition_t *partition, const char *end, const int verbose, const char*file_name_to_find)
{
  while(1)
  {
    int attr_type;
    /* Resident attributes attr_len>=24(0x18), non resident is bigger */
    unsigned int attr_len;
    if(attr_record+0x18>=end)
    {
      if(verbose>1)
      {
        log_error("ntfs_get_attr attr_record+0x18>=end\n");
      }
      return 2;
    }
    attr_type=NTFS_GETU32(attr_record);
    if(attr_type==-1) /* attribute list end with type -1 */
      return 0;
    attr_len=NTFS_GETU16(attr_record+4);
    if((attr_len%8!=0)||(attr_len<0x18))
    {
      if(verbose>1)
      {
        log_error("ntfs_get_attr attr_type=%x attr_len=%u (attr_len%%8!0)||(attr_len<0x18)\n",attr_type,attr_len);
      }
      return 2;
    }
    if(verbose>1)
    {
      log_info("attr_type=%x %s\n",attr_type,(NTFS_GETU8(attr_record+8)==0?"resident":"non resident"));
      dump_log(attr_record,attr_len);
    }
    if(NTFS_GETU8(attr_record+8)==0)	/* attribute is resident */
    {
      unsigned int attr_value_length=NTFS_GETU16(attr_record+0x10);
      unsigned int attr_value_offset=NTFS_GETU16(attr_record+0x14);
      const char *attr_td_list_entry=attr_record+attr_value_offset;
      if(attr_value_offset%8!=0)
      {
#ifdef NTFS_DEBUG
        log_debug("ntfs_get_attr attr_value_offset=%u (%%8!=0)\n",attr_value_offset);
#endif
        return 2;
      }
      if(attr_td_list_entry+26>=end)
      {
#ifdef NTFS_DEBUG
        log_debug("ntfs_get_attr attr_td_list_entry+26=%p, end=%p\n",attr_td_list_entry+26,end);
#endif
        return 2;
      }
      /* We found the attribute type. Is the name correct, too? */
      if((attr_value_offset+attr_value_length>attr_len) || (attr_td_list_entry+attr_len >= end))
      {
#ifdef NTFS_DEBUG
        // log_debug("ntfs_get_attr \n");
#endif
        return 2;
      }
      if((attr_type==my_type)&&(attr_value_offset!=0))
      {
        switch(attr_type)
        {
          case 0x30:	/* AT_FILE_NAME */
            {
              const char *file_name_attr=attr_td_list_entry;
              unsigned int file_name_length;
              const char *name_it;
              if(file_name_attr+0x42>=end)
                return 2;
              file_name_length=NTFS_GETU8(file_name_attr+0x40);	/* size in unicode char */
              if(file_name_attr+0x42+2*file_name_length>=end)
                return 2;
              {
                char file_name[256+1];	/* used size is file_name_length+1 */
                unsigned int i;
                /*		screen_buffer_add("MFT record nbr %lu ",NTFS_GETU64(file_name_attr)); */
                for(name_it=file_name_attr+0x42,i=0;i<file_name_length; name_it+=2,i++)
                  file_name[i]=*name_it;
                file_name[i]='\0';
                if(verbose>1)
                {
                  log_verbose("file_name=%s\n",file_name);
                }
                if(file_name_to_find!=NULL)
                {
                  if(attr_type==my_type)
                  {
                    if(strcmp(file_name_to_find,file_name)==0)
                      return 1;
                    else
                      return 2;
                  }
                } else
                  screen_buffer_add("%s\n",file_name);
              }
            }
            break;
          case 0x60:	/* AT_VOLUME_NAME */
            {
              unsigned int volume_name_length=attr_value_length;
              const char *name_it;
              char *dest=partition->fsname;
              volume_name_length/=2;	/* Unicode */
              if(volume_name_length>sizeof(partition->fsname)-1)
                volume_name_length=sizeof(partition->fsname)-1;
              for(name_it=attr_td_list_entry;(volume_name_length>0) && (*name_it!='\0') && (name_it[1]=='\0'); name_it+=2,volume_name_length--)
                *dest++=*name_it;
              *dest='\0'; /* 27 january 2003: Correct a bug found by Andreas du Plessis-Denz */
            }
            return 1;
          case 0x90:	/* AT_INDEX_ROOT */
            return NTFS_GETU32(attr_td_list_entry+8);	/* index_block_size */
        }
      }
    }
    else
    {	/* attribute is not resident */
      if(attr_type==my_type)
      {
        switch(attr_type)
        {
          case 0x80:	/* AT_DATA */
	    {
	      /* buf must be unsigned! */
	      const unsigned char *buf;
	      uint8_t b;                   	/* Current byte offset in buf. */
	      uint16_t mapping_pairs_offset;
	      const unsigned char*attr_end;     /* End of attribute. */
	      long lcn;
	      int64_t deltaxcn = (int64_t)-1;	/* Change in [vl]cn. */
	      mapping_pairs_offset=NTFS_GETU16(attr_record+32);
	      buf=(const unsigned char*)attr_record + mapping_pairs_offset;
	      attr_end = (const unsigned char*)attr_record + attr_len;
	      lcn = 0;
	      /* return first element of the run_list */
	      b = *buf & 0xf;
	      if (b){
		if (buf + b > attr_end)
		{
		  log_error("Attribut AT_DATA: bad size\n");
		  return 0;
		}
		for (deltaxcn = (int8_t)buf[b--]; b; b--)
		  deltaxcn = (deltaxcn << 8) + (uint8_t)buf[b];
		/* Assume a negative length to indicate data corruption */
		if (deltaxcn < 0)
		  log_error("Invalid length in mapping pairs array.\n");
	      } else { /* The length entry is compulsory. */
		log_error("Missing length entry in mapping pairs array.\n");
	      }
	      if (deltaxcn >= 0)
	      {
		if (!(*buf & 0xf0))
		{
		  log_info("LCN_HOLE\n");
		}
		else
		{
		  /* Get the lcn change which really can be negative. */
		  uint8_t b2 = *buf & 0xf;
		  b = b2 + ((*buf >> 4) & 0xf);
		  if (buf + b > attr_end)
		  {
		    log_error("Attribut AT_DATA: bad size\n");
		    return 0;
		  }
		  for (deltaxcn = (int8_t)buf[b--]; b > b2; b--)
		    deltaxcn = (deltaxcn << 8) + (uint8_t)buf[b];
		  /* Change the current lcn to it's new value. */
		  lcn += deltaxcn;
		  /* Check lcn is not below -1. */
		  if (lcn < -1) {
		    log_error("Invalid LCN < -1 in mapping pairs array.");
		    return 0;
		  }
		  if(verbose>1)
		  {
		    log_verbose("LCN %ld\n",lcn);
		  }
		  if(attr_type==my_type)
		    return lcn;
		}
	      }
	    }
            break;
        }
      }
    }
    attr_record+=attr_len;
  }
}

static int ntfs_read_MFT(disk_t *disk_car, partition_t *partition, const struct ntfs_boot_sector*ntfs_header, const int my_type, const int verbose)
{
  unsigned char *buffer;
  char *attr;
  uint64_t mft_pos;
  unsigned int mft_record_size;
  unsigned int mft_size;
  mft_pos=partition->part_offset+(uint64_t)(le16(ntfs_header->reserved)+le64(ntfs_header->mft_lcn)*ntfs_header->sectors_per_cluster)*ntfs_sector_size(ntfs_header);
  if(ntfs_header->clusters_per_mft_record>0)
    mft_record_size=ntfs_header->sectors_per_cluster*ntfs_header->clusters_per_mft_record;
  else
    mft_record_size=1<<(-ntfs_header->clusters_per_mft_record);
  /* Only need the first 4 MFT record */
  mft_size=4*mft_record_size*ntfs_sector_size(ntfs_header);
#ifdef NTFS_DEBUG
  log_debug("NTFS cluster size = %u\n",ntfs_header->sectors_per_cluster);
  log_debug("NTFS MFT cluster = %lu\n",le64(ntfs_header->mft_lcn));
  log_debug("NTFS MFT_record_size = %u\n",mft_record_size);
  log_debug("NTFS sector size= %u\n", ntfs_sector_size(ntfs_header));
#endif
  if(mft_size==0)
  {
    log_error("Invalid MFT record size or NTFS sector size\n");
    return 1;
  }
  buffer=(unsigned char *)MALLOC(mft_size);
  if((unsigned)disk_car->pread(disk_car, buffer, mft_size, mft_pos) != mft_size)
  {
    log_error("NTFS: Can't read MFT\n");
    free(buffer);
    return 1;
  }
  attr=(char*)buffer;
  while(attr+0x30<=(char*)(buffer+mft_size))
  {
    int res=ntfs_get_attr(attr, my_type, partition, (char*)buffer+mft_size, verbose, NULL);
    if((res>0)|| (NTFS_GETU32(attr + 0x1C)<0x30))
    {
      free(buffer);
      return res;
    }
    attr+= NTFS_GETU32(attr + 0x1C);
  }
  free(buffer);
  return 0;
}

int is_part_ntfs(const partition_t *partition)
{
  if(partition->arch==&arch_i386)
  {
    switch(partition->part_type_i386)
    {
      case P_NTFS:
      case P_NTFSH:
        return 1;
      default:
        break;
    }
  }
  /*
  else if(partition->arch==&arch_gpt)
  {
    if(guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_MS_BASIC_DATA)==0)
      return 1;
  }
  */
  return 0;
}

int is_ntfs(const partition_t *partition)
{
  return(is_part_ntfs(partition) || partition->upart_type==UP_NTFS);
}

int log_ntfs_info(const struct ntfs_boot_sector *ntfs_header)
{
  log_info("filesystem size           %llu\n", (long long unsigned)le64(ntfs_header->sectors_nbr)+1);
  log_info("sectors_per_cluster       %u\n", ntfs_header->sectors_per_cluster);
  log_info("mft_lcn                   %lu\n", (long unsigned int)le64(ntfs_header->mft_lcn));
  log_info("mftmirr_lcn               %lu\n", (long unsigned int)le64(ntfs_header->mftmirr_lcn));
  log_info("clusters_per_mft_record   %d\n", ntfs_header->clusters_per_mft_record);
  log_info("clusters_per_index_record %d\n", ntfs_header->clusters_per_index_record);
  return 0;
}
