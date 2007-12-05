/*
    File: ntfs_fix.c - Part of the TestDisk project.
  
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
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "ntfs.h"
#include "dir.h"
#include "ntfs_dir.h"
#include "io_redir.h"
#include "log.h"

//#define DEBUG_REPAIR_MFT 1

int repair_MFT(disk_t *disk_car, partition_t *partition, const int verbose, char **current_cmd)
{
  struct ntfs_boot_sector *ntfs_header;
  unsigned char *buffer_mft;
  unsigned char *buffer_mftmirr;
  unsigned int cluster_size;
  unsigned int mft_record_size;
  unsigned int mftmirr_size;
  unsigned int mftmirr_size_bytes;
  uint64_t mft_pos;
  uint64_t mftmirr_pos;
  log_trace("repair_MFT\n");
  if(check_NTFS(disk_car, partition, verbose, 0)!=0)
  {
    display_message("Boot sector not valid, can't repair MFT.\n");
    return -1;
  }
  ntfs_header=(struct ntfs_boot_sector *)MALLOC(DEFAULT_SECTOR_SIZE);
  if(disk_car->read(disk_car,DEFAULT_SECTOR_SIZE, ntfs_header, partition->part_offset)!=0)
  {
    free(ntfs_header);
    display_message("Can't read NTFS boot sector.\n");
    return -1;
  }
  mft_pos=partition->part_offset+(uint64_t)(le16(ntfs_header->reserved)+le64(ntfs_header->mft_lcn)*ntfs_header->sectors_per_cluster)*ntfs_sector_size(ntfs_header);
  mftmirr_pos=partition->part_offset+(uint64_t)(le16(ntfs_header->reserved)+le64(ntfs_header->mftmirr_lcn)*ntfs_header->sectors_per_cluster)*ntfs_sector_size(ntfs_header);
  if(ntfs_header->clusters_per_mft_record>0)
    mft_record_size=ntfs_header->sectors_per_cluster*ntfs_header->clusters_per_mft_record;
  else
    mft_record_size=1<<(-ntfs_header->clusters_per_mft_record);

  cluster_size=ntfs_header->sectors_per_cluster;

  if (cluster_size <= 4 * mft_record_size)
    mftmirr_size = 4;
  else
    mftmirr_size = cluster_size / mft_record_size;
  mftmirr_size_bytes=mftmirr_size * mft_record_size * ntfs_sector_size(ntfs_header);
#ifdef DEBUG_REPAIR_MFT
  log_debug("mft_pos %lu\n",(unsigned long)(mft_pos/disk_car->sector_size));
  log_debug("mftmirr_pos %lu\n",(unsigned long)(mftmirr_pos/disk_car->sector_size));
  log_debug("mftmirr_size %u\n", mftmirr_size);
  log_debug("cluster_size %u\n", cluster_size);
  log_debug("mft_record_size    %u\n", mft_record_size);
  log_debug("ntfs_sector_size   %u\n", ntfs_sector_size(ntfs_header));
  log_debug("mftmirr_size_bytes %u\n", mftmirr_size_bytes);
#endif
  if(mftmirr_size_bytes==0)
  {
    display_message("Invalid NTFS MFT size.\n");
    log_error("Invalid NTFS MFT size.\n");
    free(ntfs_header);
    return -1;
  }
  /* Check if MFT mirror is identical to the beginning of MFT */
  buffer_mft=(unsigned char *)MALLOC(mftmirr_size_bytes);
  if(disk_car->read(disk_car, mftmirr_size_bytes, buffer_mft, mft_pos)!=0)
  {
    display_message("Can't read NTFS MFT.\n");
    log_error("Can't read NTFS MFT.\n");
    free(buffer_mft);
    free(ntfs_header);
    return -1;
  }
  buffer_mftmirr=(unsigned char *)MALLOC(mftmirr_size_bytes);
  if(disk_car->read(disk_car, mftmirr_size_bytes, buffer_mftmirr, mftmirr_pos)!=0)
  {
    display_message("Can't read NTFS MFT mirror.\n");
    log_error("Can't read NTFS MFT mirror.\n");
    free(buffer_mftmirr);
    free(buffer_mft);
    free(ntfs_header);
    return -1;
  }
  if(memcmp(buffer_mft, buffer_mftmirr, mftmirr_size_bytes)==0)
  {
    log_info("MFT and MFT mirror matches perfectly.\n");
    display_message("MFT and MFT mirror matches perfectly.\n");
    free(buffer_mftmirr);
    free(buffer_mft);
    free(ntfs_header);
    return 0;
  }
/*
  log_debug("MFT\n");
  dump_log(buffer_mft, mftmirr_size_bytes);
  log_debug("MFT mirror\n");
  dump_log(buffer_mftmirr, mftmirr_size_bytes);
  */
  /*
  The idea is to use the internal IO redirector built-in TestDisk
  to redirect read access to the MFT to the MFT backup instead (or
  vice-versa) when listing the NTFS files. If TestDisk can get
  a file listing, it also knows which MFT to use.
  */
  {
    int res1,res2;
    dir_data_t dir_data;
    /* Use MFT */
    io_redir_add_redir(disk_car, mftmirr_pos, mftmirr_size_bytes, 0, buffer_mft);
    res1=dir_partition_ntfs_init(disk_car,partition,&dir_data,verbose);
    if(res1==-2)
    {
	display_message("Can't determine which MFT is correct, ntfslib is missing.\n");
	log_error("Can't determine which MFT is correct, ntfslib is missing.\n");
	free(buffer_mftmirr);
	free(buffer_mft);
	free(ntfs_header);
	io_redir_del_redir(disk_car,mftmirr_pos);
	return 0;
    }
    if(res1==0)
    {
      file_data_t *dir_list;
      dir_list=dir_data.get_dir(disk_car,partition,&dir_data,dir_data.current_inode);
      if(dir_list!=NULL)
      {
	log_info("NTFS listing using MFT:\n");
	dir_aff_log(disk_car, partition, &dir_data, dir_list);
	delete_list_file(dir_list);
	res1++;
      }
      dir_data.close(&dir_data);
    }
    io_redir_del_redir(disk_car,mftmirr_pos);
    /* Use MFT mirror */
    io_redir_add_redir(disk_car, mft_pos, mftmirr_size_bytes, 0, buffer_mftmirr);
    res2=dir_partition_ntfs_init(disk_car,partition,&dir_data,verbose);
    if(res2==0)
    {
      file_data_t *dir_list;
      dir_list=dir_data.get_dir(disk_car,partition,&dir_data,dir_data.current_inode);
      if(dir_list!=NULL)
      {
	log_info("NTFS listing using MFT mirror:\n");
	dir_aff_log(disk_car, partition, &dir_data, dir_list);
	delete_list_file(dir_list);
	res2++;
      }
      dir_data.close(&dir_data);
    }
    io_redir_del_redir(disk_car,mft_pos);
    /* */
    if(res1>res2)
    {
      /* Use MFT */
      if(ask_confirmation("Fix MFT mirror ? (Y/N)")!=0)
      {
	if(disk_car->write(disk_car, mftmirr_size_bytes, buffer_mft, mftmirr_pos)!=0)
        {
	  log_error("Failed to fix MFT mirror: write error.\n");
	  display_message("Failed to fix MFT mirror: write error.\n");
        }
	else
        {
          disk_car->sync(disk_car);
	  log_info("MFT mirror fixed.\n");
	  display_message("MFT mirror fixed.\n");
        }
      }
      else
      {
	log_info("Don't fix MFT mirror.\n");
      }
    }
    else if(res1<res2)
    {
      /* Use MFT mirror */
      if(ask_confirmation("Fix MFT ? (Y/N)")!=0)
      {
	if(disk_car->write(disk_car, mftmirr_size_bytes, buffer_mftmirr, mft_pos)!=0)
        {
	  log_error("Failed to fix MFT: write error.\n");
	  display_message("Failed to fix MFT: write error.\n");
        }
	else
        {
          disk_car->sync(disk_car);
	  log_info("MFT fixed.\n");
	  display_message("MFT fixed.\n");
        }
      }
      else
      {
	log_info("Don't fix MFT.\n");
      }
    }
    else if(res1<0)
    {
      /* Both are bad */
      log_error("MFT and MFT mirror are bad. Failed to repair them.\n");
      display_message("MFT and MFT mirror are bad. Failed to repair them.\n");
    }
    else
    {
      /* Use chkdsk */
      log_error("Both MFT seems ok but they don't match, use chkdsk.\n");
      display_message("Both MFT seems ok but they don't match, use chkdsk.\n");
    }
  }
  free(buffer_mftmirr);
  free(buffer_mft);
  free(ntfs_header);
  return 0;
}
