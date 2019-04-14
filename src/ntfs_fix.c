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
#include "ntfs_fix.h"
#include "io_redir.h"
#include "log.h"
#include "intrfn.h"
#include "lang.h"

//#define DEBUG_REPAIR_MFT 1
#define INTER_MFT_X		0
#define INTER_MFT_Y  		18

int repair_MFT(disk_t *disk_car, partition_t *partition, const int verbose, const unsigned int expert, char **current_cmd)
{
  struct ntfs_boot_sector *ntfs_header;
  unsigned char *buffer_mft;
  unsigned char *buffer_mftmirr;
  unsigned int cluster_size;
  unsigned int mft_record_size;
  unsigned int mftmirr_size_bytes;
  unsigned int use_MFT=0;
  /* 0: do nothing
   * 1: fix MFT mirror using MFT
   * 2: fix MFT using MFT mirror */
  uint64_t mft_pos;
  uint64_t mftmirr_pos;
  log_trace("repair_MFT\n");
  if(check_NTFS(disk_car, partition, verbose, 0)!=0)
  {
    display_message("Boot sector not valid, can't repair MFT.\n");
    return -1;
  }
  ntfs_header=(struct ntfs_boot_sector *)MALLOC(DEFAULT_SECTOR_SIZE);
  if(disk_car->pread(disk_car, ntfs_header, DEFAULT_SECTOR_SIZE, partition->part_offset) != DEFAULT_SECTOR_SIZE)
  {
    free(ntfs_header);
    display_message("Can't read NTFS boot sector.\n");
    return -1;
  }
  mft_pos=partition->part_offset+(uint64_t)(le16(ntfs_header->reserved)+le64(ntfs_header->mft_lcn)*ntfs_header->sectors_per_cluster)*ntfs_sector_size(ntfs_header);
  mftmirr_pos=partition->part_offset+(uint64_t)(le16(ntfs_header->reserved)+le64(ntfs_header->mftmirr_lcn)*ntfs_header->sectors_per_cluster)*ntfs_sector_size(ntfs_header);
  if(ntfs_header->clusters_per_mft_record>0)
    mft_record_size=ntfs_header->clusters_per_mft_record * ntfs_header->sectors_per_cluster * ntfs_sector_size(ntfs_header);
  else
    mft_record_size=1<<(-ntfs_header->clusters_per_mft_record);

  if(mft_record_size < 42)
  {
    display_message("Invalid NTFS MFT record size.\n");
    log_error("Invalid NTFS MFT record size.\n");
    free(ntfs_header);
    return -1;
  }

  cluster_size=ntfs_header->sectors_per_cluster * ntfs_sector_size(ntfs_header);

  mftmirr_size_bytes = td_max(cluster_size , 4 * mft_record_size);
#ifdef DEBUG_REPAIR_MFT
  log_info("mft_pos          %lu\n",(unsigned long)(mft_pos/disk_car->sector_size));
  log_info("mftmirr_pos      %lu\n",(unsigned long)(mftmirr_pos/disk_car->sector_size));
  log_info("cluster_size     %5u bytes\n", cluster_size);
  log_info("mft_record_size  %5u bytes\n", mft_record_size);
  log_info("ntfs_sector_size %5u bytes\n", ntfs_sector_size(ntfs_header));
  log_info("mftmirr_size     %5u bytes\n", mftmirr_size_bytes);
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
  if((unsigned)disk_car->pread(disk_car, buffer_mft, mftmirr_size_bytes, mft_pos) != mftmirr_size_bytes)
  {
    display_message("Can't read NTFS MFT.\n");
    log_error("Can't read NTFS MFT.\n");
    free(buffer_mft);
    free(ntfs_header);
    return -1;
  }
  buffer_mftmirr=(unsigned char *)MALLOC(mftmirr_size_bytes);
  if((unsigned)disk_car->pread(disk_car, buffer_mftmirr, mftmirr_size_bytes, mftmirr_pos) != mftmirr_size_bytes)
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
    log_info("MFT and MFT mirror match perfectly.\n");
    if(*current_cmd==NULL)
      display_message("MFT and MFT mirror match perfectly.\n");
    free(buffer_mftmirr);
    free(buffer_mft);
    free(ntfs_header);
    return 0;
  }
  if(partition->sb_offset!=0)
  {
    log_info("Please quit TestDisk and reboot your computer before trying to fix the MFT.\n");
    display_message("Please quit TestDisk and reboot your computer before trying to fix the MFT.\n");
    free(buffer_mftmirr);
    free(buffer_mft);
    free(ntfs_header);
    return -1;
  }
#ifdef DEBUG_REPAIR_MFT
  log_info("MFT\n");
  dump_log(buffer_mft, mftmirr_size_bytes);
  log_info("MFT mirror\n");
  dump_log(buffer_mftmirr, mftmirr_size_bytes);
  log_flush();
#endif
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
    res1=dir_partition_ntfs_init(disk_car, partition, &dir_data, verbose, 0);
    if(res1==DIR_PART_ENOSYS)
    {
	display_message("Can't determine which MFT is correct, ntfslib is missing.\n");
	log_error("Can't determine which MFT is correct, ntfslib is missing.\n");
	free(buffer_mftmirr);
	free(buffer_mft);
	free(ntfs_header);
	io_redir_del_redir(disk_car,mftmirr_pos);
	return 0;
    }
    if(res1==DIR_PART_OK)
    {
      file_info_t dir_list;
      TD_INIT_LIST_HEAD(&dir_list.list);
      dir_data.get_dir(disk_car,partition,&dir_data,dir_data.current_inode, &dir_list);
      if(!td_list_empty(&dir_list.list))
      {
	log_info("NTFS listing using MFT:\n");
	dir_aff_log(&dir_data, &dir_list);
	if(delete_list_file(&dir_list)>2)
	  res1++;
      }
      dir_data.close(&dir_data);
    }
    io_redir_del_redir(disk_car,mftmirr_pos);
    /* Use MFT mirror */
    io_redir_add_redir(disk_car, mft_pos, mftmirr_size_bytes, 0, buffer_mftmirr);
    res2=dir_partition_ntfs_init(disk_car, partition, &dir_data, verbose, 0);
    if(res2==DIR_PART_OK)
    {
      file_info_t dir_list;
      TD_INIT_LIST_HEAD(&dir_list.list);
      dir_data.get_dir(disk_car,partition,&dir_data,dir_data.current_inode, &dir_list);
      if(!td_list_empty(&dir_list.list))
      {
	log_info("NTFS listing using MFT mirror:\n");
	dir_aff_log(&dir_data, &dir_list);
	if(delete_list_file(&dir_list)>2)
	  res2++;
      }
      dir_data.close(&dir_data);
    }
    io_redir_del_redir(disk_car,mft_pos);
    /* */
    if(res1>res2 && res1>DIR_PART_OK)
    {
      /* Use MFT */
#ifdef HAVE_NCURSES
      if(ask_confirmation("Fix MFT mirror using MFT ? (Y/N)")!=0)
	use_MFT=1;
      else
#endif
	log_info("Don't fix MFT mirror.\n");
    }
    else if(res1<res2 && res2>DIR_PART_OK)
    {
      /* Use MFT mirror */
#ifdef HAVE_NCURSES
      if(ask_confirmation("Fix MFT using its mirror ? (Y/N) - DANGEROUS NON REVERSIBLE OPERATION\nUse it ONLY IF TestDisk and Windows failed to access this filesystem.")!=0)
	use_MFT=2;
      else
#endif
	log_info("Don't fix MFT.\n");
    }
    else
    { /* res1==res2 */
      if(res1>DIR_PART_OK && res2>DIR_PART_OK)
	log_error("Both MFT seems ok but they don't match, use chkdsk.\n");
      else
	log_error("MFT and MFT mirror are bad. Failed to repair them.\n");
      if(expert==0)
      {
	if(res1>DIR_PART_OK && res2>DIR_PART_OK)
	  display_message("Both MFT seems ok but they don't match, use chkdsk.\n");
	else
	  display_message("MFT and MFT mirror are bad. Failed to repair them.\n");
      }
      else
      {
#ifdef HAVE_NCURSES
	unsigned int menu=2;
	int real_key;
	int command;
	static const struct MenuItem menuMFT[]=
	{
	  {'B',"MFT",		"Fix MFT using MFT mirror"},
	  {'M',"MFT Mirror",	"Fix MFT mirror using MFT"},
	  {'Q',"Quit","Return to NTFS functions"},
	  {0,NULL,NULL}
	};
	aff_copy(stdscr);
	wmove(stdscr,4,0);
	wprintw(stdscr,"%s",disk_car->description(disk_car));
	mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
	wmove(stdscr,6,0);
	aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
	wmove(stdscr,8,0);
	if(res1>0 && res2>0)
	  wprintw(stdscr, "Both MFT seem ok but they don't match.\n");
	else
	  wprintw(stdscr, "MFT and MFT mirror are bad.\n");
	command=wmenuSelect_ext(stdscr, 23, INTER_MFT_Y, INTER_MFT_X, menuMFT, 10, "MBQ",
	    MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu, &real_key);
	switch(command)
	{
	  case 'b':
	  case 'B':
	    use_MFT=2;
	    break;
	  case 'm':
	  case 'M':
	    use_MFT=1;
	    break;
	  default:
	    use_MFT=0;
	    break;
	}
#endif
      }
    }
  }
  if(use_MFT==2)
  {
    if((unsigned)disk_car->pwrite(disk_car, buffer_mftmirr, mftmirr_size_bytes, mft_pos) != mftmirr_size_bytes)
    {
      display_message("Failed to fix MFT: write error.\n");
    }
    else
    {
      disk_car->sync(disk_car);
      display_message("MFT fixed.\n");
    }
  }
  else if(use_MFT==1)
  {
    if((unsigned)disk_car->pwrite(disk_car, buffer_mft, mftmirr_size_bytes, mftmirr_pos) != mftmirr_size_bytes)
    {
      display_message("Failed to fix MFT mirror: write error.\n");
    }
    else
    {
      disk_car->sync(disk_car);
      display_message("MFT mirror fixed.\n");
    }
  }
  free(buffer_mftmirr);
  free(buffer_mft);
  free(ntfs_header);
  return 0;
}
