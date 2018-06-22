/*

    File: ntfs_adv.c

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "dirpart.h"
#include "ntfs.h"
#include "lang.h"
#include "io_redir.h"
#include "log.h"
#include "log_part.h"

#define INTER_NTFS_X 0
#define INTER_NTFS_Y 23
#define INTER_NTFSBS_X		0
#define INTER_NTFSBS_Y		22

#define MAX_INFO_MFT 10
#define NTFS_SECTOR_SIZE 0x200

typedef struct s_info_mft info_mft_t;
struct s_info_mft
{
  uint64_t sector;
  uint64_t mft_lcn;
  uint64_t mftmirr_lcn;
};

#ifdef HAVE_NCURSES
static int ncurses_ntfs2_info(const struct ntfs_boot_sector *nh1, const struct ntfs_boot_sector *nh2);
static int ncurses_ntfs_info(const struct ntfs_boot_sector *ntfs_header);
#endif
static int testdisk_ffs(int x);
static int read_mft_info(disk_t *disk_car, partition_t *partition, const uint64_t mft_sector, const int verbose, unsigned int *sectors_per_cluster, uint64_t *mft_lcn, uint64_t *mftmirr_lcn, unsigned int *mft_record_size);

#ifdef HAVE_NCURSES
static void ntfs_dump_ncurses(disk_t *disk_car, const partition_t *partition, const unsigned char *orgboot, const unsigned char *newboot)
{
  WINDOW *window=newwin(LINES, COLS, 0, 0);	/* full screen */
  keypad(window, TRUE); /* Need it to get arrow key */
  aff_copy(window);
  wmove(window,4,0);
  wprintw(window,"%s",disk_car->description(disk_car));
  wmove(window,5,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  mvwaddstr(window,6,0, "     Rebuild Boot sector           Boot sector");
  dump2(window, newboot, orgboot, NTFS_SECTOR_SIZE);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
} 
#endif

static void ntfs_dump(disk_t *disk_car, const partition_t *partition, const unsigned char *orgboot, const unsigned char *newboot, char **current_cmd)
{
  log_info("     Rebuild Boot sector           Boot sector\n");
  dump2_log(newboot, orgboot, NTFS_SECTOR_SIZE);
  if(current_cmd==NULL || *current_cmd==NULL)
  {
#ifdef HAVE_NCURSES
    ntfs_dump_ncurses(disk_car, partition, orgboot, newboot);
#endif
  }
}

static void ntfs_write_boot_sector(disk_t *disk, partition_t *partition, const unsigned char *newboot)
{
  log_info("Write new boot!\n");
  /* Reset information about backup boot sector */
  partition->sb_offset=0;
  /* Write boot sector and backup boot sector */
  if(disk->pwrite(disk, newboot, NTFS_SECTOR_SIZE, partition->part_offset) != NTFS_SECTOR_SIZE)
  {
    display_message("Write error: Can't write new NTFS boot sector\n");
  }
  if(disk->pwrite(disk, newboot, NTFS_SECTOR_SIZE, partition->part_offset + partition->part_size - disk->sector_size) != NTFS_SECTOR_SIZE)
  {
    display_message("Write error: Can't write new NTFS backup boot sector\n");
  }
  disk->sync(disk);
}

static void ntfs_list(disk_t *disk, partition_t *partition, const unsigned char *newboot, char **current_cmd, const int expert)
{
  io_redir_add_redir(disk,partition->part_offset,NTFS_SECTOR_SIZE,0,newboot);
  dir_partition(disk, partition, 0, expert, current_cmd);
  io_redir_del_redir(disk,partition->part_offset);
}

static void menu_write_ntfs_boot_sector_cli(disk_t *disk_car, partition_t *partition, const unsigned char *orgboot, const unsigned char *newboot, char **current_cmd, const int expert)
{
  const struct ntfs_boot_sector *org_ntfs_header=(const struct ntfs_boot_sector *)orgboot;
  const struct ntfs_boot_sector *ntfs_header=(const struct ntfs_boot_sector *)newboot;
  int no_confirm=0;
  while(1)
  {
    if(memcmp(newboot,orgboot,NTFS_SECTOR_SIZE)!=0)
    {
      log_ntfs2_info(ntfs_header, org_ntfs_header);
    }
    else
    {
      log_ntfs_info(ntfs_header);
    }
    skip_comma_in_command(current_cmd);
    if(check_command(current_cmd,"list",4)==0)
    {
      ntfs_list(disk_car, partition, newboot, current_cmd, expert);
    }
    else if(check_command(current_cmd,"dump",4)==0)
    {
      ntfs_dump(disk_car, partition, orgboot, newboot, current_cmd);
    }
    else if(check_command(current_cmd,"noconfirm,",10)==0)
    {
      no_confirm=1;
    }
    else if(check_command(current_cmd,"write",5)==0)
    {
      if(no_confirm!=0
#ifdef HAVE_NCURSES
	|| ask_confirmation("Write new NTFS boot sector, confirm ? (Y/N)")!=0
#endif
	)
	ntfs_write_boot_sector(disk_car, partition, newboot);
      return ;
    }
    else
    {
      log_info("Don't write new NTFS boot sector and backup boot sector!\n");
      return;
    }
  }
}

#ifdef HAVE_NCURSES
static void menu_write_ntfs_boot_sector_ncurses(disk_t *disk_car, partition_t *partition, const unsigned char *orgboot, const unsigned char *newboot, const int expert)
{
  const struct ntfs_boot_sector *org_ntfs_header=(const struct ntfs_boot_sector *)orgboot;
  const struct ntfs_boot_sector *ntfs_header=(const struct ntfs_boot_sector *)newboot;
  const struct MenuItem menuSaveBoot[]=
  {
    { 'D', "Dump", "Dump sector" },
    { 'L', "List", "List directories and files" },
    { 'W', "Write","Write boot"},
    { 'Q',"Quit","Quit this section"},
    { 0, NULL, NULL }
  };
  while(1)
  {
    const char *options;
    int command;
    aff_copy(stdscr);
    wmove(stdscr,4,0);
    wprintw(stdscr,"%s",disk_car->description(disk_car));
    mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
    wmove(stdscr,6,0);
    aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
    wmove(stdscr,8,0);
    if(memcmp(newboot,orgboot,NTFS_SECTOR_SIZE))
    {
      options="DLWQ";
      ncurses_ntfs2_info(ntfs_header, org_ntfs_header);
      wprintw(stdscr,"Extrapolated boot sector and current boot sector are different.\n");
      log_ntfs2_info(ntfs_header, org_ntfs_header);
    }
    else
    {
      options="DLQ";
      log_ntfs_info(ntfs_header);
      ncurses_ntfs_info(ntfs_header);
      wprintw(stdscr,"Extrapolated boot sector and current boot sector are identical.\n");
    }
    command=wmenuSelect(stdscr, INTER_NTFSBS_Y+1, INTER_NTFSBS_Y, INTER_NTFSBS_X, menuSaveBoot,8,options,MENU_HORIZ | MENU_BUTTON, 1);
    switch(command)
    {
      case 'w':
      case 'W':
	if(strchr(options,'W')!=NULL && ask_confirmation("Write new NTFS boot sector, confirm ? (Y/N)")!=0)
	  ntfs_write_boot_sector(disk_car, partition, newboot);
	return;
      case 'd':
      case 'D':
	if(strchr(options,'D')!=NULL)
	  ntfs_dump(disk_car, partition, orgboot, newboot, NULL);
	break;
      case 'l':
      case 'L':
	ntfs_list(disk_car, partition, newboot, NULL, expert);
	break;
      case 'q':
      case 'Q':
	return;
    }
  }
}
#endif

static void create_ntfs_boot_sector(disk_t *disk_car, partition_t *partition, const unsigned int cluster_size, const uint64_t mft_lcn, const uint64_t mftmirr_lcn, const uint32_t mft_record_size, const uint32_t index_block_size, const int expert, char**current_cmd)
{
  unsigned char orgboot[NTFS_SECTOR_SIZE];
  unsigned char newboot[NTFS_SECTOR_SIZE];
  struct ntfs_boot_sector *org_ntfs_header=(struct ntfs_boot_sector *)&orgboot;
  struct ntfs_boot_sector *ntfs_header=(struct ntfs_boot_sector *)&newboot;
  if(disk_car->pread(disk_car, &orgboot, NTFS_SECTOR_SIZE, partition->part_offset) != NTFS_SECTOR_SIZE)
  {
    log_error("create_ntfs_boot_sector: Can't read boot sector.\n");
    memset(&orgboot,0,NTFS_SECTOR_SIZE);
  }
  if(cluster_size==0)
  {
    display_message("NTFS Bad extrapolation.\n");
    return ;
  }
  memcpy(&newboot,&orgboot,NTFS_SECTOR_SIZE);
  memcpy(ntfs_header->system_id,"NTFS    ",8);
  ntfs_header->sector_size[0]=disk_car->sector_size & 0xFF;
  ntfs_header->sector_size[1]=disk_car->sector_size>>8;
  ntfs_header->sectors_per_cluster=cluster_size/disk_car->sector_size;
  ntfs_header->reserved=le16(0);
  ntfs_header->fats=0;
  ntfs_header->dir_entries[0]=0;
  ntfs_header->dir_entries[1]=0;
  ntfs_header->sectors[0]=0;
  ntfs_header->sectors[1]=0;
  ntfs_header->media=0xF8;
  ntfs_header->fat_length=le16(0);
  ntfs_header->secs_track=le16(disk_car->geom.sectors_per_head);
  ntfs_header->heads=le16(disk_car->geom.heads_per_cylinder);
  /* absolute sector address from the beginning of the disk (!= FAT) */
  ntfs_header->hidden=le32(partition->part_offset/disk_car->sector_size);
  ntfs_header->total_sect=le32(0);
  ntfs_header->sectors_nbr=le64(partition->part_size/disk_car->sector_size-1);
  ntfs_header->mft_lcn=le64(mft_lcn);
  ntfs_header->mftmirr_lcn=le64(mftmirr_lcn);
  ntfs_header->clusters_per_mft_record=(mft_record_size >= cluster_size ?
      mft_record_size / cluster_size : -(testdisk_ffs(mft_record_size) - 1));
  ntfs_header->clusters_per_index_record =(index_block_size >= cluster_size ?
      index_block_size / cluster_size : -(testdisk_ffs(index_block_size) - 1));
  ntfs_header->reserved0[0]=0;
  ntfs_header->reserved0[1]=0;
  ntfs_header->reserved0[2]=0;
  ntfs_header->reserved1[0]=0;
  ntfs_header->reserved1[1]=0;
  ntfs_header->reserved1[2]=0;
  /*
  {
    uint32_t *u;
    uint32_t checksum;
    for (checksum = 0,u=(uint32_t*)ntfs_header; u < (uint32_t*)(&ntfs_header->checksum); u++)
      checksum += NTFS_GETU32(u);
    ntfs_header->checksum=le32(checksum);
  }
  */
  ntfs_header->checksum=le32(0);
  ntfs_header->marker=le16(0xAA55);
  if(memcmp(newboot,orgboot,NTFS_SECTOR_SIZE))
  {
    log_warning("             New / Current boot sector\n");
    log_ntfs2_info(ntfs_header,org_ntfs_header);
    log_warning("Extrapolated boot sector and current boot sector are different.\n");
  }
  else
  {
    log_info("Extrapolated boot sector and current boot sector are identical.\n");
  }
  if(*current_cmd!=NULL)
  {
    menu_write_ntfs_boot_sector_cli(disk_car, partition, orgboot, newboot, current_cmd, expert);
    return ;
  }
#ifdef HAVE_NCURSES
  menu_write_ntfs_boot_sector_ncurses(disk_car, partition, orgboot, newboot, expert);
#endif
}

static int read_mft_info(disk_t *disk_car, partition_t *partition, const uint64_t mft_sector, const int verbose, unsigned int *sectors_per_cluster, uint64_t *mft_lcn, uint64_t *mftmirr_lcn, unsigned int *mft_record_size)
{
  char buffer[8*DEFAULT_SECTOR_SIZE];
  const struct ntfs_mft_record *record=(const struct ntfs_mft_record *)buffer;
  const ntfs_attribnonresident *attr80;
  if(disk_car->pread(disk_car, &buffer, sizeof(buffer), partition->part_offset + (uint64_t)mft_sector * disk_car->sector_size) != sizeof(buffer))
  {
    display_message("NTFS: Can't read mft_sector\n");
    return 1;
  }
  *mft_record_size=le32(record->bytes_allocated);
  if(*mft_record_size < 42)
  {
    if(verbose>0)
      log_warning("read_mft_info failed: mft_record_size < 42\n");
    return 2;
  }
  attr80=(const ntfs_attribnonresident *)ntfs_findattribute(record, 0x80, buffer+sizeof(buffer));
  if(attr80 && attr80->header.bNonResident)
  {
    *mft_lcn=ntfs_get_first_rl_element(attr80, buffer+sizeof(buffer));
  }
  record=(const struct ntfs_mft_record *)(buffer + (*mft_record_size));
  if((const char *)record< buffer || (const char *)record> buffer+sizeof(buffer))
  {
    if(verbose<0)
      log_warning("read_mft_info failed: bad record.\n");
    return 2;
  }
  attr80=(const ntfs_attribnonresident *)ntfs_findattribute(record, 0x80, buffer+sizeof(buffer));
  if(attr80 && attr80->header.bNonResident)
  {
    *mftmirr_lcn=ntfs_get_first_rl_element(attr80, buffer+sizeof(buffer));
  }
  /* Try to divide by the biggest number first */
  if(*mft_lcn<*mftmirr_lcn)
  {
    if(*mftmirr_lcn>0 && mft_sector%(*mftmirr_lcn)==0)
    {
      *sectors_per_cluster=mft_sector/(*mftmirr_lcn);
      switch(*sectors_per_cluster)
      {
	case 1: case 2: case 4: case 8: case 16: case 32: case 64: case 128:
	  return 0;
	default:
	  break;
      }
    }
    if(*mft_lcn>0 && mft_sector%(*mft_lcn)==0)
    {
      *sectors_per_cluster=mft_sector/(*mft_lcn);
      switch(*sectors_per_cluster)
      {
	case 1: case 2: case 4: case 8: case 16: case 32: case 64: case 128:
	  return 0;
	default:
	  break;
      }
    }
  }
  else
  {
    if(*mft_lcn>0 && mft_sector%(*mft_lcn)==0)
    {
      *sectors_per_cluster=mft_sector/(*mft_lcn);
      switch(*sectors_per_cluster)
      {
	case 1: case 2: case 4: case 8: case 16: case 32: case 64: case 128:
	  return 0;
	default:
	  break;
      }
    }
    if(*mftmirr_lcn>0 && mft_sector%(*mftmirr_lcn)==0)
    {
      *sectors_per_cluster=mft_sector/(*mftmirr_lcn);
      switch(*sectors_per_cluster)
      {
	case 1: case 2: case 4: case 8: case 16: case 32: case 64: case 128:
	  return 0;
	default:
	  break;
      }
    }
  }
  if(verbose>0)
  {
    log_warning("read_mft_info failed\n");
    log_warning("ntfs_find_mft: sectors_per_cluster invalid\n");
    log_warning("ntfs_find_mft: mft_lcn             %lu\n",(long unsigned int)*mft_lcn);
    log_warning("ntfs_find_mft: mftmirr_lcn         %lu\n",(long unsigned int)*mftmirr_lcn);
    log_warning("ntfs_find_mft: mft_record_size     %u\n",*mft_record_size);
    log_warning("\n");
  }
  *sectors_per_cluster=0;
  return 3;
}

int rebuild_NTFS_BS(disk_t *disk_car, partition_t *partition, const int verbose, const unsigned int expert, char **current_cmd)
{
  uint64_t sector;
  char buffer[8*DEFAULT_SECTOR_SIZE];
  int ind_stop=0;
  unsigned int sectors_per_cluster=0;
  uint64_t mft_lcn=0;
  uint64_t mftmirr_lcn=0;
  unsigned int mft_record_size=1024;
  info_mft_t info_mft[MAX_INFO_MFT];
  unsigned int nbr_mft=0;
  log_info("rebuild_NTFS_BS\n");
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s",disk_car->description(disk_car));
  mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
  wmove(stdscr,6,0);
  aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  wmove(stdscr,22,0);
  wattrset(stdscr, A_REVERSE);
  waddstr(stdscr,"  Stop  ");
  wattroff(stdscr, A_REVERSE);
#endif
  /* try to find MFT Backup first */
  for(sector=(partition->part_size/disk_car->sector_size/2-20>0?partition->part_size/disk_car->sector_size/2-20:1);
      sector<partition->part_size/disk_car->sector_size && 
      sector<=partition->part_size/disk_car->sector_size/2+20 &&
      ind_stop==0;
      sector++)
  {
    if(disk_car->pread(disk_car, &buffer, 0x400, partition->part_offset + sector * (uint64_t)disk_car->sector_size) == 0x400)
    {
      const struct ntfs_mft_record *record=(const struct ntfs_mft_record *)&buffer;
      if(memcmp(buffer,"FILE",4)==0 &&
	  le16(record->attrs_offset)%8==0 &&
	  le16(record->attrs_offset)>=42 &&
	  le16(record->flags)==1)	/* MFT_RECORD_IN_USE */
      {
	const ntfs_attribheader *attr30;
	int res=0;
	attr30=ntfs_findattribute(record, 0x30, buffer+0x400);
	if(attr30 && attr30->bNonResident==0)
	{
	  const TD_FILE_NAME_ATTR *file_name_attr=(const TD_FILE_NAME_ATTR *)ntfs_getattributedata((const ntfs_attribresident *)attr30, buffer+0x400);
	  if(file_name_attr->file_name_length==4 &&
	      (const char*)&file_name_attr->file_name[0]+8 <= buffer+0x400 &&
	      memcmp(file_name_attr->file_name,"$\0M\0F\0T\0", 8)==0)
	    res=1;
	}
	if(res==1)
	{
	  int tmp;
	  log_info("mft at %lu\n",(long unsigned)sector);
	  tmp=read_mft_info(disk_car, partition, sector, verbose, &sectors_per_cluster, &mft_lcn, &mftmirr_lcn, &mft_record_size);
	  if(tmp==0)
	  {
	    log_info("ntfs_find_mft: mft_lcn             %lu\n",(long unsigned int)mft_lcn);
	    log_info("ntfs_find_mft: mftmirr_lcn         %lu\n",(long unsigned int)mftmirr_lcn);
	    if(expert==0
#ifdef HAVE_NCURSES
		|| ask_confirmation("Use MFT from %lu, confirm ? (Y/N)",(long unsigned int)mft_lcn)!=0
#endif
	      )
	      ind_stop=1;
	  }
	  else if(tmp==3)
	  {
	    if(nbr_mft<MAX_INFO_MFT)
	    {
	      info_mft[nbr_mft].sector=sector;
	      info_mft[nbr_mft].mft_lcn=mft_lcn;
	      info_mft[nbr_mft].mftmirr_lcn=mftmirr_lcn;
	      nbr_mft++;
	    }
	  }
	}
      }
    }
  }
  for(sector=1;(sector<partition->part_size/disk_car->sector_size)&&(ind_stop==0);sector++)
  {
#ifdef HAVE_NCURSES
    if((sector&0xffff)==0)
    {
      wmove(stdscr,9,0);
      wclrtoeol(stdscr);
      wprintw(stdscr,"Search mft %10lu/%lu", (long unsigned)sector,
	  (long unsigned)(partition->part_size/disk_car->sector_size));
      wrefresh(stdscr);
      if(check_enter_key_or_s(stdscr))
      {
	log_info("Search mft stopped: %10lu/%lu\n", (long unsigned)sector,
	    (long unsigned)(partition->part_size/disk_car->sector_size));
	ind_stop=1;
      }
    }
#endif
    if(disk_car->pread(disk_car, &buffer, 0x400, partition->part_offset + sector * (uint64_t)disk_car->sector_size) == 0x400)
    {
      const struct ntfs_mft_record *record=(const struct ntfs_mft_record *)&buffer;
      if(memcmp(buffer,"FILE",4)==0 &&
	  le16(record->attrs_offset)%8==0 &&
	  le16(record->attrs_offset)>=42 &&
	  le16(record->flags)==1)	/* MFT_RECORD_IN_USE */
      {
	const ntfs_attribheader *attr30;
	int res=0;
	attr30=ntfs_findattribute(record, 0x30, buffer+0x400);
	if(attr30 && attr30->bNonResident==0)
	{
	  const TD_FILE_NAME_ATTR *file_name_attr=(const TD_FILE_NAME_ATTR *)ntfs_getattributedata((const ntfs_attribresident *)attr30, buffer+0x400);
	  if(file_name_attr->file_name_length==4 &&
	      (const char*)&file_name_attr->file_name[0]+8 <= buffer+0x400 &&
	      memcmp(file_name_attr->file_name,"$\0M\0F\0T\0", 8)==0)
	    res=1;
	}
	if(res==1)
	{
	  int tmp;
	  log_info("mft at %lu\n", (long unsigned)sector);
	  tmp=read_mft_info(disk_car, partition, sector, verbose, &sectors_per_cluster, &mft_lcn, &mftmirr_lcn, &mft_record_size);
	  if(tmp==0)
	  {
	    log_info("ntfs_find_mft: mft_lcn             %lu\n",(long unsigned int)mft_lcn);
	    log_info("ntfs_find_mft: mftmirr_lcn         %lu\n",(long unsigned int)mftmirr_lcn);
	    if(expert==0
#ifdef HAVE_NCURSES
	      || ask_confirmation("Use MFT from %lu, confirm ? (Y/N)",(long unsigned int)mft_lcn)!=0
#endif
	      )
	      ind_stop=1;
	  }
	  else if(tmp==3)
	  {
	    if(nbr_mft<MAX_INFO_MFT)
	    {
	      info_mft[nbr_mft].sector=sector;
	      info_mft[nbr_mft].mft_lcn=mft_lcn;
	      info_mft[nbr_mft].mftmirr_lcn=mftmirr_lcn;
	      nbr_mft++;
	    }
	  }
	}
      }
    }
  }
  /* Find partition location using MFT information */
  {
    unsigned int i;
    unsigned int j;
    int find_partition=0;
    for(i=0;i<nbr_mft;i++)
    {
      for(j=i+1;j<nbr_mft;j++)
      {
	if(info_mft[i].mft_lcn == info_mft[j].mft_lcn &&
	    info_mft[i].mftmirr_lcn == info_mft[j].mftmirr_lcn &&
	    info_mft[i].mft_lcn != info_mft[i].mftmirr_lcn)
	{
	  const uint64_t diff_mft=(info_mft[i].mft_lcn > info_mft[i].mftmirr_lcn ?
	      info_mft[i].mft_lcn - info_mft[i].mftmirr_lcn:
	      info_mft[i].mftmirr_lcn - info_mft[i].mft_lcn);
	  const uint64_t diff_sector=info_mft[j].sector - info_mft[i].sector;
	  if(diff_sector%diff_mft==0)
	  {
	    const unsigned int sec_per_cluster=diff_sector/diff_mft;
	    const uint64_t tmp=partition->part_offset;
	    partition->part_offset+=(info_mft[i].sector -
		(info_mft[i].mft_lcn < info_mft[i].mftmirr_lcn ? info_mft[i].mft_lcn : info_mft[i].mftmirr_lcn) *
		sec_per_cluster) * disk_car->sector_size;
	    if(find_partition==0)
	      log_info("Potential partition:\n");
	    log_partition(disk_car, partition);
	    find_partition=1;
	    partition->part_offset=tmp;
	  }
	}
      }
    }
  }
#ifdef HAVE_NCURSES
  if(expert>0)
  {
    wmove(stdscr, INTER_NTFS_Y, INTER_NTFS_X);
    sectors_per_cluster=ask_number(sectors_per_cluster,0,512,"Sectors per cluster ");
    wmove(stdscr, INTER_NTFS_Y, INTER_NTFS_X);
    mft_lcn=ask_number(mft_lcn,0,0,"MFT LCN ");
    wmove(stdscr, INTER_NTFS_Y, INTER_NTFS_X);
    mftmirr_lcn=ask_number(mftmirr_lcn,0,0,"MFTMIRR LCN ");
    wmove(stdscr, INTER_NTFS_Y, INTER_NTFS_X);
    mft_record_size=ask_number(mft_record_size,42,4096," mft record size ");
  }
#endif
  /* TODO read_mft_info(partition,sector,*sectors_per_cluster,*mft_lcn,*mftmirr_lcn,*mft_record_size); */
  if(sectors_per_cluster>0 && mft_record_size>=42 && mft_record_size <= sizeof(buffer))
  {
    // 0x90 AT_INDEX_ROOT
    const ntfs_attribheader *attr90;
    unsigned int index_block_size=4096;
    log_info("ntfs_find_mft: sectors_per_cluster %u\n",sectors_per_cluster);
    log_info("ntfs_find_mft: mft_lcn             %lu\n",(long unsigned int)mft_lcn);
    log_info("ntfs_find_mft: mftmirr_lcn         %lu\n",(long unsigned int)mftmirr_lcn);
    log_info("ntfs_find_mft: mft_record_size     %u bytes\n",mft_record_size);
    /* Read "root directory" in MFT */
    if((unsigned)disk_car->pread(disk_car, &buffer, mft_record_size, partition->part_offset + (uint64_t)mft_lcn * sectors_per_cluster * disk_car->sector_size + 5 * (uint64_t)mft_record_size) != mft_record_size)
    {
      display_message("NTFS Can't read \"root directory\" in MFT\n");
      return 1;
    }
    attr90=ntfs_findattribute((const ntfs_recordheader*)buffer, 0x90, buffer+mft_record_size);
    if(attr90 && attr90->bNonResident==0)
    {
      const TD_INDEX_ROOT *index_root=(const TD_INDEX_ROOT *)ntfs_getattributedata((const ntfs_attribresident *)attr90, buffer+mft_record_size);
      if(index_root)
	index_block_size=le32(index_root->index_block_size);
    }
    if(index_block_size%512!=0 || index_block_size==0)
      index_block_size=4096;
    log_info("ntfs_find_mft: index_block_size    %u\n",index_block_size);
    create_ntfs_boot_sector(disk_car,partition, sectors_per_cluster*disk_car->sector_size, mft_lcn, mftmirr_lcn, mft_record_size, index_block_size, expert, current_cmd);
    /* TODO: ask if the user want to continue the search of MFT */
  }
  else
  {
    log_error("Failed to rebuild NTFS boot sector.\n");
  }
  return 0;
}

static int testdisk_ffs(int x)
{
  int r = 1;

  if (!x)
    return 0;
  if (!(x & 0xffff)) {
    x >>= 16;
    r += 16;
  }
  if (!(x & 0xff)) {
    x >>= 8;
    r += 8;
  }
  if (!(x & 0xf)) {
    x >>= 4;
    r += 4;
  }
  if (!(x & 3)) {
    x >>= 2;
    r += 2;
  }
  if (!(x & 1)) {
//  x >>= 1;
    r += 1;
  }
  return r;
}

#ifdef HAVE_NCURSES
static int ncurses_ntfs_info(const struct ntfs_boot_sector *ntfs_header)
{
  wprintw(stdscr,"filesystem size           %llu\n", (long long unsigned)(le64(ntfs_header->sectors_nbr)+1));
  wprintw(stdscr,"sectors_per_cluster       %u\n",ntfs_header->sectors_per_cluster);
  wprintw(stdscr,"mft_lcn                   %lu\n",(long unsigned int)le64(ntfs_header->mft_lcn));
  wprintw(stdscr,"mftmirr_lcn               %lu\n",(long unsigned int)le64(ntfs_header->mftmirr_lcn));
  wprintw(stdscr,"clusters_per_mft_record   %d\n",ntfs_header->clusters_per_mft_record);
  wprintw(stdscr,"clusters_per_index_record %d\n",ntfs_header->clusters_per_index_record);
  return 0;
}

static int ncurses_ntfs2_info(const struct ntfs_boot_sector *nh1, const struct ntfs_boot_sector *nh2)
{
  wprintw(stdscr,"filesystem size           %llu %llu\n",
      (long long unsigned)(le64(nh1->sectors_nbr)+1),
      (long long unsigned)(le64(nh2->sectors_nbr)+1));
  wprintw(stdscr,"sectors_per_cluster       %u %u\n",nh1->sectors_per_cluster,nh2->sectors_per_cluster);
  wprintw(stdscr,"mft_lcn                   %lu %lu\n",
      (long unsigned int)le64(nh1->mft_lcn),
      (long unsigned int)le64(nh2->mft_lcn));
  wprintw(stdscr,"mftmirr_lcn               %lu %lu\n",
      (long unsigned int)le64(nh1->mftmirr_lcn),
      (long unsigned int)le64(nh2->mftmirr_lcn));
  wprintw(stdscr,"clusters_per_mft_record   %d %d\n",nh1->clusters_per_mft_record,nh2->clusters_per_mft_record);
  wprintw(stdscr,"clusters_per_index_record %d %d\n",nh1->clusters_per_index_record,nh2->clusters_per_index_record);
  return 0;
}
#endif

int log_ntfs2_info(const struct ntfs_boot_sector *nh1, const struct ntfs_boot_sector *nh2)
{
  log_info("filesystem size           %llu %llu\n",
      (long long unsigned)(le64(nh1->sectors_nbr)+1),
      (long long unsigned)(le64(nh2->sectors_nbr)+1));
  log_info("sectors_per_cluster       %u %u\n",nh1->sectors_per_cluster,nh2->sectors_per_cluster);
  log_info("mft_lcn                   %lu %lu\n",(long unsigned int)le64(nh1->mft_lcn),(long unsigned int)le64(nh2->mft_lcn));
  log_info("mftmirr_lcn               %lu %lu\n",(long unsigned int)le64(nh1->mftmirr_lcn),(long unsigned int)le64(nh2->mftmirr_lcn));
  log_info("clusters_per_mft_record   %d %d\n",nh1->clusters_per_mft_record,nh2->clusters_per_mft_record);
  log_info("clusters_per_index_record %d %d\n",nh1->clusters_per_index_record,nh2->clusters_per_index_record);
  return 0;
}


