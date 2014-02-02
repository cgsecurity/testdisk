/*

    File: adv.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#include <ctype.h>
#include "types.h"
#include "common.h"
#include "lang.h"
#include "intrf.h"
#include "intrfn.h"
#include "fnctdsk.h"
#include "chgtype.h"
#include "chgtypen.h"
#include "dirpart.h"
#include "fat.h"
#include "ntfs.h"
#include "adv.h"
#include "log.h"
#include "log_part.h"
#include "guid_cmp.h"
#include "dimage.h"
#include "ntfs_udl.h"
#include "ext2_sb.h"
#include "ext2_sbn.h"
#include "fat1x.h"
#include "fat32.h"
#include "texfat.h"
#include "tntfs.h"
#include "thfs.h"
#include "askloc.h"
#include "addpart.h"
#include "addpartn.h"
#include "io_redir.h"

extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_mac;
extern const arch_fnct_t arch_none;
extern const arch_fnct_t arch_sun;
extern const arch_fnct_t arch_xbox;

#ifdef HAVE_NCURSES
#define INTER_ADV_X	0
#define INTER_ADV_Y	(LINES-2)
#define INTER_ADV	(LINES-2-7-1)
#endif

#define DEFAULT_IMAGE_NAME "image.dd"

static int is_exfat(const partition_t *partition);
static int is_hfs(const partition_t *partition);
static int is_hfsp(const partition_t *partition);
static int is_linux(const partition_t *partition);
static int is_part_hfs(const partition_t *partition);
static int is_part_hfsp(const partition_t *partition);

static int is_exfat(const partition_t *partition)
{
  return (is_part_ntfs(partition) || partition->upart_type==UP_EXFAT);
}

static int is_hfs(const partition_t *partition)
{
  return (is_part_hfs(partition) || partition->upart_type==UP_HFS);
}

static int is_hfsp(const partition_t *partition)
{
  return (is_part_hfsp(partition) || partition->upart_type==UP_HFSP || partition->upart_type==UP_HFSX);
}

static int is_linux(const partition_t *partition)
{
  if(is_part_linux(partition))
    return 1;
  switch(partition->upart_type)
  {
    case UP_CRAMFS:
    case UP_EXT2:
    case UP_EXT3:
    case UP_EXT4:
    case UP_JFS:
    case UP_RFS:
    case UP_RFS2:
    case UP_RFS3:
    case UP_RFS4:
    case UP_XFS:
    case UP_XFS2:
    case UP_XFS3:
    case UP_XFS4:
      return 1;
    default:
      break;
  }
  return 0;
}

static int is_part_hfs(const partition_t *partition)
{
  switch(partition->part_type_i386)
  {
    case P_HFS:
      return 1;
  }
  switch(partition->part_type_mac)
  {
    case PMAC_HFS:
      return 1;
  }
  if(guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_MAC_HFS)==0)
    return 1;
  return 0;
}

static int is_part_hfsp(const partition_t *partition)
{
  switch(partition->part_type_i386)
  {
    case P_HFSP:
      return 1;
  }
  switch(partition->part_type_mac)
  {
    case PMAC_HFS:
      return 1;
  }
  if(guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_MAC_HFS)==0)
    return 1;
  return 0;
}

int is_part_linux(const partition_t *partition)
{
  if(partition->arch==&arch_i386)
  {
    if(partition->part_type_i386==P_LINUX)
      return 1;
  }
  else if(partition->arch==&arch_sun)
  {
    if(partition->part_type_sun==PSUN_LINUX)
      return 1;
  }
  else if(partition->arch==&arch_mac)
  {
    if(partition->part_type_mac==PMAC_LINUX)
      return 1;
  }
  /*
  else if(partition->arch==&arch_gpt)
  {
    if(guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_LINUX_DATA)==0)
      return 1;
  }
  */
  return 0;
}

void interface_adv(disk_t *disk_car, const int verbose,const int dump_ind, const unsigned int expert, char**current_cmd)
{
#ifdef HAVE_NCURSES
  int offset=0;
  int current_element_num=0;
  int old_LINES=LINES;
#endif
  int rewrite=1;
  unsigned int menu=0;
  list_part_t *element;
  list_part_t *list_part;
  list_part_t *current_element;
  log_info("\nInterface Advanced\n");
  list_part=disk_car->arch->read_part(disk_car,verbose,0);
  current_element=list_part;
  log_all_partitions(disk_car, list_part);
  while(1)
  {
    const char *options;
    static struct MenuItem menuAdv[]=
    {
      {'t',"Type","Change type, this setting will not be saved on disk"},
      {'b',"Boot","Boot sector recovery"},
      {'s',"Superblock",NULL},
      {'l',"List", "List and copy files"},
      {'u',"Undelete", "File undelete"},
      {'c',"Image Creation", "Create an image"},
//      {'a',"Add", "Add temporary partition (Expert only)"},
      {'q',"Quit","Return to main menu"},
      {0,NULL,NULL}
    };
    int command;
#ifdef HAVE_NCURSES
    int i;
    if(old_LINES!=LINES)
    {
      old_LINES=LINES;
      rewrite=1;
    }
    if(rewrite!=0)
    {
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      if(list_part!=NULL)
	mvwaddstr(stdscr,6,0,msg_PART_HEADER_LONG);
      rewrite=0;
    }
    for(i=0,element=list_part; element!=NULL && i<offset+INTER_ADV;element=element->next,i++)
    {
      if(i<offset)
	continue;
      wmove(stdscr,7+i-offset,0);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      if(element==current_element)
      {
	wattrset(stdscr, A_REVERSE);
	waddstr(stdscr, ">");
	aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,element->part);
	wattroff(stdscr, A_REVERSE);
      } else
      {
	waddstr(stdscr, " ");
	aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,element->part);
      }
    }
    wmove(stdscr,7+INTER_ADV,5);
    wclrtoeol(stdscr);
    if(element!=NULL)
      wprintw(stdscr, "Next");
#endif
    if(current_element==NULL)
    {
      options="q";
#ifdef HAVE_NCURSES
      wmove(stdscr,7,0);
      wattrset(stdscr, A_REVERSE);
      wprintw(stdscr,"No partition available.");
      wattroff(stdscr, A_REVERSE);
#endif
    }
    else
    {
      const partition_t *partition=current_element->part;
      if(menu==0 && (disk_car->arch!=&arch_none || partition->upart_type!=UP_UNK))
	menu=1;
      if(is_part_fat(partition))
      {
	options="tubcq";
	menu=(partition->upart_type==UP_UNK?1:4);
      }
      else if(is_part_ntfs(partition))
	options="tlubcq";
      else if(is_part_linux(partition))
      {
	if(partition->upart_type==UP_EXT2)
	  options="tuscq";
	else
	  options="tlscq";
	menuAdv[2].desc="Locate ext2/ext3/ext4 backup superblock";
      }
      else if(is_part_hfs(partition) || is_part_hfsp(partition))
      {
	options="tscq";
	menuAdv[2].desc="Locate HFS/HFS+ backup volume header";
      }
      else if(is_fat(partition))
	options="tubcq";
      else if(is_ntfs(partition))
	options="tlubcq";
      else if(is_exfat(partition))
	options="tlubcq";
      else if(is_linux(partition))
      {
	if(partition->upart_type==UP_EXT2)
	  options="tluscq";
	else
	  options="tlscq";
	menuAdv[2].desc="Locate ext2/ext3/ext4 backup superblock";
      }
      else if(is_hfs(partition) || is_hfsp(partition))
      {
	options="tscq";
	menuAdv[2].desc="Locate HFS/HFS+ backup volume header";
      }
      else
	options="tcq";
    }
    if(*current_cmd!=NULL)
    {
      int keep_asking;
      command='q';
      do
      {
	keep_asking=0;
	while(*current_cmd[0]==',')
	  (*current_cmd)++;
	if(strncmp(*current_cmd,"type",4)==0)
	{
	  (*current_cmd)+=4;
	  command='t';
	}
	else if(strncmp(*current_cmd,"addpart",7)==0)
	{
	  (*current_cmd)+=7;
	  command='a';
	}
	else if(strncmp(*current_cmd,"boot",4)==0)
	{
	  (*current_cmd)+=4;
	  command='b';
	}
	else if(strncmp(*current_cmd,"copy",4)==0)
	{
	  (*current_cmd)+=4;
	  command='c';
	}
	else if(strncmp(*current_cmd,"list",4)==0)
	{
	  (*current_cmd)+=4;
	  command='l';
	}
	else if(strncmp(*current_cmd,"undelete",8)==0)
	{
	  (*current_cmd)+=8;
	  command='u';
	}
	else if(strncmp(*current_cmd,"superblock",10)==0)
	{
	  (*current_cmd)+=10;
	  command='s';
	}
	else if(isdigit(*current_cmd[0]))
	{
	  const unsigned int order= atoi(*current_cmd);
	  while(*current_cmd[0]!=',' && *current_cmd[0]!='\0')
	    (*current_cmd)++;
	  for(element=list_part;element!=NULL && element->part->order!=order;element=element->next);
	  if(element!=NULL)
	  {
	    current_element=element;
	    keep_asking=1;
	  }
	}
      } while(keep_asking>0);
    }
    else
    {
#ifdef HAVE_NCURSES
      command = wmenuSelect_ext(stdscr, INTER_ADV_Y+1, INTER_ADV_Y, INTER_ADV_X, menuAdv, 8, options,
	  MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, &menu, NULL);
#else
      command = 'q';
#endif
    }
    switch(command)
    {
      case 'q':
      case 'Q':
	part_free_list(list_part);
	return;
#ifdef HAVE_NCURSES
      case 'a':
      case 'A':
	if(disk_car->arch!=&arch_none)
	{
	  if(*current_cmd!=NULL)
	    list_part=add_partition_cli(disk_car, list_part, current_cmd);
	  else
	    list_part=add_partition_ncurses(disk_car, list_part);
	  current_element=list_part;
	  rewrite=1;
	}
	break;
#endif
    }
#ifdef HAVE_NCURSES
    if(current_element!=NULL)
    {
      switch(command)
      {
	case 'p':
	case 'P':
	case KEY_UP:
	  if(current_element->prev!=NULL)
	  {
	    current_element=current_element->prev;
	    current_element_num--;
	  }
	  break;
	case 'n':
	case 'N':
	case KEY_DOWN:
	  if(current_element->next!=NULL)
	  {
	    current_element=current_element->next;
	    current_element_num++;
	  }
	  break;
	case KEY_PPAGE:
	  for(i=0;i<INTER_ADV-1 && current_element->prev!=NULL;i++)
	  {
	    current_element=current_element->prev;
	    current_element_num--;
	  }
	  break;
	case KEY_NPAGE:
	  for(i=0;i<INTER_ADV-1 && current_element->next!=NULL;i++)
	  {
	    current_element=current_element->next;
	    current_element_num++;
	  }
	  break;
	case 'b':
	case 'B':
	  {
	    partition_t *partition=current_element->part;
	    if(is_part_fat32(partition))
	    {
	      fat32_boot_sector(disk_car, partition, verbose, dump_ind, expert,current_cmd);
	      rewrite=1;
	    }
	    else if(is_part_fat12(partition) || is_part_fat16(partition))
	    {
	      fat1x_boot_sector(disk_car, partition, verbose, dump_ind,expert,current_cmd);
	      rewrite=1;
	    }
	    else if(is_part_ntfs(partition))
	    {
	      if(partition->upart_type==UP_EXFAT)
		exFAT_boot_sector(disk_car, partition, verbose, current_cmd);
	      else
		ntfs_boot_sector(disk_car, partition, verbose, expert, current_cmd);
	      rewrite=1;
	    }
	    else if(partition->upart_type==UP_FAT32)
	    {
	      fat32_boot_sector(disk_car, partition, verbose, dump_ind, expert,current_cmd);
	      rewrite=1;
	    }
	    else if(partition->upart_type==UP_FAT12 || partition->upart_type==UP_FAT16)
	    {
	      fat1x_boot_sector(disk_car, partition, verbose, dump_ind,expert,current_cmd);
	      rewrite=1;
	    }
	    else if(partition->upart_type==UP_NTFS)
	    {
	      ntfs_boot_sector(disk_car, partition, verbose, expert, current_cmd);
	      rewrite=1;
	    }
	    else if(partition->upart_type==UP_EXFAT)
	    {
	      exFAT_boot_sector(disk_car, partition, verbose, current_cmd);
	      rewrite=1;
	    }
	  }
	  break;
	case 'c':
	case 'C':
	  {
	    char *dst_path;
#ifdef HAVE_NCURSES
	    if(*current_cmd!=NULL)
	      dst_path=get_default_location();
	    else
	    {
	      char msg[256];
	      snprintf(msg, sizeof(msg),
		  "Please select where to store the file image.dd (%u MB), an image of the partition",
		  (unsigned int)(current_element->part->part_size/1000/1000));
	      dst_path=ask_location(msg, "", NULL);
	    }
#else
	    dst_path=get_default_location();
#endif
	    if(dst_path!=NULL)
	    {
	      char *filename=(char *)MALLOC(strlen(dst_path) + 1 + strlen(DEFAULT_IMAGE_NAME) + 1);
	      strcpy(filename, dst_path);
	      strcat(filename, "/");
	      strcat(filename, DEFAULT_IMAGE_NAME);
	      disk_image(disk_car, current_element->part, filename);
	      free(filename);
	      free(dst_path);
	    }
	  }
	  rewrite=1;
	  break;
	case 'u':
	case 'U':
	  {
	    partition_t *partition=current_element->part;
	    if(partition->sb_offset!=0 && partition->sb_size>0)
	    {
	      io_redir_add_redir(disk_car,
		  partition->part_offset+partition->sborg_offset,
		  partition->sb_size,
		  partition->part_offset+partition->sb_offset,
		  NULL);
	      if(partition->upart_type==UP_NTFS ||
		  (is_part_ntfs(partition) && partition->upart_type!=UP_EXFAT))
		ntfs_undelete_part(disk_car, partition, verbose, current_cmd);
	      else
		dir_partition(disk_car, partition, 0, current_cmd);
	      io_redir_del_redir(disk_car, partition->part_offset+partition->sborg_offset);
	    }
	    else
	    {
	      if(partition->upart_type==UP_NTFS ||
		  (is_part_ntfs(partition) && partition->upart_type!=UP_EXFAT))
		ntfs_undelete_part(disk_car, partition, verbose, current_cmd);
	      else
		dir_partition(disk_car, partition, 0, current_cmd);
	    }
	  }
	  rewrite=1;
	  break;
	case 'l':
	case 'L':
	  {
	    partition_t *partition=current_element->part;
	    if(partition->sb_offset!=0 && partition->sb_size>0)
	    {
	      io_redir_add_redir(disk_car,
		  partition->part_offset+partition->sborg_offset,
		  partition->sb_size,
		  partition->part_offset+partition->sb_offset,
		  NULL);
	      dir_partition(disk_car,partition,verbose, current_cmd);
	      io_redir_del_redir(disk_car, partition->part_offset+partition->sborg_offset);
	    }
	    else
	      dir_partition(disk_car,partition,verbose, current_cmd);
	  }
	  rewrite=1;
	  break;
	case 's':
	case 'S':
	  {
	    if(is_linux(current_element->part))
	    {
	      list_part_t *list_sb=search_superblock(disk_car,current_element->part,verbose,dump_ind,1);
	      interface_superblock(disk_car,list_sb,current_cmd);
	      part_free_list(list_sb);
	    }
	    if(is_hfs(current_element->part) || is_hfsp(current_element->part))
	    {
	      HFS_HFSP_boot_sector(disk_car, current_element->part, verbose, current_cmd);
	    }
	    rewrite=1;
	  }
	  break;
	case 't':
	case 'T':
	  if(*current_cmd!=NULL)
	    change_part_type_cli(disk_car, current_element->part, current_cmd);
	  else
	    change_part_type_ncurses(disk_car, current_element->part);
	  rewrite=1;
	  break;
      }
      if(current_element_num<offset)
	offset=current_element_num;
      if(current_element_num>=offset+INTER_ADV)
	offset=current_element_num-INTER_ADV+1;
    }
#endif
  }
}
