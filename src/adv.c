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
#include <assert.h>
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

static int is_part_hfs(const partition_t *partition)
{
  if( partition->part_type_i386 == P_HFS ||
      partition->part_type_mac  == PMAC_HFS)
    return 1;
  if(guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_MAC_HFS)==0)
    return 1;
  return 0;
}

static int is_part_hfsp(const partition_t *partition)
{
  if( partition->part_type_i386 == P_HFSP ||
      partition->part_type_mac  == PMAC_HFS )
      return 1;
  if(guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_MAC_HFS)==0)
    return 1;
  return 0;
}

int is_part_linux(const partition_t *partition)
{
  if(partition->arch==&arch_i386 && partition->part_type_i386==P_LINUX)
      return 1;
  if(partition->arch==&arch_sun  && partition->part_type_sun==PSUN_LINUX)
      return 1;
  if(partition->arch==&arch_mac  && partition->part_type_mac==PMAC_LINUX)
      return 1;
  if(partition->arch==&arch_gpt &&
      (
       guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_LINUX_DATA)==0 ||
       guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_LINUX_HOME)==0 ||
       guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_LINUX_SRV)==0
      ))
      return 1;
  return 0;
}

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
    case UP_XFS5:
      return 1;
    default:
      break;
  }
  return 0;
}

#ifdef HAVE_NCURSES
static void interface_adv_ncurses(disk_t *disk, const int rewrite, list_part_t *list_part, const list_part_t *current_element, const int offset)
{
  list_part_t *element;
  int i;
  if(rewrite!=0)
  {
    aff_copy(stdscr);
    wmove(stdscr,4,0);
    wprintw(stdscr,"%s",disk->description(disk));
    if(list_part!=NULL)
      mvwaddstr(stdscr,6,0,msg_PART_HEADER_LONG);
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
      aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk,element->part);
      wattroff(stdscr, A_REVERSE);
    } else
    {
      waddstr(stdscr, " ");
      aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk,element->part);
    }
  }
  wmove(stdscr,7+INTER_ADV,5);
  wclrtoeol(stdscr);
  if(element!=NULL)
    wprintw(stdscr, "Next");
  if(current_element==NULL)
  {
    wmove(stdscr,7,0);
    wattrset(stdscr, A_REVERSE);
    wprintw(stdscr,"No partition available.");
    wattroff(stdscr, A_REVERSE);
  }
}
#endif

static int adv_string_to_command(char**current_cmd, list_part_t **current_element, list_part_t *list_part)
{
  int keep_asking;
  int command='q';
  assert(current_cmd!=NULL);
  do
  {
    keep_asking=0;
    skip_comma_in_command(current_cmd);
    if(check_command(current_cmd,"type",4)==0)
    {
      command='t';
    }
    else if(check_command(current_cmd,"addpart",7)==0)
    {
      command='a';
    }
    else if(check_command(current_cmd,"boot",4)==0)
    {
      command='b';
    }
    else if(check_command(current_cmd,"copy",4)==0)
    {
      command='c';
    }
    else if(check_command(current_cmd,"list",4)==0)
    {
      command='l';
    }
    else if(check_command(current_cmd,"undelete",8)==0)
    {
      command='u';
    }
    else if(check_command(current_cmd,"superblock",10)==0)
    {
      command='s';
    }
    else if(isdigit(*current_cmd[0]))
    {
      list_part_t *element;
      const unsigned int order= get_int_from_command(current_cmd);
      for(element=list_part;
	  element!=NULL && element->part->order!=order;
	  element=element->next);
      if(element!=NULL)
      {
	*current_element=element;
	keep_asking=1;
      }
    }
  } while(keep_asking>0);
  return command;
}

#ifdef HAVE_NCURSES
static const char *adv_get_boot_description(const partition_t *partition)
{
  assert(partition!=NULL);
  if(is_part_linux(partition))
  {
    return "Locate ext2/ext3/ext4 backup superblock";
  }
  else if(is_part_hfs(partition) || is_part_hfsp(partition))
  {
    return "Locate HFS/HFS+ backup volume header";
  }
  else if(is_linux(partition))
  {
    return "Locate ext2/ext3/ext4 backup superblock";
  }
  else if(is_hfs(partition) || is_hfsp(partition))
  {
    return "Locate HFS/HFS+ backup volume header";
  }
  return "Boot sector recovery";
}

static const char *adv_get_options_for_partition(const partition_t *partition)
{
  if(is_part_fat(partition))
  {
    return "tubcq";
  }
  else if(is_part_ntfs(partition))
    return "tlubcq";
  else if(is_part_linux(partition))
  {
    if(partition->upart_type==UP_EXT2)
      return "tuscq";
    else
      return "tlscq";
  }
  else if(is_part_hfs(partition) || is_part_hfsp(partition))
  {
    return "tscq";
  }
  else if(is_fat(partition))
    return "tubcq";
  else if(is_ntfs(partition) || is_exfat(partition))
    return "tlubcq";
  else if(is_linux(partition))
  {
    if(partition->upart_type==UP_EXT2)
      return "tluscq";
    else
      return "tlscq";
  }
  else if(is_hfs(partition) || is_hfsp(partition))
  {
    return "tscq";
  }
  return "tcq";
}
#endif

static int adv_menu_boot_selected(disk_t *disk, partition_t *partition, const int verbose,const int dump_ind, const unsigned int expert, char**current_cmd)
{
  if(is_part_fat32(partition))
  {
    fat32_boot_sector(disk, partition, verbose, dump_ind, expert,current_cmd);
    return 1;
  }
  else if(is_part_fat12(partition) || is_part_fat16(partition))
  {
    fat1x_boot_sector(disk, partition, verbose, dump_ind,expert,current_cmd);
    return 1;
  }
  else if(is_part_ntfs(partition))
  {
    if(partition->upart_type==UP_EXFAT)
      exFAT_boot_sector(disk, partition, current_cmd);
    else
      ntfs_boot_sector(disk, partition, verbose, expert, current_cmd);
    return 1;
  }
  else if(partition->upart_type==UP_FAT32)
  {
    fat32_boot_sector(disk, partition, verbose, dump_ind, expert,current_cmd);
    return 1;
  }
  else if(partition->upart_type==UP_FAT12 || partition->upart_type==UP_FAT16)
  {
    fat1x_boot_sector(disk, partition, verbose, dump_ind,expert,current_cmd);
    return 1;
  }
  else if(partition->upart_type==UP_NTFS)
  {
    ntfs_boot_sector(disk, partition, verbose, expert, current_cmd);
    return 1;
  }
  else if(partition->upart_type==UP_EXFAT)
  {
    exFAT_boot_sector(disk, partition, current_cmd);
    return 1;
  }
  return 0;
}

static void adv_menu_image_selected(disk_t *disk, const partition_t *partition, char **current_cmd)
{
  char dst_path[4096];
  dst_path[0]='\0';
#ifdef HAVE_NCURSES
  if(*current_cmd!=NULL)
    td_getcwd(dst_path, sizeof(dst_path));
  else
  {
    char msg[256];
    snprintf(msg, sizeof(msg),
	"Please select where to store the file image.dd (%u MB), an image of the partition",
	(unsigned int)(partition->part_size/1000/1000));
    ask_location(dst_path, sizeof(dst_path), msg, "");
  }
#else
  td_getcwd(&dst_path, sizeof(dst_path));
#endif
  if(dst_path[0]!='\0')
  {
    char *filename=(char *)MALLOC(strlen(dst_path) + 1 + strlen(DEFAULT_IMAGE_NAME) + 1);
    strcpy(filename, dst_path);
    strcat(filename, "/");
    strcat(filename, DEFAULT_IMAGE_NAME);
    disk_image(disk, partition, filename);
    free(filename);
  }
}

static void adv_menu_undelete_selected(disk_t *disk, const partition_t *partition, const int verbose, char **current_cmd)
{
  if(partition->sb_offset!=0 && partition->sb_size>0)
  {
    io_redir_add_redir(disk,
	partition->part_offset+partition->sborg_offset,
	partition->sb_size,
	partition->part_offset+partition->sb_offset,
	NULL);
    if(partition->upart_type==UP_NTFS ||
	(is_part_ntfs(partition) && partition->upart_type!=UP_EXFAT))
      ntfs_undelete_part(disk, partition, verbose, current_cmd);
    else
      dir_partition(disk, partition, 0, 0, current_cmd);
    io_redir_del_redir(disk, partition->part_offset+partition->sborg_offset);
  }
  else
  {
    if(partition->upart_type==UP_NTFS ||
	(is_part_ntfs(partition) && partition->upart_type!=UP_EXFAT))
      ntfs_undelete_part(disk, partition, verbose, current_cmd);
    else
      dir_partition(disk, partition, 0, 0, current_cmd);
  }
}

static void adv_menu_list_selected(disk_t *disk, const partition_t *partition, const int verbose, const int expert, char **current_cmd)
{
  if(partition->sb_offset!=0 && partition->sb_size>0)
  {
    io_redir_add_redir(disk,
	partition->part_offset+partition->sborg_offset,
	partition->sb_size,
	partition->part_offset+partition->sb_offset,
	NULL);
    dir_partition(disk,partition, verbose, expert, current_cmd);
    io_redir_del_redir(disk, partition->part_offset+partition->sborg_offset);
  }
  else
    dir_partition(disk, partition, verbose, expert, current_cmd);
}

static void adv_menu_superblock_selected(disk_t *disk, partition_t *partition, const int verbose,const int dump_ind, char**current_cmd)
{
  if(is_linux(partition))
  {
    list_part_t *list_sb=search_superblock(disk,partition,verbose,dump_ind);
    interface_superblock(disk, list_sb, current_cmd);
    part_free_list(list_sb);
  }
  if(is_hfs(partition) || is_hfsp(partition))
  {
    HFS_HFSP_boot_sector(disk, partition, verbose, current_cmd);
  }
}

void interface_adv(disk_t *disk_car, const int verbose,const int dump_ind, const unsigned int expert, char**current_cmd)
{
  int current_element_num=0;
#ifdef HAVE_NCURSES
  int offset=0;
#endif
  int rewrite=1;
  unsigned int menu=0;
  list_part_t *list_part;
  list_part_t *current_element;
  assert(current_cmd!=NULL);
  log_info("\nInterface Advanced\n");
  list_part=disk_car->arch->read_part(disk_car,verbose,0);
  /*@ assert valid_list_part(list_part); */
  current_element=list_part;
  log_all_partitions(disk_car, list_part);
  while(1)
  {
    int command;
#ifdef HAVE_NCURSES
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
    const char *options;
    int old_LINES=LINES;
    interface_adv_ncurses(disk_car, rewrite, list_part, current_element, offset);
#endif
    rewrite=0;
    if(current_element==NULL)
    {
#ifdef HAVE_NCURSES
      options="q";
#endif
    }
    else
    {
      if(menu==0 && (disk_car->arch!=&arch_none || current_element->part->upart_type!=UP_UNK))
	menu=1;
#ifdef HAVE_NCURSES
      options=adv_get_options_for_partition(current_element->part);
      menuAdv[2].desc=adv_get_boot_description(current_element->part);
#endif
    }
    if(*current_cmd!=NULL)
    {
      command=adv_string_to_command(current_cmd, &current_element, list_part);
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
      case 'a':
      case 'A':
	if(disk_car->arch!=&arch_none)
	{
	  if(*current_cmd!=NULL)
	    list_part=add_partition_cli(disk_car, list_part, current_cmd);
#ifdef HAVE_NCURSES
	  else
	    list_part=add_partition_ncurses(disk_car, list_part);
#endif
	  current_element=list_part;
	  rewrite=1;
	}
	break;
    }
    if(current_element!=NULL)
    {
      switch(command)
      {
	case 'p':
	case 'P':
#ifdef KEY_UP
	case KEY_UP:
#endif
	  if(current_element->prev!=NULL)
	  {
	    current_element=current_element->prev;
	    current_element_num--;
	  }
	  break;
	case 'n':
	case 'N':
#ifdef KEY_DOWN
	case KEY_DOWN:
#endif
	  if(current_element->next!=NULL)
	  {
	    current_element=current_element->next;
	    current_element_num++;
	  }
	  break;
#ifdef KEY_PPAGE
	case KEY_PPAGE:
	  {
	    int i;
	    for(i=0;i<INTER_ADV-1 && current_element->prev!=NULL;i++)
	    {
	      current_element=current_element->prev;
	      current_element_num--;
	    }
	  }
	  break;
#endif
#ifdef KEY_NPAGE
	case KEY_NPAGE:
	  {
	    int i;
	    for(i=0;i<INTER_ADV-1 && current_element->next!=NULL;i++)
	    {
	      current_element=current_element->next;
	      current_element_num++;
	    }
	  }
	  break;
#endif
	case 'b':
	case 'B':
	  rewrite=adv_menu_boot_selected(disk_car, current_element->part, verbose, dump_ind, expert, current_cmd);
	  break;
	case 'c':
	case 'C':
	  adv_menu_image_selected(disk_car, current_element->part, current_cmd);
	  rewrite=1;
	  break;
	case 'u':
	case 'U':
	  adv_menu_undelete_selected(disk_car, current_element->part, verbose, current_cmd);
	  rewrite=1;
	  break;
	case 'l':
	case 'L':
	  adv_menu_list_selected(disk_car, current_element->part, verbose, expert, current_cmd);
	  rewrite=1;
	  break;
	case 's':
	case 'S':
	  adv_menu_superblock_selected(disk_car, current_element->part, verbose, dump_ind, current_cmd);
	  rewrite=1;
	  break;
	case 't':
	case 'T':
	  if(*current_cmd!=NULL)
	    change_part_type_cli(disk_car, current_element->part, current_cmd);
#ifdef HAVE_NCURSES
	  else
	    change_part_type_ncurses(disk_car, current_element->part);
#endif
	  rewrite=1;
	  break;
      }
#ifdef HAVE_NCURSES
      if(current_element_num<offset)
	offset=current_element_num;
      if(current_element_num>=offset+INTER_ADV)
	offset=current_element_num-INTER_ADV+1;
#endif
    }
#ifdef HAVE_NCURSES
    if(old_LINES!=LINES)
      rewrite=1;
#endif
  }
}
