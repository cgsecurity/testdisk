/*

    File: adv.c

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
 
#include <stdarg.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>
#include "types.h"
#include "common.h"
#include "lang.h"
#include "intrf.h"
#include "intrfn.h"
#include "fnctdsk.h"
#include "chgtype.h"
#include "testdisk.h"
#include "dirpart.h"
#include "fat.h"
#include "ntfs.h"
#include "hfs.h"
#include "hfsp.h"
#include "adv.h"
#include "analyse.h"
#include "intrface.h"
#include "io_redir.h"
#include "log.h"
#include "guid_cmp.h"
#include "dimage.h"
#include "fat_adv.h"

extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_mac;
extern const arch_fnct_t arch_none;
extern const arch_fnct_t arch_sun;
extern const arch_fnct_t arch_xbox;

#define INTER_ADV_X	0
#define INTER_ADV_Y	23
#define INTER_ADV	15
#define DEFAULT_IMAGE_NAME "image.dd"

static int is_hfs(const partition_t *partition);
static int is_hfsp(const partition_t *partition);
static int is_linux(const partition_t *partition);
static int is_part_hfs(const partition_t *partition);
static int is_part_hfsp(const partition_t *partition);

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
  int quit;
  int offset=0;
  int current_element_num=0;
  int rewrite=1;
  const char *options;
  list_part_t *element;
  list_part_t *list_part;
  list_part_t *current_element;
  log_info("\nInterface Advanced\n");
  list_part=disk_car->arch->read_part(disk_car,verbose,0);
  current_element=list_part;
  for(element=list_part;element!=NULL;element=element->next)
  {
    log_partition(disk_car,element->part);
  }
  do
  {
    static struct MenuItem menuAdv[]=
    {
      {'t',"Type","Change type, this setting will not be saved on disk"},
      {'b',"Boot","Boot sector recovery"},
      {'s',"Superblock",NULL},
      {'c',"Image Creation", "Create an image"},
//      {'a',"Add", "Add temporary partition (Expert only)"},
      {'q',"Quit","Return to main menu"},
      {0,NULL,NULL}
    };
    int menu=0;
    int i;
    int command;
#ifdef HAVE_NCURSES
    if(rewrite!=0)
    {
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      if(list_part!=NULL)
	mvwaddstr(stdscr,6,0,msg_PART_HEADER_LONG);
      rewrite=0;
    }
    for(i=0,element=list_part;(element!=NULL) && (i<offset);element=element->next,i++);
    for(i=offset;(element!=NULL) && ((i-offset)<INTER_ADV);element=element->next,i++)
    {
      wmove(stdscr,5+2+i-offset,0);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      if(element==current_element)
      {
	wattrset(stdscr, A_REVERSE);
	aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,element->part);
	wattroff(stdscr, A_REVERSE);
      } else
      {
	aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,element->part);
      }
    }
#endif
    menu=0;
    if(current_element==NULL)
    {
      options="q";
#ifdef HAVE_NCURSES
      wmove(stdscr,5+2,0);
      wattrset(stdscr, A_REVERSE);
      wprintw(stdscr,"No partition available.");
      wattroff(stdscr, A_REVERSE);
#endif
    }
    else
    {
      if(is_part_fat(current_element->part) ||
	  is_part_ntfs(current_element->part))
      {
	options="tbcq";
	menu=1;
      }
      else if(is_part_linux(current_element->part))
      {
	options="tscq";
	menuAdv[2].desc="Locate EXT2/EXT3 backup superblock";
	menu=1;
      }
      else if(is_part_hfs(current_element->part) || is_part_hfsp(current_element->part))
      {
	options="tscq";
	menuAdv[2].desc="Locate HFS/HFS+ backup volume header";
	menu=1;
      }
      else if(is_fat(current_element->part) ||
	  is_ntfs(current_element->part))
      {
	options="tbcq";
	menu=1;
      }
      else if(is_linux(current_element->part))
      {
	options="tscq";
	menuAdv[2].desc="Locate EXT2/EXT3 backup superblock";
	menu=1;
      }
      else if(is_hfs(current_element->part) || is_hfsp(current_element->part))
      {
	options="tscq";
	menuAdv[2].desc="Locate HFS/HFS+ backup volume header";
	menu=1;
      }
      else
	options="tcq";
    }
    quit=0;
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
	else if(strncmp(*current_cmd,"superblock",10)==0)
	{
	  (*current_cmd)+=10;
	  command='s';
	}
	else
	{
	  unsigned int order;
	  order= atoi(*current_cmd);
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
      command = wmenuSelect(stdscr, 24, INTER_ADV_Y, INTER_ADV_X, menuAdv, 8, options,
	  MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, menu);
#else
      command = 'q';
#endif
    }
    switch(command)
    {
#ifdef HAVE_NCURSES
      case KEY_UP:
	if(current_element!=NULL)
	{
	  if(current_element->prev!=NULL)
	  {
	    current_element=current_element->prev;
	    current_element_num--;
	  }
	  if(current_element_num<offset)
	    offset--;
	}
	break;
      case KEY_DOWN:
	if(current_element!=NULL)
	{
	  if(current_element->next!=NULL)
	  {
	    current_element=current_element->next;
	    current_element_num++;
	  }
	  if(current_element_num>=offset+INTER_ADV)
	    offset++;
	}
	break;
#endif
      case 'q':
      case 'Q':
	quit=1;
	break;
      case 'a':
      case 'A':
	if(disk_car->arch->add_partition!=NULL)
	{
	  list_part=disk_car->arch->add_partition(disk_car,list_part, verbose, current_cmd);
	  current_element=list_part;
	  rewrite=1;
	}
	break;
      case 'b':
      case 'B':
	if(current_element!=NULL)
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
	    ntfs_boot_sector(disk_car, partition, verbose, dump_ind, expert, current_cmd);
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
	    ntfs_boot_sector(disk_car, partition, verbose, dump_ind, expert, current_cmd);
	    rewrite=1;
	  }
	}
	break;
      case 'c':
      case 'C':
	if(current_element!=NULL)
	{
	  char *image_dd;
	  menu=0;
	  image_dd=ask_location("Do you want to save disk file image.dd in %s%s ? [Y/N]","");
	  if(image_dd!=NULL)
	  {
	    char *new_recup_dir=MALLOC(strlen(image_dd)+1+strlen(DEFAULT_IMAGE_NAME)+1);
	    strcpy(new_recup_dir,image_dd);
	    strcat(new_recup_dir,"/");
	    strcat(new_recup_dir,DEFAULT_IMAGE_NAME);
	    free(image_dd);
	    image_dd=new_recup_dir;
	  }
	  if(image_dd!=NULL)
	  {
	    disk_image(disk_car, current_element->part, image_dd);
	    free(image_dd);
	  }
	}
	break;
      case 'l':
      case 'L':
	if(current_element!=NULL)
	{
	  dir_partition(disk_car, current_element->part, 0, current_cmd);
	}
	break;
      case 's':
      case 'S':
	if(current_element!=NULL)
	{
	  if(is_linux(current_element->part))
	  {
	    list_part_t *list_sb=search_superblock(disk_car,current_element->part,verbose,dump_ind,1);
	    interface_superblock(disk_car,list_sb,current_cmd);
	    part_free_list(list_sb);
	  }
	  if(is_hfs(current_element->part) || is_hfsp(current_element->part))
	  {
	    HFS_HFSP_boot_sector(disk_car, current_element->part, verbose, dump_ind, expert, current_cmd);
	  }
	  rewrite=1;
	}
	break;
      case 't':
      case 'T':
	if(current_element!=NULL)
	{
	  change_part_type(disk_car,current_element->part, current_cmd);
	  rewrite=1;
	}
	break;
    }
  } while(quit==0);
  part_free_list(list_part);
}

#ifdef HAVE_NCURSES
static void dump_fat1x_ncurses(disk_t *disk_car, partition_t *partition, const unsigned char *buffer_bs)
{
  WINDOW *window=newwin(0,0,0,0);	/* full screen */
  keypad(window, TRUE); /* Need it to get arrow key */
  aff_copy(window);
  wmove(window,4,0);
  wprintw(window,"%s",disk_car->description(disk_car));
  wmove(window,5,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  mvwaddstr(window,6,0, "Boot sector");
  dump(window,buffer_bs,FAT1x_BOOT_SECTOR_SIZE);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
}
#endif

static void dump_fat1x(disk_t *disk_car, partition_t *partition, const unsigned char *buffer_bs)
{
  log_info("Boot sector\n");
  dump_log(buffer_bs, FAT1x_BOOT_SECTOR_SIZE);
#ifdef HAVE_NCURSES
  dump_fat1x_ncurses(disk_car, partition, buffer_bs);
#endif
}

int fat1x_boot_sector(disk_t *disk_car, partition_t *partition, const int verbose, const int dump_ind, const unsigned int expert, char **current_cmd)
{
  unsigned char *buffer_bs;
  const char *options="DR";
  int rescan=1;
  struct MenuItem menu_fat1x[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Quit","Return to Advanced menu"},
    { 'L', "List", "List directories and files, copy and undelete data from FAT" },
    { 'R', "Rebuild BS","Rebuild boot sector"},
    { 'D', "Dump","Dump boot sector and backup boot sector"},
    { 'C', "Repair FAT","Very Dangerous! Expert only"},
    { 'I', "Init Root","Init root directory: Very Dangerous! Expert only"},
    { 0, NULL, NULL }
  };
  buffer_bs=(unsigned char*)MALLOC(FAT1x_BOOT_SECTOR_SIZE);
  while(1)
  {
    unsigned int menu=0;
    int command;
    screen_buffer_reset();
    if(rescan==1)
    {
#ifdef HAVE_NCURSES
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
      wmove(stdscr,6,0);
      aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
#endif
      log_info("\nfat1x_boot_sector\n");
      log_partition(disk_car,partition);
      screen_buffer_add("Boot sector\n");
      if(disk_car->read(disk_car,FAT1x_BOOT_SECTOR_SIZE, buffer_bs, partition->part_offset)!=0)
      {
	screen_buffer_add("fat1x_boot_sector: Can't read boot sector.\n");
	memset(buffer_bs,0,FAT1x_BOOT_SECTOR_SIZE);
      }
      if(test_FAT(disk_car,(const struct fat_boot_sector *)buffer_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("OK\n");
	if(expert==0)
	  options="DRCL";
	else
	  options="DRCIL";
      }
      else
      {
	screen_buffer_add("Bad\n");
	options="DRC";
      }
      screen_buffer_add("\n");
      screen_buffer_add("A valid FAT Boot sector must be present in order to access\n");
      screen_buffer_add("any data; even if the partition is not bootable.\n");
      rescan=0;
    }
    screen_buffer_to_log();
    if(*current_cmd!=NULL)
    {
      command=0;
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(strncmp(*current_cmd,"rebuildbs",9)==0)
      {
	(*current_cmd)+=9;
	command='R';
      }
      else if(strncmp(*current_cmd,"dump",4)==0)
      {
	(*current_cmd)+=4;
	command='D';
      }
      else if(strncmp(*current_cmd,"list",4)==0)
      {
	(*current_cmd)+=4;
	if(strchr(options,'L')!=NULL)
	  command='L';
      }
      else if(strncmp(*current_cmd,"repairfat",8)==0)
      {
	(*current_cmd)+=8;
	if(strchr(options,'C')!=NULL)
	  command='C';
      }
      else if(strncmp(*current_cmd,"initroot",8)==0)
      {
	(*current_cmd)+=8;
	if(strchr(options,'I')!=NULL)
	    command='I';
      }
    }
    else
    {
      log_flush();
#ifdef HAVE_NCURSES
      command=screen_buffer_display_ext(stdscr, options, menu_fat1x, &menu);
#else
      command=0;
#endif
    }
    switch(command)
    {
      case 0:
	free(buffer_bs);
	return 0;
      case 'R': /* R : rebuild boot sector */
	rebuild_FAT_BS(disk_car,partition,verbose,dump_ind,1,expert,current_cmd);
	rescan=1;
	break;
      case 'D':
	dump_fat1x(disk_car, partition, buffer_bs);
	break;
      case 'C':
	repair_FAT_table(disk_car,partition,verbose);
	break;
      case 'I':
	FAT_init_rootdir(disk_car,partition,verbose);
	break;
      case 'L':
	dir_partition(disk_car, partition, 0,current_cmd);
	break;
    }
  }
}

#ifdef HAVE_NCURSES
static void dump_fat32_ncurses(disk_t *disk_car, const partition_t *partition, const unsigned char *buffer_bs, const unsigned char *buffer_backup_bs)
{
  WINDOW *window=newwin(0,0,0,0);	/* full screen */
  keypad(window, TRUE); /* Need it to get arrow key */
  aff_copy(window);
  wmove(window,4,0);
  wprintw(window,"%s",disk_car->description(disk_car));
  wmove(window,5,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  mvwaddstr(window,6,0, "Boot sector                        Backup boot sector");
  dump2(window, buffer_bs, buffer_backup_bs, 3*disk_car->sector_size);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
}
#endif

static void dump_fat32(disk_t *disk_car, const partition_t *partition, const unsigned char *buffer_bs, const unsigned char *buffer_backup_bs)
{
  log_info("Boot sector                        Backup boot sector\n");
  dump2_log(buffer_bs, buffer_backup_bs, 3*disk_car->sector_size);
  log_fat2_info((const struct fat_boot_sector*)buffer_bs,(const struct fat_boot_sector*)buffer_backup_bs,UP_FAT32,disk_car->sector_size);
#ifdef HAVE_NCURSES
  dump_fat32_ncurses(disk_car, partition, buffer_bs, buffer_backup_bs);
#endif
}

int fat32_boot_sector(disk_t *disk_car, partition_t *partition, const int verbose, const int dump_ind, const unsigned int expert, char **current_cmd)
{
  unsigned char *buffer_bs;
  unsigned char *buffer_backup_bs;
  const char *options="DRC";
  int rescan=1;
  struct MenuItem menu_fat32[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Quit","Return to Advanced menu"},
    { 'L', "List", "List directories and files, copy and undelete data from FAT" },
    { 'O', "Org. BS","Copy boot sector over backup sector"},
    { 'B', "Backup BS","Copy backup boot sector over boot sector"},
    { 'R', "Rebuild BS","Rebuild boot sector"},
    { 'D', "Dump","Dump boot sector and backup boot sector"},
    { 'C', "Repair FAT","Very Dangerous! Expert only"},
    { 0, NULL, NULL }
  };
  buffer_bs=(unsigned char*)MALLOC(3*disk_car->sector_size);
  buffer_backup_bs=(unsigned char*)MALLOC(3*disk_car->sector_size);
  while(1)
  {
    unsigned int menu=0;
    int command;
    screen_buffer_reset();
    if(rescan==1)
    {
      int opt_over=0;
      int opt_B=0;
      int opt_O=0;
      options="DRC";
#ifdef HAVE_NCURSES
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
      wmove(stdscr,6,0);
      aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
#endif
      log_info("\nfat32_boot_sector\n");
      log_partition(disk_car,partition);
      screen_buffer_add("Boot sector\n");
      if(disk_car->read(disk_car,3*disk_car->sector_size, buffer_bs, partition->part_offset)!=0)
      {
	screen_buffer_add("fat32_boot_sector: Can't read boot sector.\n");
	memset(buffer_bs,0,3*disk_car->sector_size);
      }
      if(test_FAT(disk_car,(struct fat_boot_sector *)buffer_bs,partition,verbose,0)==0)
      {
        screen_buffer_add("OK\n");
        if(partition->upart_type==UP_FAT32)
        {
          opt_O=1;
          opt_over=1;
        }
        else
        {
          screen_buffer_add("Warning: valid FAT bootsector but not a FAT32 one!");
        }
      }
      else
      {
        screen_buffer_add("Bad\n");
      }
      screen_buffer_add("\nBackup boot sector\n");
      if(disk_car->read(disk_car,3*disk_car->sector_size, buffer_backup_bs, partition->part_offset+6*disk_car->sector_size)!=0)
      {
	screen_buffer_add("fat32_boot_sector: Can't read backup boot sector.\n");
	memset(buffer_backup_bs,0,3*disk_car->sector_size);
      }
      if(test_FAT(disk_car,(struct fat_boot_sector *)buffer_backup_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("OK\n");
	if(partition->upart_type==UP_FAT32)
	{
	  opt_B=1;
	  opt_over=1;
	}
	else
	{
	  screen_buffer_add("Warning: valid FAT backup bootsector but not a FAT32 one!");
	}
      }
      else
      {
        screen_buffer_add("Bad\n");
      }
      screen_buffer_add("\n");
      if((memcmp(buffer_bs,buffer_backup_bs,0x3E8)==0)&&(memcmp(buffer_bs+0x3F0,buffer_backup_bs+0x3F0,0x600-0x3F0))==0)
      {
	screen_buffer_add("Sectors are identical.\n");
	opt_over=0;
      }
      else
      {
	if(memcmp(buffer_bs,buffer_backup_bs,0x200)!=0)
	  screen_buffer_add("First sectors (Boot code and partition information) are not identical.\n");
	if((memcmp(buffer_bs+disk_car->sector_size, buffer_backup_bs+disk_car->sector_size,0x1E8)!=0)||
	    (memcmp(buffer_bs+disk_car->sector_size+0x1F0, buffer_backup_bs+disk_car->sector_size+0x1F0,0x200-0x1F0)!=0))
	  screen_buffer_add("Second sectors (cluster information) are not identical.\n");
	if(memcmp(buffer_bs+2*disk_car->sector_size, buffer_backup_bs+2*disk_car->sector_size,0x200)!=0)
	  screen_buffer_add("Third sectors (Second part of boot code) are not identical.\n");
      }
      screen_buffer_add("\n");
      screen_buffer_add("A valid FAT Boot sector must be present in order to access\n");
      screen_buffer_add("any data; even if the partition is not bootable.\n");
      if(opt_over!=0)
      {
	if(opt_B!=0 && opt_O!=0)
	  options="DOBRL";
	else if(opt_B!=0)
	{
	  menu=5;
	  options="DBRL";
	}
	else if(opt_O!=0)
	{
	  menu=4;
	  options="DORL";
	}
      }
      else
      {
	if(opt_B!=0)
	  options="DRCL";
	else
	  options="DR";
      }
      rescan=0;
    }
    screen_buffer_to_log();
    if(*current_cmd!=NULL)
    {
      command=0;
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(strncmp(*current_cmd,"rebuildbs",9)==0)
      {
	(*current_cmd)+=9;
	command='R';
      }
      else if(strncmp(*current_cmd,"dump",4)==0)
      {
	(*current_cmd)+=4;
	command='D';
      }
      else if(strncmp(*current_cmd,"list",4)==0)
      {
	(*current_cmd)+=4;
	if(strchr(options,'L')!=NULL)
	  command='L';
      }
      else if(strncmp(*current_cmd,"repairfat",8)==0)
      {
	(*current_cmd)+=8;
	if(strchr(options,'C')!=NULL)
	  command='C';
      }
      else if(strncmp(*current_cmd,"originalfat",11)==0)
      {
	(*current_cmd)+=11;
	if(strchr(options,'O')!=NULL)
	    command='O';
      }
      else if(strncmp(*current_cmd,"backupfat",9)==0)
      {
	(*current_cmd)+=9;
	if(strchr(options,'B')!=NULL)
	    command='B';
      }
    }
    else
    {
      log_flush();
#ifdef HAVE_NCURSES
      command=screen_buffer_display_ext(stdscr, options, menu_fat32, &menu);
#else
      command=0;
#endif
    }
    switch(command)
    {
      case 0:
	free(buffer_bs);
	free(buffer_backup_bs);
	return 0;
      case 'O': /* O : copy original boot sector over backup boot */
	if(ask_confirmation("Copy original FAT32 boot sector over backup boot, confirm ? (Y/N)")!=0)
	{
	  log_info("copy original boot sector over backup boot\n");
	  if(disk_car->write(disk_car,3*disk_car->sector_size, buffer_bs, partition->part_offset+6*disk_car->sector_size)!=0)
	  {
	    display_message("Write error: Can't overwrite FAT32 backup boot sector\n");
	  }
          disk_car->sync(disk_car);
	  rescan=1;
	}
	break;
      case 'B': /* B : copy backup boot sector over boot sector */
	if(ask_confirmation("Copy backup FAT32 boot sector over boot sector, confirm ? (Y/N)")!=0)
	{
	  log_info("copy backup boot sector over boot sector\n");
	  if(disk_car->write(disk_car,3*disk_car->sector_size, buffer_backup_bs, partition->part_offset)!=0)
	  {
	    display_message("Write error: Can't overwrite FAT32 boot sector\n");
	  }
          disk_car->sync(disk_car);
	  rescan=1;
	}
	break;
      case 'C':
	repair_FAT_table(disk_car,partition,verbose);
	break;
      case 'D':
	dump_fat32(disk_car, partition, buffer_bs, buffer_backup_bs);
	break;
      case 'L':
	if(strchr(options,'O')==NULL && strchr(options,'B')!=NULL)
	{
	  io_redir_add_redir(disk_car,partition->part_offset,3*disk_car->sector_size,0,buffer_backup_bs);
	  dir_partition(disk_car, partition, 0,current_cmd);
	  io_redir_del_redir(disk_car,partition->part_offset);
	}
	else
	  dir_partition(disk_car, partition, 0,current_cmd);
	break;
      case 'R': /* R : rebuild boot sector */
	rebuild_FAT_BS(disk_car,partition,verbose,dump_ind,1,expert,current_cmd);
	rescan=1;
	break;
    }
  }
}

#ifdef HAVE_NCURSES
static void dump_NTFS_ncurses(disk_t *disk_car, const partition_t *partition, const unsigned char *buffer_bs, const unsigned char *buffer_backup_bs)
{
  WINDOW *window=newwin(0,0,0,0);	/* full screen */
  keypad(window, TRUE); /* Need it to get arrow key */
  aff_copy(window);
  wmove(window,4,0);
  wprintw(window,"%s",disk_car->description(disk_car));
  wmove(window,5,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  mvwaddstr(window,6,0, "Boot sector                        Backup boot sector");
  dump2(window, buffer_bs, buffer_backup_bs, NTFS_BOOT_SECTOR_SIZE);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
}
#endif

static void dump_NTFS(disk_t *disk_car, const partition_t *partition, const unsigned char *buffer_bs, const unsigned char *buffer_backup_bs)
{
  log_info("Boot sector                        Backup boot sector\n");
  dump2_log(buffer_bs, buffer_backup_bs, NTFS_BOOT_SECTOR_SIZE);
#ifdef HAVE_NCURSES
  dump_NTFS_ncurses(disk_car, partition, buffer_bs, buffer_backup_bs);
#endif
}

int ntfs_boot_sector(disk_t *disk_car, partition_t *partition, const int verbose, const int dump_ind, const unsigned int expert, char **current_cmd)
{
  unsigned char *buffer_bs;
  unsigned char *buffer_backup_bs;
  const char *options="";
  int rescan=1;
  struct MenuItem menu_ntfs[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Quit","Return to Advanced menu"},
    { 'L', "List", "List directories and files, copy data from NTFS" },
    { 'O', "Org. BS","Copy boot sector over backup sector"},
    { 'B', "Backup BS","Copy backup boot sector over boot sector"},
    { 'R', "Rebuild BS","Rebuild boot sector"},
    { 'M', "Repair MFT","Check MFT"},
    { 'D', "Dump","Dump boot sector and backup boot sector"},
#if 0
    { 'U', "Undelete","Recover deleted files"},
#endif
    { 0, NULL, NULL }
  };
  buffer_bs=(unsigned char*)MALLOC(NTFS_BOOT_SECTOR_SIZE);
  buffer_backup_bs=(unsigned char*)MALLOC(NTFS_BOOT_SECTOR_SIZE);

  while(1)
  {
    unsigned int menu=0;
    int command;
    screen_buffer_reset();
    if(rescan==1)
    {
      int identical_sectors=0;
      int opt_B=0;
      int opt_O=0;
#ifdef HAVE_NCURSES
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
      wmove(stdscr,6,0);
      aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
#endif
      log_info("\nntfs_boot_sector\n");
      log_partition(disk_car,partition);
      screen_buffer_add("Boot sector\n");
      if(disk_car->read(disk_car,NTFS_BOOT_SECTOR_SIZE, buffer_bs, partition->part_offset)!=0)
      {
	screen_buffer_add("ntfs_boot_sector: Can't read boot sector.\n");
	memset(buffer_bs,0,NTFS_BOOT_SECTOR_SIZE);
      }
      if(test_NTFS(disk_car,(struct ntfs_boot_sector*)buffer_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("Status: OK\n");
	opt_O=1;
      }
      else
      {
	screen_buffer_add("Status: Bad\n");
      }
      screen_buffer_add("\nBackup boot sector\n");
      if(disk_car->read(disk_car,NTFS_BOOT_SECTOR_SIZE, buffer_backup_bs, partition->part_offset+partition->part_size-disk_car->sector_size)!=0)
      {
	screen_buffer_add("ntfs_boot_sector: Can't read backup boot sector.\n");
	memset(buffer_backup_bs,0,NTFS_BOOT_SECTOR_SIZE);
      }
      if(test_NTFS(disk_car,(struct ntfs_boot_sector*)buffer_backup_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("Status: OK\n");
	opt_B=1;
      }
      else
      {
	screen_buffer_add("Status: Bad\n");
      }
      screen_buffer_add("\n");
      if(memcmp(buffer_bs,buffer_backup_bs,NTFS_BOOT_SECTOR_SIZE)==0)
      {
	log_ntfs_info((const struct ntfs_boot_sector *)buffer_bs);
	screen_buffer_add("Sectors are identical.\n");
	identical_sectors=1;
      }
      else
      {
	log_ntfs2_info((const struct ntfs_boot_sector *)buffer_bs, (const struct ntfs_boot_sector *)buffer_backup_bs);
	screen_buffer_add("Sectors are not identical.\n");
	identical_sectors=0;
      }
      screen_buffer_add("\n");
      screen_buffer_add("A valid NTFS Boot sector must be present in order to access\n");
      screen_buffer_add("any data; even if the partition is not bootable.\n");
      if(opt_B!=0 && opt_O!=0)
      {
//      options="DRMLU";
	if(identical_sectors==0)
	  options="DOBRL";
	else
	  options="DRML";
      }
      else if(opt_B!=0)
      {
	menu=5;
	options="DBRL";
      }
      else if(opt_O!=0)
      {
	menu=4;
	options="DORL";
      }
      else
	options="DR";
      rescan=0;
    }
    screen_buffer_to_log();
    if(*current_cmd!=NULL)
    {
      command=0;
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(strncmp(*current_cmd,"rebuildbs",9)==0)
      {
	(*current_cmd)+=9;
	command='R';
      }
      else if(strncmp(*current_cmd,"dump",4)==0)
      {
	(*current_cmd)+=4;
	command='D';
      }
      else if(strncmp(*current_cmd,"list",4)==0)
      {
	(*current_cmd)+=4;
	command='L';
      }
      else if(strncmp(*current_cmd,"originalntfs",11)==0)
      {
	(*current_cmd)+=11;
	if(strchr(options,'O')!=NULL)
	    command='O';
      }
      else if(strncmp(*current_cmd,"backupntfs",9)==0)
      {
	(*current_cmd)+=9;
	if(strchr(options,'B')!=NULL)
	    command='B';
      }
      else if(strncmp(*current_cmd,"repairmft",9)==0)
      {
	(*current_cmd)+=9;
	if(strchr(options,'M')!=NULL)
	    command='M';
      }
    }
    else
    {
      log_flush();
#ifdef HAVE_NCURSES
      command=screen_buffer_display_ext(stdscr, options, menu_ntfs, &menu);
#else
      command=0;
#endif
    }
    switch(command)
    {
      case 0:
        free(buffer_bs);
        free(buffer_backup_bs);
	return 0;
      case 'O': /* O : copy original boot sector over backup boot */
	if(ask_confirmation("Copy original NTFS boot sector over backup boot, confirm ? (Y/N)")!=0)
	{
	  log_info("copy original boot sector over backup boot\n");
	  if(disk_car->write(disk_car,NTFS_BOOT_SECTOR_SIZE, buffer_bs, partition->part_offset+partition->part_size-disk_car->sector_size)!=0)
	  {
	    display_message("Write error: Can't overwrite NTFS backup boot sector\n");
	  }
          disk_car->sync(disk_car);
	  rescan=1;
	}
	break;
      case 'B': /* B : copy backup boot sector over boot sector */
	if(ask_confirmation("Copy backup NTFS boot sector over boot sector, confirm ? (Y/N)")!=0)
	{
	  log_info("copy backup boot sector over boot sector\n");
	  if(disk_car->write(disk_car,NTFS_BOOT_SECTOR_SIZE, buffer_backup_bs, partition->part_offset)!=0)
	  {
	    display_message("Write error: Can't overwrite NTFS boot sector\n");
	  }
          disk_car->sync(disk_car);
	  rescan=1;
	}
	break;
      case 'L':
	if(strchr(options,'O')==NULL && strchr(options,'B')!=NULL)
	{
	  io_redir_add_redir(disk_car,partition->part_offset,NTFS_BOOT_SECTOR_SIZE,0,buffer_backup_bs);
	  dir_partition(disk_car, partition, 0,current_cmd);
	  io_redir_del_redir(disk_car,partition->part_offset);
	}
	else
	  dir_partition(disk_car, partition, 0,current_cmd);
	break;
      case 'M':
        repair_MFT(disk_car, partition, verbose, expert, current_cmd);
	break;
      case 'R': /* R : rebuild boot sector */
	rebuild_NTFS_BS(disk_car,partition,verbose,dump_ind,1,expert,current_cmd);
	rescan=1;
	break;
      case 'D':
	dump_NTFS(disk_car, partition, buffer_bs, buffer_backup_bs);
	break;
#if 0
#ifdef HAVE_LIBNTFS
      case 'U':
	ntfs_undelete_part(disk_car, partition, verbose);
	break;
#endif
#endif
    }
  }
}

#ifdef HAVE_NCURSES
static void hfs_dump_ncurses(disk_t *disk_car, const partition_t *partition, const unsigned char *buffer_bs, const unsigned char *buffer_backup_bs)
{
  WINDOW *window=newwin(0,0,0,0);	/* full screen */
  keypad(window, TRUE); /* Need it to get arrow key */
  aff_copy(window);
  wmove(window,4,0);
  wprintw(window,"%s",disk_car->description(disk_car));
  wmove(window,5,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  mvwaddstr(window,6,0, "Superblock                        Backup superblock");
  dump2(window, buffer_bs, buffer_backup_bs, HFSP_BOOT_SECTOR_SIZE);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
}
#endif

static void hfs_dump(disk_t *disk_car, const partition_t *partition, const unsigned char *buffer_bs, const unsigned char *buffer_backup_bs)
{
  log_info("Superblock                        Backup superblock\n");
  dump2_log(buffer_bs, buffer_backup_bs, HFSP_BOOT_SECTOR_SIZE);
#ifdef HAVE_NCURSES
  hfs_dump_ncurses(disk_car, partition, buffer_bs, buffer_backup_bs);
#endif
}

int HFS_HFSP_boot_sector(disk_t *disk_car, partition_t *partition, const int verbose, const int dump_ind, const unsigned int expert, char **current_cmd)
{
  unsigned char *buffer_bs;
  unsigned char *buffer_backup_bs;
  const char *options="";
  int rescan=1;
  struct MenuItem menu_hfsp[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Quit","Return to Advanced menu"},
    { 'O', "Org. BS","Copy superblock over backup sector"},
    { 'B', "Backup BS","Copy backup superblock over superblock"},
    { 'D', "Dump","Dump superblock and backup superblock"},
    { 0, NULL, NULL }
  };
  buffer_bs=(unsigned char*)MALLOC(HFSP_BOOT_SECTOR_SIZE);
  buffer_backup_bs=(unsigned char*)MALLOC(HFSP_BOOT_SECTOR_SIZE);

  while(1)
  {
    unsigned int menu=0;
    int command;
    screen_buffer_reset();
    if(rescan==1)
    {
      int opt_over=0;
      int opt_B=0;
      int opt_O=0;
      options="D";
#ifdef HAVE_NCURSES
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
      wmove(stdscr,6,0);
      aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
#endif
      log_info("\nHFS_HFSP_boot_sector\n");
      log_partition(disk_car,partition);
      screen_buffer_add("Volume header\n");
      if(disk_car->read(disk_car,HFSP_BOOT_SECTOR_SIZE, buffer_bs, partition->part_offset+0x400)!=0)
      {
	screen_buffer_add("Bad: can't read HFS/HFS+ volume header.\n");
	memset(buffer_bs,0,HFSP_BOOT_SECTOR_SIZE);
      }
      else if(test_HFSP(disk_car,(const struct hfsp_vh*)buffer_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("HFS+ OK\n");
	opt_O=1;
	opt_over=1;
      }
      else if(test_HFS(disk_car,(const hfs_mdb_t*)buffer_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("HFS Ok\n");
	opt_O=1;
	opt_over=1;
      }
      else
	screen_buffer_add("Bad\n");
      screen_buffer_add("\nBackup volume header\n");
      if(disk_car->read(disk_car,HFSP_BOOT_SECTOR_SIZE, buffer_backup_bs, partition->part_offset+partition->part_size-0x400)!=0)
      {
	screen_buffer_add("Bad: can't read HFS/HFS+ backup volume header.\n");
	memset(buffer_backup_bs,0,HFSP_BOOT_SECTOR_SIZE);
      }
      else if(test_HFSP(disk_car,(const struct hfsp_vh*)buffer_backup_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("HFS+ OK\n");
	opt_B=1;
	opt_over=1;
      }
      else if(test_HFS(disk_car,(const hfs_mdb_t*)buffer_backup_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("HFS Ok\n");
	opt_B=1;
	opt_over=1;
      }
      else
	screen_buffer_add("Bad\n");
      screen_buffer_add("\n");
      if(memcmp(buffer_bs,buffer_backup_bs,HFSP_BOOT_SECTOR_SIZE)==0)
      {
	screen_buffer_add("Sectors are identical.\n");
	opt_over=0;
      }
      else
      {
	screen_buffer_add("Sectors are not identical.\n");
      }
      if(opt_over!=0)
      {
	if(opt_B!=0 && opt_O!=0)
	  options="DOB";
	else if(opt_B!=0)
	  options="DB";
	else if(opt_O!=0)
	  options="DO";
      }
      rescan=0;
    }
    screen_buffer_to_log();
    if(*current_cmd!=NULL)
    {
      command=0;
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(strncmp(*current_cmd,"dump",4)==0)
      {
	(*current_cmd)+=4;
	command='D';
      }
      else if(strncmp(*current_cmd,"originalhfsp",11)==0)
      {
	(*current_cmd)+=11;
	if(strchr(options,'O')!=NULL)
	    command='O';
      }
      else if(strncmp(*current_cmd,"backuphfsp",9)==0)
      {
	(*current_cmd)+=9;
	if(strchr(options,'B')!=NULL)
	    command='B';
      }
    }
    else
    {
      log_flush();
#ifdef HAVE_NCURSES
      command=screen_buffer_display_ext(stdscr, options, menu_hfsp, &menu);
#else
      command=0;
#endif
    }
    switch(command)
    {
      case 0:
        free(buffer_bs);
        free(buffer_backup_bs);
	return 0;
      case 'O': /* O : copy original superblock over backup boot */
	if(ask_confirmation("Copy original HFS/HFS+ volume header over backup, confirm ? (Y/N)")!=0)
	{
	  log_info("copy original superblock over backup boot\n");
	  if(disk_car->write(disk_car,HFSP_BOOT_SECTOR_SIZE, buffer_bs, partition->part_offset+partition->part_size-0x400)!=0)
	  {
	    display_message("Write error: Can't overwrite HFS/HFS+ backup volume header\n");
	  }
          disk_car->sync(disk_car);
	  rescan=1;
	}
	break;
      case 'B': /* B : copy backup superblock over main superblock */
	if(ask_confirmation("Copy backup HFS/HFS+ volume header over main volume header, confirm ? (Y/N)")!=0)
	{
	  log_info("copy backup superblock over main superblock\n");
	  if(disk_car->write(disk_car,HFSP_BOOT_SECTOR_SIZE, buffer_backup_bs, partition->part_offset+0x400)!=0)
	  {
	    display_message("Write error: Can't overwrite HFS/HFS+ main volume header\n");
	  }
          disk_car->sync(disk_car);
	  rescan=1;
	}
	break;
      case 'D':
	hfs_dump(disk_car, partition, buffer_bs, buffer_backup_bs);
	break;
    }
  }
}
