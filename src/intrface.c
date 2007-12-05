/*

    File: intrface.c

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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include "types.h"
#include "common.h"
#include "lang.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#else
#include <stdio.h>
#endif
#include "intrface.h"
#include "godmode.h"
#include "fnctdsk.h"
#include "testdisk.h"
#include "adv.h"
#include "analyse.h"
#include "chgtype.h"
#include "edit.h"
#include "savehdr.h"
#include "dirpart.h"
#include "fat.h"
#include "partauto.h"
#include "log.h"
#include "guid_cmp.h"
#include "hdaccess.h"
#include "io_redir.h"

#define INTER_DISK_X	0
#define INTER_DISK_Y	7
extern const arch_fnct_t arch_i386;

static void interface_options(int *dump_ind, int *align, int *allow_partial_last_cylinder, unsigned int *expert, char**current_cmd);
static list_part_t *interface_load(disk_t *disk_car,list_part_t *list_part, const int verbose);
static list_part_t *merge_partition_list(list_part_t *list_part,list_part_t *backup_part, const int verbose);
static int write_MBR_code(disk_t *disk_car);
static int write_clean_table(disk_t *disk_car);
static int interface_check_disk_capacity(disk_t *disk_car);
static int interface_check_disk_access(disk_t *disk_car, char **current_cmd);
static list_part_t *interface_analyse(disk_t *disk_car, const int verbose, const int saveheader, char**current_cmd);
static int menu_disk(disk_t *disk_car, const int verbose,int dump_ind, const int saveheader, char **current_cmd);

void interface_list(disk_t *disk_car, const int verbose, const int saveheader, const int backup, char **current_cmd)
{
  list_part_t *list_part;
  log_info("\nAnalyse ");
  log_info("%s\n",disk_car->description(disk_car));
  printf("%s\n",disk_car->description(disk_car));
  printf(msg_PART_HEADER_LONG);
  list_part=disk_car->arch->read_part(disk_car,verbose,saveheader);
  aff_buffer(BUFFER_WRITE,"Q");
  if(backup>0)
  {
    partition_save(disk_car,list_part,verbose);
  }
  part_free_list(list_part);
}

#ifdef HAVE_NCURSES
static int write_MBR_code(disk_t *disk_car)
{
  aff_copy(stdscr);
  wmove(stdscr,5,0);
  wprintw(stdscr,"%s\n",disk_car->description(disk_car));
  wmove(stdscr,INTER_DISK_Y,INTER_DISK_X);
  if(disk_car->arch->write_MBR_code==NULL)
  {
    display_message("Function to write a new MBR code not implemented for this partition type.\n");
    return 1;
  }
  wprintw(stdscr,msg_WRITE_MBR_CODE);
  if(ask_YN(stdscr)!=0 && ask_confirmation("Write a new copy of MBR code, confirm ? (Y/N)")!=0)
  {
    if(disk_car->arch->write_MBR_code(disk_car))
    {
      display_message("Write error: Can't write new MBR code.\n");
      return 2;
    }
    else
      display_message("A new copy of MBR code has been written.\nYou have to reboot for the change to take effect.\n");
  }
  return 0;
}

static int write_clean_table(disk_t *disk_car)
{
  aff_copy(stdscr);
  wmove(stdscr,5,0);
  wprintw(stdscr,"%s\n",disk_car->description(disk_car));
  wmove(stdscr,INTER_DISK_Y,INTER_DISK_X);
  if(disk_car->arch->erase_list_part==NULL)
  {
    display_message("Clear partition table not implemented for this partition type.\n");
    return 1;
  }
  wprintw(stdscr,msg_WRITE_CLEAN_TABLE);
  if(ask_YN(stdscr)!=0 && ask_confirmation("Clear partition table, confirm ? (Y/N)")!=0)
  {
    if(disk_car->arch->erase_list_part(disk_car))
    {
      display_message("Write error: Can't clear partition table.\n");
      return 2;
    }
    else
      display_message("Partition table has been cleared.\nYou have to reboot for the change to take effect.\n");
  }
  return 0;
}
#else
static int write_MBR_code(disk_t *disk_car)
{
  if(disk_car->arch->write_MBR_code==NULL)
  {
    log_error("Function to write a new MBR code not implemented for this partition type.\n");
    return 1;
  }
  if(disk_car->arch->write_MBR_code(disk_car))
  {
    log_error("Write error: Can't write new MBR code.\n");
    return 2;
  }
  else
    log_info("A new copy of MBR code has been written.\nYou have to reboot for the change to take effect.\n");
  return 0;
}

static int write_clean_table(disk_t *disk_car)
{
  if(disk_car->arch->erase_list_part==NULL)
  {
    log_error("Clear partition table not implemented for this partition type.\n");
    return 1;
  }
  if(disk_car->arch->erase_list_part(disk_car))
  {
    log_error("Write error: Can't clear partition table.\n");
    return 2;
  }
  else
    log_info("Partition table has been cleared.\nYou have to reboot for the change to take effect.\n");
  return 0;
}
#endif

static int menu_disk_cli(disk_t *disk_car, const int verbose,int dump_ind, const int saveheader, char **current_cmd)
{
  int align=2;
  int allow_partial_last_cylinder=0;
  int ask_part_order=0;
  unsigned int expert=0;
  char options[16];
  strcpy(options, "AGOPTQ");
  while(1)
  {
    while(*current_cmd[0]==',')
      (*current_cmd)++;
    if(strncmp(*current_cmd,"analyze",7)==0 || strncmp(*current_cmd,"analyse",7)==0)
    {
      (*current_cmd)+=7;
      {
	int search_vista_part=0;
	list_part_t *list_part;
	list_part=interface_analyse(disk_car, verbose, saveheader, current_cmd);
	if(disk_car->arch==&arch_i386)
	{
	  const int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
	  const list_part_t *element;
	  for(element=list_part;element!=NULL;element=element->next)
	  {
	    if(element->part->part_offset%(2048*512)==0 && element->part->part_size%(2048*512)==0)
	      search_vista_part=1;
	  }
	  while(*current_cmd[0]==',')
	    (*current_cmd)++;
	  if(strncmp(*current_cmd,"mode_vista",10)==0)
	  {
	    (*current_cmd)+=10;
	    search_vista_part=1;
	  }
	  if(search_vista_part==1)
	    allow_partial_last_cylinder=1;
	  if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	    hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
	  log_info("Allow partial last cylinder : %s\n", allow_partial_last_cylinder>0?"Yes":"No");
	  log_info("search_vista_part: %d\n", search_vista_part);
	}
	interface_recovery(disk_car, list_part, verbose, dump_ind, align, ask_part_order, expert, search_vista_part, current_cmd);
	part_free_list(list_part);
      }
    }
    else if(strncmp(*current_cmd,"geometry,",9)==0)
    {
      (*current_cmd)+=9;
      change_geometry(disk_car, current_cmd);
    }
    else if(strncmp(*current_cmd,"advanced",8)==0)
    {
      (*current_cmd)+=8;
      interface_adv(disk_car, verbose, dump_ind, expert,current_cmd);
    }
    else if(strncmp(*current_cmd,"options,",8)==0)
    {
      const int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
      (*current_cmd)+=8;
      interface_options(&dump_ind, &align,&allow_partial_last_cylinder,&expert,current_cmd);
      if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
    }
    else if(strncmp(*current_cmd,"delete",6)==0)
    {
      (*current_cmd)+=6;
      write_clean_table(disk_car);
    }
    else if(strncmp(*current_cmd,"mbr_code",8)==0)
    {
      (*current_cmd)+=8;
      write_MBR_code(disk_car);
    }
    else
    {
      return 0;
    }
  }
}

#ifdef HAVE_NCURSES
static int menu_disk_ncurses(disk_t *disk_car, const int verbose,int dump_ind, const int saveheader, char **current_cmd)
{
  int align=2;
  int allow_partial_last_cylinder=0;
  int ask_part_order=0;
  int command;
  unsigned int menu=0;
  int real_key;
  unsigned int expert=0;
  char options[16];
  static struct MenuItem menuMain[]=
  {
	{'A',"Analyse","Analyse current partition structure and search for lost partitions"},
	{'T',"Advanced","Filesystem Utils"},
	{'G',"Geometry", "Change disk geometry" },
	{'O',"Options","Modify options"},
	{'C',"MBR Code","Write TestDisk MBR code to first sector"},
	{'D',"Delete","Delete all data in the partition table"},
	{'Q',"Quit","Return to disk selection"},
	{'E',"Editor","Basic disk editor"},
	{0,NULL,NULL}
  };
  strcpy(options, "AGOPTQ");
  if(disk_car->arch->write_MBR_code!=NULL)
    strcat(options,"C");
  if(disk_car->arch->erase_list_part!=NULL)
    strcat(options,"D");
  while(1)
  {
    aff_copy(stdscr);
    wmove(stdscr,5,0);
    wprintw(stdscr,"%s\n",disk_car->description(disk_car));
    wmove(stdscr,20,0);
    wprintw(stdscr,"Note: Correct disk geometry is required for a successful recovery. 'Analyse'");
    wmove(stdscr,21,0);
    wprintw(stdscr,"process may give some warnings if it thinks the logical geometry is mismatched.");
    command = wmenuSelect_ext(stdscr,INTER_DISK_Y, INTER_DISK_X, menuMain, 10,
	options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON | MENU_ACCEPT_OTHERS, &menu,&real_key);
    /* e for editor will be added when the editor will be better */
    switch(command)
    {
      case 'a':
      case 'A':
	{
	  int search_vista_part=0;
	  list_part_t *list_part;
	  list_part=interface_analyse(disk_car, verbose, saveheader, current_cmd);
	  if(disk_car->arch==&arch_i386)
	  {
	    const int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
	    const list_part_t *element;
	    for(element=list_part;element!=NULL;element=element->next)
	    {
	      if(element->part->part_offset%(2048*512)==0 && element->part->part_size%(2048*512)==0)
		search_vista_part=1;
	    }
	    if(search_vista_part==0)
	    {
	      log_info("Ask the user for vista mode\n");
	      if(ask_confirmation("Should TestDisk search for partition created under Vista ? [Y/N] (answer Yes if unsure)")!=0)
		search_vista_part=1;
	    }
	    if(search_vista_part==1)
	      allow_partial_last_cylinder=1;
	    if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	      hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
	    log_info("Allow partial last cylinder : %s\n", allow_partial_last_cylinder>0?"Yes":"No");
	    log_info("search_vista_part: %d\n", search_vista_part);
	  }
	  interface_recovery(disk_car, list_part, verbose, dump_ind, align, ask_part_order, expert, search_vista_part, current_cmd);
	  part_free_list(list_part);
	}
	break;
      case 'd':
      case 'D':
	write_clean_table(disk_car);
	break;
      case 'c':
      case 'C':
	write_MBR_code(disk_car);
	break;
      case 'g':
      case 'G':
	change_geometry(disk_car, current_cmd);
	break;
      case 'o':
      case 'O':
	{
	  const int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
	  interface_options(&dump_ind, &align,&allow_partial_last_cylinder,&expert, current_cmd);
	  if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	    hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
	}
	break;
      case 't':
      case 'T':
	interface_adv(disk_car, verbose, dump_ind, expert, current_cmd);
	break;
      case 'e':
      case 'E':
	interface_editor(disk_car);
	break;
      case 'q':
      case 'Q':
	return 0;
    }
  }
}
#endif

static int menu_disk(disk_t *disk_car, const int verbose,int dump_ind, const int saveheader, char **current_cmd)
{
  if(*current_cmd!=NULL)
    return menu_disk_cli(disk_car, verbose, dump_ind, saveheader, current_cmd);
#ifdef HAVE_NCURSES
  return menu_disk_ncurses(disk_car, verbose, dump_ind, saveheader, current_cmd);
#else
  return 0;
#endif
}

static int testdisk_disk_selection_cli(int verbose,int dump_ind, const list_disk_t *list_disk, const int saveheader, const char *cmd_device, char **current_cmd)
{
  const list_disk_t *element_disk;
  const list_disk_t *current_disk=NULL;
  if(cmd_device!=NULL)
  {
    for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    {
      if(strcmp(element_disk->disk->device,cmd_device)==0)
	current_disk=element_disk;
    }
  }
  else
    current_disk=list_disk;
  if(current_disk==NULL)
  {
    return intrf_no_disk("TestDisk");
  }
  if(*current_cmd!=NULL)
  {
    while(*current_cmd[0]==',')
      (*current_cmd)++;
    {
      disk_t *disk=current_disk->disk;
      autodetect_arch(disk);
      autoset_unit(disk);
      if(interface_check_disk_capacity(disk)==0 &&
          interface_check_disk_access(disk, current_cmd)==0 &&
          interface_partition_type(disk, verbose, current_cmd)==0)
      {
	menu_disk(disk, verbose, dump_ind, saveheader, current_cmd);
      }
    }
  }
  return 0;
}

#ifdef HAVE_NCURSES
static int testdisk_disk_selection_ncurses(int verbose,int dump_ind, const list_disk_t *list_disk, const int saveheader, char **current_cmd)
{
  int command='Q';
  unsigned int menu=0;
  int offset=0;
  int pos_num=0;
  const list_disk_t *element_disk;
  const list_disk_t *current_disk;
  static struct MenuItem menuMain[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'O',"Proceed",""},
    { 'Q',"Quit","Quit program"},
    { 0,NULL,NULL}
  };
  current_disk=list_disk;
  if(current_disk==NULL)
  {
    return intrf_no_disk("TestDisk");
  }
    /* ncurses interface */
  while(1)
  {
    const char *options;
    int i;
#ifdef HAVE_NCURSES
    aff_copy(stdscr);
    wmove(stdscr,4,0);
    wprintw(stdscr,"  TestDisk is free software, and");
    wmove(stdscr,5,0);
    wprintw(stdscr,"comes with ABSOLUTELY NO WARRANTY.");
    wmove(stdscr,7,0);
    wprintw(stdscr,"Select a media (use Arrow keys, then press Enter):");
#endif
    for(i=0,element_disk=list_disk;(element_disk!=NULL) && (i<offset);element_disk=element_disk->next,i++);
    for(;element_disk!=NULL && (i-offset)<10;i++,element_disk=element_disk->next)
    {
      wmove(stdscr,8+i-offset,0);
      if(element_disk!=current_disk)
	wprintw(stdscr,"%s\n",element_disk->disk->description_short(element_disk->disk));
      else
      {
	wattrset(stdscr, A_REVERSE);
	wprintw(stdscr,"%s\n",element_disk->disk->description_short(element_disk->disk));
	wattroff(stdscr, A_REVERSE);
      }
    }
    if(i<=10 && element_disk==NULL)
      options="OQ";
    else
      options="PNOQ";
    {
      int line=20;
      mvwaddstr(stdscr,line++,0,"Note: ");
#if defined(__CYGWIN__) || defined(__MINGW32__) || defined(DJGPP)
#else
#ifdef HAVE_GETEUID
      if(geteuid()!=0)
      {
        if(has_colors())
          wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(1));
        waddstr(stdscr,"Some disks won't appear unless you are root user.");
        if(has_colors())
          wbkgdset(stdscr,' ' | COLOR_PAIR(0));
        wmove(stdscr,line++,0);
      }
#endif
#endif
      waddstr(stdscr,"Disk capacity must be correctly detected for a successful recovery.");
      wmove(stdscr,line++,0);
      wprintw(stdscr,"If a disk listed above has incorrect size, check HD jumper settings, BIOS");
      wmove(stdscr,line++,0);
      wprintw(stdscr,"detection, and install the latest OS patches and disk drivers."); 
    }
    command = wmenuSelect_ext(stdscr,INTER_MAIN_Y, INTER_MAIN_X, menuMain, 8,
	options, MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, &menu,NULL);
    switch(command)
    {
      case KEY_UP:
      case 'P':
	if(current_disk->prev!=NULL)
	{
	  current_disk=current_disk->prev;
	  pos_num--;
	}
	if(pos_num<offset)
	  offset--;
	break;
      case KEY_DOWN:
      case 'N':
	if(current_disk->next!=NULL)
	{
	  current_disk=current_disk->next;
	  pos_num++;
	}
	if(pos_num>=offset+10)
	  offset++;
	break;
      case KEY_PPAGE:
	for(i=0;i<INTER_STRUCTURE && current_disk->prev!=NULL;i++)
	{
	  current_disk=current_disk->prev;
	  pos_num--;
	  if(pos_num<offset)
	    offset--;
	}
	break;
      case KEY_NPAGE:
	for(i=0;i<INTER_STRUCTURE && current_disk->next!=NULL;i++)
	{
	  current_disk=current_disk->next;
	  pos_num++;
	  if(pos_num>=offset+10)
	    offset++;
	}
	break;
      case 'o':
      case 'O':
	{
	  disk_t *disk=current_disk->disk;
	  autodetect_arch(disk);
	  autoset_unit(disk);
	  if(interface_check_disk_capacity(disk)==0 &&
              interface_check_disk_access(disk, current_cmd)==0 &&
	      interface_partition_type(disk, verbose, current_cmd)==0)
	  {
	    if(menu_disk(disk, verbose, dump_ind, saveheader, current_cmd))
	      return 0;
	  }
	}
	break;
      case 'q':
      case 'Q':
	return 0;
    }
  }
}
#endif

int do_curses_testdisk(int verbose,int dump_ind, const list_disk_t *list_disk, const int saveheader, const char *cmd_device, char **current_cmd)
{
  if(*current_cmd!=NULL)
    return testdisk_disk_selection_cli(verbose, dump_ind, list_disk, saveheader, cmd_device, current_cmd);
#ifdef HAVE_NCURSES
  return testdisk_disk_selection_ncurses(verbose, dump_ind, list_disk, saveheader, current_cmd);
#else
  return 0;
#endif
}

#ifdef HAVE_NCURSES
static int interface_check_disk_capacity_ncurses(disk_t *disk_car)
{
  static const struct MenuItem menuMain[]=
  {
    { 'C', "Continue","The HD is really 137 GB only."},
    { 'Q',"Quit","The HD is bigger, it's safer to enable LBA48 support first."},
    { 0,NULL,NULL}
  };
  unsigned int menu=1;
  int car;
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s\n",disk_car->description(disk_car));
  wmove(stdscr,6,0);
  wprintw(stdscr,"The Harddisk size seems to be 137GB.");
  wmove(stdscr,7,0);
  wprintw(stdscr,"Support for 48-bit Logical Block Addressing (LBA) is needed to access");
  wmove(stdscr,8,0);
  wprintw(stdscr,"hard disks larger than 137 GB.");
  wmove(stdscr,9,0);
#if defined(__CYGWIN__) || defined(__MINGW32__)
  wprintw(stdscr,"Update Windows to support LBA48 (minimum: W2K SP4 or XP SP1)");
#endif
  car= wmenuSelect_ext(stdscr,INTER_MAIN_Y, INTER_MAIN_X, menuMain, 10,
      "CQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
  if(car=='c' || car=='C')
    return 0;
  return 1;
}
#endif

static int interface_check_disk_capacity(disk_t *disk_car)
{
  /* Test for LBA28 limitation */
  if(disk_car->CHS.sector>0 && (disk_car->CHS.cylinder+1) == (((1<<28)-1) / (disk_car->CHS.head+1) / disk_car->CHS.sector))
  {
    log_warning("LBA28 limitation\n");
    log_flush();
#ifdef HAVE_NCURSES
    return interface_check_disk_capacity_ncurses(disk_car);
#endif
  }
  return 0;
}

#ifdef HAVE_NCURSES
static int interface_check_disk_access_ncurses(disk_t *disk_car)
{
  const char *prog_name="TestDisk";
  static const struct MenuItem menuDiskAccess[]=
  {
    { 'C', "Continue", "Continue even if write access isn't available"},
    { 'Q', "Quit", "Return to disk selection"},
    { 0,NULL,NULL}
  };
  unsigned int menu=0;
  int car;
  int line=9;
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s\n",disk_car->description(disk_car));
  wmove(stdscr,6,0);
  wprintw(stdscr,"Write access for this media is not available.");
  wmove(stdscr,7,0);
  wprintw(stdscr,"TestDisk won't be able to modify it.");
#ifdef DJGPP
#elif defined(__CYGWIN__) || defined(__MINGW32__)
  wmove(stdscr,line++,0);
  wprintw(stdscr,"- You may need to be administrator to have write access.\n");
  wmove(stdscr,line++,0);
  wprintw(stdscr,"Under Vista, select %s, right-click and choose \"Run as administrator\".\n", prog_name);
#elif defined HAVE_GETEUID
  if(geteuid()!=0)
  {
    wmove(stdscr,line++,0);
    wprintw(stdscr,"- You may need to be root to have write access.\n");
#if defined(__APPLE__)
    wmove(stdscr,line++,0);
    wprintw(stdscr,"Use the sudo command to launch %s.\n", prog_name);
#endif
    wmove(stdscr,line++,0);
    wprintw(stdscr,"- Check the OS permission for this file or device.\n");
  }
#endif
#if defined(__APPLE__)
  wmove(stdscr,line++,0);
  wprintw(stdscr,"- No partition from this disk must be mounted:\n");
  wmove(stdscr,line++,0);
  wprintw(stdscr,"Open the Disk Utility (In Finder -> Application -> Utility folder)\n");
  wmove(stdscr,line++,0);
  wprintw(stdscr,"and press Umount button for each volume from this disk\n");
#endif
  wmove(stdscr,line++,0);
  wprintw(stdscr,"- This media may be physically write-protected, check the jumpers.\n");
  car= wmenuSelect_ext(stdscr,INTER_MAIN_Y, INTER_MAIN_X, menuDiskAccess, 10,
      "CQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
  if(car=='c' || car=='C')
    return 0;
  return 1;
}
#endif

static int interface_check_disk_access(disk_t *disk_car, char **current_cmd)
{
  if((disk_car->access_mode&TESTDISK_O_RDWR)==TESTDISK_O_RDWR)
    return 0;
  if(*current_cmd!=NULL)
    return 0;
  log_warning("Media is opened in read-only.\n");
  log_flush();
#ifdef HAVE_NCURSES
  return interface_check_disk_access_ncurses(disk_car);
#else
  return 0;
#endif
}

static list_part_t *interface_analyse_ncurses(disk_t *disk_car, const int verbose, const int saveheader, char**current_cmd)
{
  list_part_t *list_part;
  int command;
  struct MenuItem menuAnalyse[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q',"Quick Search","Try to locate partition"},
    { 'B', "Backup","Save current partition list to backup.log file and proceed"},
    { 0, NULL, NULL }
  };
  aff_buffer(BUFFER_RESET,"Q");
  /* ncurses interface */
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  if(disk_car->arch->msg_part_type!=NULL)
    mvwaddstr(stdscr,22,0,disk_car->arch->msg_part_type);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s\n",disk_car->description(disk_car));
  mvwaddstr(stdscr,5,0,"Checking current partition structure");
  wmove(stdscr,6,0);
  wrefresh(stdscr);
  wprintw(stdscr,msg_PART_HEADER_LONG);
#endif
  list_part=disk_car->arch->read_part(disk_car,verbose,saveheader);
  log_info("Current partition structure:\n");
  screen_buffer_to_log();
#ifdef HAVE_NCURSES
  wmove(stdscr,5,0);
  wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
  waddstr(stdscr,"Current partition structure:");
#endif
  command='Q';
  if(*current_cmd!=NULL)
  {
    while(*current_cmd[0]==',')
      (*current_cmd)++;
    if(strncmp(*current_cmd,"backup",6)==0)
    {
      (*current_cmd)+=6;
      if(list_part!=NULL)
	command='B';
    }
  }
  else
  {
    log_flush();
#ifdef HAVE_NCURSES
    command=screen_buffer_display(stdscr,(list_part!=NULL?"QB":"Q"),menuAnalyse);
#endif
  }
  if(command=='B')
  {
    log_info("Backup partition structure\n");
    if(partition_save(disk_car,list_part,verbose)<0)
    {
      display_message("Can't create backup.log.\n");
    }
  }
  return list_part;
}

static list_part_t *interface_analyse(disk_t *disk_car, const int verbose, const int saveheader, char**current_cmd)
{
  log_info("\nAnalyse ");
  log_info("%s\n",disk_car->description(disk_car));
  return interface_analyse_ncurses(disk_car, verbose, saveheader, current_cmd);
}

int interface_write(disk_t *disk_car,list_part_t *list_part,const int can_search_deeper, const int can_ask_minmax_ext, int *no_confirm, char **current_cmd, unsigned int *menu)
{
  list_part_t *parts;
  struct MenuItem menuWrite[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Quit","Return to main menu"},
    { 'S', "Deeper Search","Try to find more partitions"},
    { 'W', "Write","Write partition structure to disk"},
    { 'E', "Extd Part","Maximize/Minimize extended partition"},
    { 0, NULL, NULL }
  };
  int command;
  log_info("\ninterface_write()\n");
  aff_buffer(BUFFER_RESET,"Q");
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s",disk_car->description(disk_car));
  wmove(stdscr,5,0);
  mvwaddstr(stdscr,6,0,msg_PART_HEADER_LONG);
#endif
  for(parts=list_part;parts!=NULL;parts=parts->next)
    if(parts->part->status!=STATUS_LOG)
      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,parts->part);
  for(parts=list_part;parts!=NULL;parts=parts->next)
    if(parts->part->status==STATUS_LOG)
      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,parts->part);
  command='Q';
  if(list_part==NULL)
  {
    aff_buffer(BUFFER_ADD," \nNo partition found or selected for recovery");
    screen_buffer_to_log();
    if(*current_cmd!=NULL)
    {
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(strncmp(*current_cmd,"search",6)==0)
      {
	(*current_cmd)+=6;
	command='S';
      }
    }
    else
    {
      log_flush();
#ifdef HAVE_NCURSES
      command=screen_buffer_display_ext(stdscr,(can_search_deeper?"S":""),menuWrite,menu);
#endif
    }
  }
  else
  {
    if(*current_cmd!=NULL)
    {
      do
      {
	command='Q';
	while(*current_cmd[0]==',')
	  (*current_cmd)++;
	if(strncmp(*current_cmd,"search",6)==0)
	{
	  (*current_cmd)+=6;
	  if(can_search_deeper)
	    command='S';
	}
	else if(strncmp(*current_cmd,"noconfirm",9)==0)
	{
	  command=0;	/* do nothing */
	  (*no_confirm)=1;
	  (*current_cmd)+=9;
	}
	else if(strncmp(*current_cmd,"write",5)==0)
	{
	  (*current_cmd)+=5;
	  if(disk_car->arch->write_part!=NULL)
	    command='W';
	}
      } while(command==0);
      screen_buffer_to_log();
    }
    else
    {
      char options[10];
      options[0]=0;
      if(can_search_deeper)
	strcat(options,"S");
      if(disk_car->arch->write_part!=NULL)
	strcat(options,"W");
      else
	aff_buffer(BUFFER_ADD," \nWrite isn't available because the partition table type \"%s\" has been selected.",
	    disk_car->arch->part_name);
      if(can_ask_minmax_ext)
	strcat(options,"E");
      screen_buffer_to_log();
      log_flush();
#ifdef HAVE_NCURSES
      command=screen_buffer_display_ext(stdscr,options,menuWrite,menu);
#else
      command='Q';
#endif
    }
  }
  return command;
}

#ifdef HAVE_NCURSES
static void interface_options_ncurses(int *dump_ind, int *align, int *allow_partial_last_cylinder, unsigned int *expert)
{
  unsigned int menu = 4;
  /* ncurses interface */
  while (1)
  {
    int car;
    int real_key;
    struct MenuItem menuOptions[]=
    {
      { 'E',NULL,"Expert mode adds some functionalities"},
      { 'C',NULL,"Partitions are aligned on cylinder/head boundaries" },
      { 'A',NULL,""},
      { 'D',NULL,"Dump essential sectors" },
      { 'Q',"[ Ok ]","Done with changing options"},
      { 0, NULL, NULL }
    };
    menuOptions[0].name=*expert?"Expert mode : Yes":"Expert mode : No";
    switch(*align)
    {
      case 0:
	menuOptions[1].name="Cylinder boundary : No";
	break;
      case 1:
	menuOptions[1].name="Cylinder boundary : Head boundary only";
	break;
      case 2:
	menuOptions[1].name="Cylinder boundary : Yes";
	break;
    }
    menuOptions[2].name=*allow_partial_last_cylinder?"Allow partial last cylinder : Yes":"Allow partial last cylinder : No";
    menuOptions[3].name=*dump_ind?"Dump : Yes":"Dump : No";
    aff_copy(stdscr);
    car=wmenuSelect_ext(stdscr,INTER_OPTION_Y, INTER_OPTION_X, menuOptions, 0, "ECADQ", MENU_VERT|MENU_VERT_ARROW2VALID, &menu,&real_key);
    switch(car)
    {
      case 'd':
      case 'D':
	*dump_ind=!*dump_ind;
	break;
      case 'c':
      case 'C':
	if(*align<2)
	  (*align)++;
	else
	  *align=0;
	break;
      case 'a':
      case 'A':
	*allow_partial_last_cylinder=!*allow_partial_last_cylinder;
	break;
      case 'e':
      case 'E':
	*expert=!*expert;
	break;
      case key_ESC:
      case 'q':
      case 'Q':
	return;
    }
  }
}
#endif

static void interface_options(int *dump_ind, int *align, int *allow_partial_last_cylinder, unsigned int *expert, char**current_cmd)
{
  if(*current_cmd==NULL)
  {
#ifdef HAVE_NCURSES
    interface_options_ncurses(dump_ind, align, allow_partial_last_cylinder, expert);
#endif
  }
  /* write new options to log file */
  log_info("New options :\n Dump : %s\n ", (*dump_ind?"Yes":"No"));
  switch(*align)
  {
    case 0:
      log_info("Cylinder boundary : No");
      break;
    case 1:
      log_info("Cylinder boundary : Head boundary only");
      break;
    case 2:
      log_info("Cylinder boundary : Yes");
      break;
  }
  log_info("\n Allow partial last cylinder : %s\n Expert mode : %s\n",
      *allow_partial_last_cylinder?"Yes":"No",
      *expert?"Yes":"No");
}

static list_part_t *ask_structure_cli(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  list_part_t *pos=list_part;
  while(*current_cmd[0]==',')
    (*current_cmd)++;
  if(strncmp(*current_cmd,"list",4)==0)
  {
    (*current_cmd)+=4;
    if(pos!=NULL)
    {
      partition_t *partition=pos->part;
      if(partition->sb_offset==0 || partition->sb_size==0)
        dir_partition(disk_car,partition,verbose, current_cmd);
      else
      {
        io_redir_add_redir(disk_car,
            partition->part_offset+partition->sborg_offset,
            partition->sb_size,
            partition->part_offset+partition->sb_offset,
            NULL);
        dir_partition(disk_car,partition,verbose, current_cmd);
        io_redir_del_redir(disk_car, partition->part_offset+partition->sborg_offset);
      }
    }
  }
  return list_part;
}

#ifdef HAVE_NCURSES
static list_part_t *ask_structure_ncurses(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  int offset=0;
  int pos_num=0;
  list_part_t *pos=list_part;
  int rewrite=1;
  while(1)
  {
    int i;
    int command;
    list_part_t *parts;
    int structure_status;
    if(rewrite)
    {
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      mvwaddstr(stdscr,5,0,msg_PART_HEADER);
      rewrite=0;
    }
    structure_status=disk_car->arch->test_structure(list_part);
    for(i=0,parts=list_part;(parts!=NULL) && (i<offset);parts=parts->next,i++);
    for(i=offset;(parts!=NULL) &&((i-offset)<INTER_STRUCTURE);i++,parts=parts->next)
    {
      wmove(stdscr,6+i-offset,0);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      if(parts==pos)
      {
	wattrset(stdscr, A_REVERSE);
      }
      if(structure_status==0 && parts->part->status!=STATUS_DELETED && has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(2));
      aff_part(stdscr, AFF_PART_STATUS, disk_car, parts->part);
      if(structure_status==0 && parts->part->status!=STATUS_DELETED && has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(0));
      if(parts==pos)
      {
	char buffer_part_size[100];
	wattroff(stdscr, A_REVERSE);
	wmove(stdscr,24,0);
	wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
	if(parts->part->info[0]!='\0')
	{
	  wprintw(stdscr,"%s, ",parts->part->info);
	}
	wprintw(stdscr,"%s",size_to_unit(parts->part->part_size,buffer_part_size));
      }
    }
    if(structure_status==0)
      mvwaddstr(stdscr,19,0,msg_STRUCT_OK);
    else
    {
      if(has_colors())
	wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(1));
      mvwaddstr(stdscr,19,0,msg_STRUCT_BAD);
      if(has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(0));
    }
    if(list_part!=NULL && disk_car->arch->msg_part_type!=NULL)
    {
      mvwaddstr(stdscr,19,16,"Use ");
      if(has_colors())
	wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
      waddstr(stdscr,"Up");
      if(has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(0));
      waddstr(stdscr,"/");
      if(has_colors())
	wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
      waddstr(stdscr,"Down");
      if(has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(0));
      waddstr(stdscr," Arrow keys to select partition.");
      mvwaddstr(stdscr,20,0,"Use ");
      if(has_colors())
	wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
      waddstr(stdscr,"Left");
      if(has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(0));
      waddstr(stdscr,"/");
      if(has_colors())
	wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
      waddstr(stdscr,"Right");
      if(has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(0));
      waddstr(stdscr," Arrow keys to CHANGE partition characteristics:");
      mvwaddstr(stdscr,21,0,disk_car->arch->msg_part_type);
    }
    wmove(stdscr,22,0);
    wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
    waddstr(stdscr,"Keys ");
    if(has_colors())
      wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
    waddstr(stdscr,"A");
    if(has_colors())
      wbkgdset(stdscr,' ' | COLOR_PAIR(0));
    waddstr(stdscr,": add partition, ");
    if(has_colors())
      wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
    waddstr(stdscr,"L");
    if(has_colors())
      wbkgdset(stdscr,' ' | COLOR_PAIR(0));
    waddstr(stdscr,": load backup, ");

    if(list_part==NULL)
    {
      waddstr(stdscr,"Enter: to continue");
    }
    else
    {
      if(pos->part->arch==NULL || pos->part->arch==disk_car->arch)
      {
	if(has_colors())
	  wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(stdscr,"T");
	if(has_colors())
	  wbkgdset(stdscr,' ' | COLOR_PAIR(0));
	waddstr(stdscr,": change type, ");
      }
      switch(pos->part->upart_type)
      {
	case UP_EXT2:
	case UP_EXT3:
	case UP_RFS:
	case UP_RFS2:
	case UP_RFS3:
	case UP_FAT12:
	case UP_FAT16:
	case UP_FAT32:
	case UP_NTFS:
	  if(has_colors())
	    wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
	  waddstr(stdscr,"P");
	  if(has_colors())
	    wbkgdset(stdscr,' ' | COLOR_PAIR(0));
	  waddstr(stdscr,": list files, ");
	  break;
	default:
	  break;
      }
      if(has_colors())
	wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
      mvwaddstr(stdscr,23,5, "Enter");
      if(has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(0));
      waddstr(stdscr,": to continue");
    }
    wrefresh(stdscr);
    command=wgetch(stdscr);
    switch(command)
    {
      case KEY_UP:
	if(list_part!=NULL)
	{
	  only_one_bootable(list_part,pos);
	  if(pos->prev!=NULL)
	  {
	    pos=pos->prev;
	    pos_num--;
	  }
	  if(pos_num<offset)
	    offset--;
	}
	break;
      case KEY_DOWN:
	if(list_part!=NULL)
	{
	  only_one_bootable(list_part,pos);
	  if(pos->next!=NULL)
	  {
	    pos=pos->next;
	    pos_num++;
	  }
	  if(pos_num>=offset+INTER_STRUCTURE)
	    offset++;
	}
	break;
      case KEY_PPAGE:
	if(list_part!=NULL)
	{
	  only_one_bootable(list_part,pos);
	  for(i=0;(i<INTER_STRUCTURE) && (pos->prev!=NULL);i++)
	  {
	    pos=pos->prev;
	    pos_num--;
	    if(pos_num<offset)
	      offset--;
	  }
	}
	break;
      case KEY_NPAGE:
	if(list_part!=NULL)
	{
	  only_one_bootable(list_part,pos);
	  for(i=0;(i<INTER_STRUCTURE) && (pos->next!=NULL);i++)
	  {
	    pos=pos->next;
	    pos_num++;
	    if(pos_num>=offset+INTER_STRUCTURE)
	      offset++;
	  }
	}
	break;
      case KEY_RIGHT:
      case '+':
      case ' ':
	if(list_part!=NULL)
	{
	  if(pos->part->arch==NULL || pos->part->arch==disk_car->arch)
	    disk_car->arch->set_next_status(disk_car,pos->part);
	}
	break;
      case KEY_LEFT:
      case '-':
	if(list_part!=NULL)
	{
	  if(pos->part->arch==NULL || pos->part->arch==disk_car->arch)
	    disk_car->arch->set_prev_status(disk_car,pos->part);
	}
	break;
      case 'a':
      case 'A':
	{
	  list_part=disk_car->arch->add_partition(disk_car,list_part, verbose, current_cmd);
	  rewrite=1;
	  offset=0;
	  pos_num=0;
	  pos=list_part;
	}
	break;
      case 't':
      case 'T':
	if(list_part!=NULL)
	{
	  rewrite=1;
	  change_part_type(disk_car, pos->part, current_cmd);
	}
	break;
      case 'p':
      case 'P':
	if(list_part!=NULL)
        {
          partition_t *partition=pos->part;
          if(partition->sb_offset==0 || partition->sb_size==0)
            dir_partition(disk_car,partition,verbose, current_cmd);
          else
          {
            io_redir_add_redir(disk_car,
                partition->part_offset+partition->sborg_offset,
                partition->sb_size,
                partition->part_offset+partition->sb_offset,
                NULL);
            dir_partition(disk_car,partition,verbose, current_cmd);
            io_redir_del_redir(disk_car, partition->part_offset+partition->sborg_offset);
          }
        }
	break;
      case 'l':
      case 'L':
        list_part=interface_load(disk_car,list_part,verbose);
	rewrite=1;
	offset=0;
	pos_num=0;
	pos=list_part;
        break;
      case 'q':
      case '\r':
      case '\n':
      case KEY_ENTER:
#ifdef PADENTER
      case PADENTER:
#endif
      case 'M':
	return list_part;
      default:
/*	log_trace("ask_structure command=%x\n",command); */
	break;
    }
  }
}
#endif

list_part_t *ask_structure(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  if(*current_cmd!=NULL)
    return ask_structure_cli(disk_car, list_part, verbose, current_cmd);
#ifdef HAVE_NCURSES
  return ask_structure_ncurses(disk_car, list_part, verbose, current_cmd);
#else
  return list_part;
#endif
}

static list_part_t *merge_partition_list(list_part_t *list_part,list_part_t *backup_part, const int verbose)
{
  list_part_t *partition;
  for(partition=backup_part;partition!=NULL;partition=partition->next)
  {
    int insert_error=0;
    partition_t *new_partition=partition_new(NULL);
    dup_partition_t(new_partition,partition->part);
    list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
    if(insert_error>0)
      free(new_partition);
  }
  return list_part;
}

#ifdef HAVE_NCURSES
static struct td_list_head *interface_load_ncurses(disk_t *disk_car, backup_disk_t *backup_list, const int verbose)
{
  int offset=0;
  int backup_current_num=0;
  int rewrite=1;
  unsigned int menu=3;   /* default : quit */
  struct td_list_head *backup_current=backup_list->list.next;
  struct td_list_head *backup_walker=NULL;
  struct MenuItem menuLoadBackup[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'L',"Load","Load partition structure from backup and try to locate partition"},
    { 'Q',"Cancel","Don't use backup and try to locate partition"},
    { 0, NULL, NULL }
  };
  char options[20];
  while(1)
  {
    int i;
    if(rewrite)
    {
      aff_copy(stdscr);
      mvwaddstr(stdscr,4,0,disk_car->description(disk_car));
      if(backup_list!=NULL)
      {
	mvwaddstr(stdscr,5,0,"Choose the backup you want to restore:");
	mvwaddstr(stdscr,20,0,"PS: Don't worry you will have to confirm the partition restoration.");
      }
      else
      {
	mvwaddstr(stdscr,5,0,"No backup found!");
      }
      rewrite=0;
    }
    if(backup_list!=NULL)
    {
      backup_disk_t *backup=NULL;
      for(i=0,backup_walker=backup_list->list.next;(backup_walker!=&backup_list->list) && (i<offset);backup_walker=backup_walker->next,i++);
      for(i=offset;(backup_walker!=&backup_list->list) &&((i-offset)<INTER_STRUCTURE);i++,backup_walker=backup_walker->next)
      {
	backup=td_list_entry(backup_walker, backup_disk_t, list);
	wmove(stdscr,8+i-offset,0);
	wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
	if(backup_walker==backup_current)
	{
	  wattrset(stdscr, A_REVERSE);
	  wprintw(stdscr,"%s %s",backup->description,ctime(&backup->my_time));
	  wattroff(stdscr, A_REVERSE);
	} else
	{
	  wprintw(stdscr,"%s %s",backup->description,ctime(&backup->my_time));
	}
      }
      if(i<=INTER_STRUCTURE && backup==NULL)
      {
	strncpy(options,"LQ",sizeof(options));
	menu=0;
      }
      else
      {
	strncpy(options,"PNLQ",sizeof(options));
	menu=2;
      }
    }
    else
    {
      menu=0;
      strncpy(options,"Q",sizeof(options));
    }
    switch(wmenuSelect(stdscr,INTER_DUMP_Y,INTER_DUMP_X, menuLoadBackup, 8, options, MENU_HORIZ| MENU_BUTTON | MENU_ACCEPT_OTHERS, menu))
    {
      case 'q':
      case 'Q':
	return NULL;
      case 'l':
      case 'L':
	if(backup_current==&backup_list->list)
	  return NULL;
	return backup_current;
      case KEY_UP:
	if(backup_current->prev!=&backup_list->list)
	{
	  backup_current=backup_current->prev;
	  backup_current_num--;
	  if(backup_current_num<offset)
	    offset--;
	}
	break;
      case KEY_DOWN:
	if(backup_current->next!=&backup_list->list)
	{
	  backup_current=backup_current->next;
	  backup_current_num++;
	  if(backup_current_num>=offset+INTER_STRUCTURE)
	    offset++;
	}
	break;
      case KEY_PPAGE:
	{
	  for(i=0;(i<INTER_STRUCTURE) && (backup_current->prev!=&backup_list->list);i++)
	  {
	    backup_current=backup_current->prev;
	    backup_current_num--;
	    if(backup_current_num<offset)
	      offset--;
	  }
	}
	break;
      case KEY_NPAGE:
	{
	  for(i=0;(i<INTER_STRUCTURE) && (backup_current->next!=&backup_list->list);i++)
	  {
	    backup_current=backup_current->next;
	    backup_current_num++;
	    if(backup_current_num>=offset+INTER_STRUCTURE)
	      offset++;
	  }
	}
	break;
      default:
	/*	log_trace("ask_structure car=%x\n",car); */
	break;
    }
  }
}
#endif

static list_part_t *interface_load(disk_t *disk_car,list_part_t *list_part, const int verbose)
{
  struct td_list_head *backup_walker=NULL;
  struct td_list_head *backup_current=NULL;
  backup_disk_t *backup_list=partition_load(disk_car,verbose);
  log_info("interface_load\n");
  td_list_for_each(backup_walker,&backup_list->list)
  {
    list_part_t *element;
    backup_disk_t *backup;
    backup=td_list_entry(backup_walker, backup_disk_t, list);
    log_info("%s %s",backup->description,ctime(&backup->my_time));
    for(element=backup->list_part;element!=NULL;element=element->next)
      log_partition(disk_car,element->part);
  }
#ifdef HAVE_NCURSES
  backup_current=interface_load_ncurses(disk_car, backup_list, verbose);
#endif
  if(backup_current!=NULL)
  {
    list_part_t *partition;
    backup_disk_t *backup;
    backup=td_list_entry(backup_current, backup_disk_t, list);
    for(partition=backup->list_part;partition!=NULL;partition=partition->next)
    {
      /* Check partition and load partition name */
      disk_car->arch->check_part(disk_car,verbose,partition->part,0);
    }
    list_part=merge_partition_list(list_part,backup->list_part,verbose);
  } 
  { /* Cleanup */
    struct td_list_head *backup_walker_next = NULL;
    td_list_for_each_safe(backup_walker,backup_walker_next,&backup_list->list)
    {
      backup_disk_t *backup;
      backup=td_list_entry(backup_walker, backup_disk_t, list);
      part_free_list(backup->list_part);
      free(backup);
    }
    free(backup_list);
  }
  return list_part;
}

int interface_superblock(disk_t *disk_car,list_part_t *list_part, char**current_cmd)
{
  const list_part_t *parts;
  const partition_t *old_part=NULL;
  struct MenuItem menuSuperblock[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q',"Quit","Return to Advanced menu"},
    { 0, NULL, NULL }
  };
  aff_buffer(BUFFER_RESET,"Q");
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s",disk_car->description(disk_car));
  wmove(stdscr,5,0);
  mvwaddstr(stdscr,6,0,msg_PART_HEADER_LONG);
#endif
  for(parts=list_part;parts!=NULL;parts=parts->next)
  {
    const partition_t *partition=parts->part;
    if(old_part==NULL ||
      old_part->part_offset!=partition->part_offset ||
      old_part->part_size!=partition->part_size ||
      guid_cmp(old_part->part_type_gpt, partition->part_type_gpt)!=0	||
      old_part->part_type_i386!=partition->part_type_i386 	||
      old_part->part_type_sun!=partition->part_type_sun 	||
      old_part->part_type_mac!=partition->part_type_mac 	||
      old_part->upart_type!=partition->upart_type)
    {
      aff_part_buffer(AFF_PART_BASE, disk_car, partition);
      old_part=partition;
    }
    if(partition->blocksize!=0)
      aff_buffer(BUFFER_ADD,"superblock %lu, blocksize=%u\n",
          (long unsigned)(partition->sb_offset/partition->blocksize),
          partition->blocksize);
  }
  screen_buffer_to_log();
  if(*current_cmd==NULL)
  {
    log_flush();
#ifdef HAVE_NCURSES
    screen_buffer_display(stdscr,"",menuSuperblock);
#endif
  }
  return 0;
}

