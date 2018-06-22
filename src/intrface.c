/*

    File: intrface.c

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "lang.h"
#include "intrf.h"
#include "godmode.h"
#include "fnctdsk.h"
#include "chgtypen.h"
#include "savehdr.h"
#include "dirpart.h"
#include "log.h"
#include "io_redir.h"
#include "tload.h"
#include "intrface.h"
#include "addpart.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#include "addpartn.h"
#endif

#define INTER_DISK_X	0
#define INTER_DISK_Y	7

extern const arch_fnct_t arch_none;

void interface_list(disk_t *disk, const int verbose, const int saveheader, const int backup)
{
  list_part_t *list_part;
  list_part_t *parts;
  log_info("\nAnalyse ");
  log_info("%s\n", disk->description(disk));
  printf("%s\n", disk->description(disk));
  printf(msg_PART_HEADER_LONG);
  list_part=disk->arch->read_part(disk,verbose,saveheader);

  for(parts=list_part; parts!=NULL; parts=parts->next)
  {
    const char *msg;
    const partition_t *partition=parts->part;
    msg=aff_part_aux(AFF_PART_ORDER|AFF_PART_STATUS, disk, partition);
    printf("%s\n", msg);
    if(partition->info[0]!='\0')
      printf("     %s\n", partition->info);
  }
  if(backup>0)
  {
    partition_save(disk, list_part, verbose);
  }
  part_free_list(list_part);
}

static list_part_t *ask_structure_cli(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  const list_part_t *pos=list_part;
  skip_comma_in_command(current_cmd);
  if(check_command(current_cmd,"list",4)==0)
  {
    if(pos!=NULL)
    {
      const partition_t *partition=pos->part;
      if(partition->sb_offset==0 || partition->sb_size==0)
        dir_partition(disk_car, partition, verbose, 0, current_cmd);
      else
      {
        io_redir_add_redir(disk_car,
            partition->part_offset+partition->sborg_offset,
            partition->sb_size,
            partition->part_offset+partition->sb_offset,
            NULL);
        dir_partition(disk_car, partition, verbose, 0, current_cmd);
        io_redir_del_redir(disk_car, partition->part_offset+partition->sborg_offset);
      }
    }
  }
  return list_part;
}

#ifdef HAVE_NCURSES
#define INTER_STRUCTURE	(LINES-12)
static list_part_t *ask_structure_ncurses(disk_t *disk_car,list_part_t *list_part, const int verbose)
{
  int offset=0;
  int pos_num=0;
  list_part_t *pos=list_part;
  int rewrite=1;
  int old_LINES=LINES;
  while(1)
  {
    int i;
    int command;
    list_part_t *parts;
    int structure_status;
    if(old_LINES!=LINES)
    {
      rewrite=1;
      old_LINES=LINES;
    }
    if(rewrite)
    {
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      mvwaddstr(stdscr,5,0,msg_PART_HEADER);
      rewrite=0;
    }
    structure_status=disk_car->arch->test_structure(list_part);
    for(i=0,parts=list_part;
	parts!=NULL && i<offset+INTER_STRUCTURE;
	i++, parts=parts->next)
    {
      if(i<offset)
	continue;
      wmove(stdscr,6+i-offset,0);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      if(parts==pos)
	wattrset(stdscr, A_REVERSE);
      if(structure_status==0 && parts->part->status!=STATUS_DELETED && has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(2));
      if(parts==pos)
	waddstr(stdscr, ">");
      else
	waddstr(stdscr, " ");
      aff_part(stdscr, AFF_PART_STATUS, disk_car, parts->part);
      if(structure_status==0 && parts->part->status!=STATUS_DELETED && has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(0));
      if(parts==pos)
      {
	char buffer_part_size[100];
	wattroff(stdscr, A_REVERSE);
	wmove(stdscr,LINES-1,0);
	wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
	if(parts->part->info[0]!='\0')
	{
	  wprintw(stdscr,"%s, ",parts->part->info);
	}
	size_to_unit(parts->part->part_size, buffer_part_size);
	wprintw(stdscr,"%s", buffer_part_size);
      }
    }
    if(structure_status==0)
    {
      if(list_part!=NULL)
	mvwaddstr(stdscr,LINES-6,0,msg_STRUCT_OK);
    }
    else
    {
      if(has_colors())
	wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(1));
      mvwaddstr(stdscr,LINES-6,0,msg_STRUCT_BAD);
      if(has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(0));
    }
    if(list_part!=NULL && disk_car->arch->msg_part_type!=NULL)
    {
      mvwaddstr(stdscr,LINES-6,16,"Use ");
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
      mvwaddstr(stdscr,LINES-5,0,"Use ");
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
      mvwaddstr(stdscr,LINES-4,0,disk_car->arch->msg_part_type);
    }
    wmove(stdscr,LINES-3,0);
    wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
    waddstr(stdscr,"Keys ");
    /* If the disk can't be partionned, there is no partition to add and no partition to save */
    if(disk_car->arch != &arch_none)
    {
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
    }
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
	case UP_EXFAT:
	case UP_EXT2:
	case UP_EXT3:
	case UP_EXT4:
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
      mvwaddstr(stdscr,LINES-2,5, "Enter");
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
	}
	break;
      case KEY_PPAGE:
	if(list_part!=NULL)
	{
	  only_one_bootable(list_part,pos);
	  for(i=0; i<INTER_STRUCTURE && pos->prev!=NULL; i++)
	  {
	    pos=pos->prev;
	    pos_num--;
	  }
	}
	break;
      case KEY_NPAGE:
	if(list_part!=NULL)
	{
	  only_one_bootable(list_part,pos);
	  for(i=0; i<INTER_STRUCTURE && pos->next!=NULL; i++)
	  {
	    pos=pos->next;
	    pos_num++;
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
	if(disk_car->arch != &arch_none)
	{
	  list_part=add_partition_ncurses(disk_car, list_part);
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
	  change_part_type_ncurses(disk_car, pos->part);
	}
	break;
      case 'p':
      case 'P':
	if(list_part!=NULL)
        {
          const partition_t *partition=pos->part;
	  char *current_cmd=NULL;
          if(partition->sb_offset==0 || partition->sb_size==0)
            dir_partition(disk_car, partition, verbose, 0, &current_cmd);
          else
          {
            io_redir_add_redir(disk_car,
                partition->part_offset+partition->sborg_offset,
                partition->sb_size,
                partition->part_offset+partition->sb_offset,
                NULL);
            dir_partition(disk_car, partition, verbose, 0, &current_cmd);
            io_redir_del_redir(disk_car, partition->part_offset+partition->sborg_offset);
          }
	  rewrite=1;
        }
	break;
      case 'b':
      case 'B':
	if(partition_save(disk_car,list_part,verbose)<0)
	  display_message("Can't create backup.log.\n");
	else
	  display_message("Results saved in backup.log.\n");
	rewrite=1;
        break;
      case 'l':
      case 'L':
	if(disk_car->arch != &arch_none)
	{
	  list_part=interface_load(disk_car,list_part,verbose);
	  rewrite=1;
	  offset=0;
	  pos_num=0;
	  pos=list_part;
	}
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
    if(pos_num<offset)
      offset=pos_num;
    if(pos_num>=offset+INTER_STRUCTURE)
      offset=pos_num-INTER_STRUCTURE+1;
  }
}
#endif

list_part_t *ask_structure(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  if(*current_cmd!=NULL)
    return ask_structure_cli(disk_car, list_part, verbose, current_cmd);
#ifdef HAVE_NCURSES
  return ask_structure_ncurses(disk_car, list_part, verbose);
#else
  return list_part;
#endif
}
