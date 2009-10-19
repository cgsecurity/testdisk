/*

    File: ppartsel.c

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
#include <ctype.h>      /* isdigit */
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "fnctdsk.h"
#include "dir.h"
#include "list.h"
#include "lang.h"
#include "filegen.h"
#include "photorec.h"
#include "phrecn.h"
#include "log.h"
#include "log_part.h"
#include "hdaccess.h"
#include "ext2grp.h"
#include "pfree_whole.h"
#include "ppartsel.h"
#include "askloc.h"
#include "geometry.h"
#include "addpart.h"
#include "intrfn.h"

extern const arch_fnct_t arch_none;

enum { INIT_SPACE_WHOLE, INIT_SPACE_PREINIT, INIT_SPACE_EXT2_GROUP, INIT_SPACE_EXT2_INODE };

static int spacerange_cmp(const struct td_list_head *a, const struct td_list_head *b)
{
  const alloc_data_t *space_a=td_list_entry(a, const alloc_data_t, list);
  const alloc_data_t *space_b=td_list_entry(b, const alloc_data_t, list);
  if(space_a->start < space_b->start)
    return -1;
  if(space_a->start > space_b->start)
    return 1;
  return space_a->end - space_b->end;
}

#ifdef HAVE_NCURSES
#define INTER_SELECT_X	0
#define INTER_SELECT_Y	(LINES-2)
#define INTER_SELECT	(LINES-2-7-1)
#endif

void menu_photorec(disk_t *disk_car, const int verbose, const char *recup_dir, file_enable_t *file_enable, char **current_cmd, alloc_data_t*list_search_space)
{
  int insert_error=0;
  list_part_t *list_part;
  list_part_t *current_element;
  int allow_partial_last_cylinder=0;
  int paranoid=1;
  int keep_corrupted_file=0;
  unsigned int current_element_num;
  unsigned int mode_ext2=0;
  unsigned int blocksize=0;
  unsigned int expert=0;
  unsigned int lowmem=0;
  unsigned int carve_free_space_only=0;
  int done=0;
  int mode_init_space=(td_list_empty(&list_search_space->list)?INIT_SPACE_WHOLE:INIT_SPACE_PREINIT);
#ifdef HAVE_NCURSES
  int command;
  unsigned int offset=0;
  unsigned int menu=0;
  static const struct MenuItem menuMain[]=
  {
	{'S',"Search","Start file recovery"},
	{'O',"Options","Modify options"},
	{'F',"File Opt","Modify file options"},
	{'G',"Geometry", "Change disk geometry" },
	{'Q',"Quit","Return to disk selection"},
	{0,NULL,NULL}
  };
#endif
  list_part=disk_car->arch->read_part(disk_car,verbose,0);
  {
    partition_t *partition_wd;
    partition_wd=new_whole_disk(disk_car);
    list_part=insert_new_partition(list_part, partition_wd, 0, &insert_error);
    if(insert_error>0)
    {
      free(partition_wd);
    }
  }
  if(list_part==NULL)
    return;
  {
    list_part_t *element;
    for(element=list_part;element!=NULL;element=element->next)
    {
      log_partition(disk_car,element->part);
    }
  }
  if(list_part->next!=NULL)
  {
    current_element_num=1;
    current_element=list_part->next;
  }
  else
  {
    current_element_num=0;
    current_element=list_part;
  }
  while(done==0)
  {
    if(*current_cmd!=NULL)
    {
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(*current_cmd[0]=='\0')
      {
	part_free_list(list_part);
	return;
      }
      if(strncmp(*current_cmd,"search",6)==0)
      {
	char *res;
	(*current_cmd)+=6;
	if(recup_dir!=NULL)
	  res=(char *)recup_dir;
	else
	{
#ifdef HAVE_NCURSES
	  res=ask_location("Do you want to save recovered files in %s%s ? [Y/N]\nDo not choose to write the files to the same partition they were stored on.", "", NULL);
#else
	  res=get_default_location();
#endif
	  if(res!=NULL)
	  {
	    char *new_recup_dir=(char *)MALLOC(strlen(res)+1+strlen(DEFAULT_RECUP_DIR)+1);
	    strcpy(new_recup_dir,res);
	    strcat(new_recup_dir,"/");
	    strcat(new_recup_dir,DEFAULT_RECUP_DIR);
	    if(res!=recup_dir)
	      free(res);
	    res=new_recup_dir;
	  }
	}
	if(res!=NULL)
	{
	  partition_t *partition=current_element->part;
	  if(mode_init_space==INIT_SPACE_EXT2_GROUP)
	  {
	    blocksize=ext2_fix_group(list_search_space, disk_car, partition);
	    if(blocksize==0)
	      display_message("Not a valid ext2/ext3/ext4 filesystem");
	  }
	  else if(mode_init_space==INIT_SPACE_EXT2_INODE)
	  {
	    blocksize=ext2_fix_inode(list_search_space, disk_car, partition);
	    if(blocksize==0)
	      display_message("Not a valid ext2/ext3/ext4 filesystem");
	  }
	  if(td_list_empty(&list_search_space->list))
	  {
	    init_search_space(list_search_space, disk_car, partition);
	  }
	  if(carve_free_space_only>0)
	  {
	    blocksize=remove_used_space(disk_car, partition, list_search_space);
	  }
	  photorec(disk_car, partition, verbose, paranoid, res, keep_corrupted_file,1,file_enable,mode_ext2,current_cmd,list_search_space,blocksize,expert, lowmem, carve_free_space_only);
	}
	if(res!=recup_dir)
	  free(res);
      }
      else if(strncmp(*current_cmd,"options",7)==0)
      {
	int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
	(*current_cmd)+=7;
	interface_options_photorec(&paranoid, &allow_partial_last_cylinder,
	    &keep_corrupted_file, &mode_ext2, &expert, &lowmem, current_cmd);
	if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	  hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
      }
      else if(strncmp(*current_cmd,"fileopt",7)==0)
      {
	(*current_cmd)+=7;
	interface_file_select(file_enable,current_cmd);
      }
      else if(strncmp(*current_cmd,"blocksize,",10)==0)
      {
	(*current_cmd)+=10;
	blocksize=atoi(*current_cmd);
	while(*current_cmd[0]!=',' && *current_cmd[0]!='\0')
	  (*current_cmd)++;
      }
      else if(strncmp(*current_cmd,"geometry,",9)==0)
      {
	(*current_cmd)+=9;
	change_geometry(disk_car,current_cmd);
      }
      else if(strncmp(*current_cmd,"inter",5)==0)
      {	/* Start interactive mode */
	*current_cmd=NULL;
      }
      else if(strncmp(*current_cmd,"wholespace",10)==0)
      {
	(*current_cmd)+=10;
	carve_free_space_only=0;
      }
      else if(strncmp(*current_cmd,"freespace",9)==0)
      {
	(*current_cmd)+=9;
	carve_free_space_only=1;
      }
      else if(strncmp(*current_cmd,"ext2_group,",11)==0)
      {
	unsigned int groupnr;
	(*current_cmd)+=11;
	mode_ext2=1;
	groupnr=atoi(*current_cmd);
	while(*current_cmd[0]!=',' && *current_cmd[0]!='\0')
	  (*current_cmd)++;
	if(mode_init_space==INIT_SPACE_WHOLE)
	  mode_init_space=INIT_SPACE_EXT2_GROUP;
	if(mode_init_space==INIT_SPACE_EXT2_GROUP)
	{
          alloc_data_t *new_free_space;
          new_free_space=(alloc_data_t*)MALLOC(sizeof(*new_free_space));
          /* Temporary storage, values need to be multiplied by group size and aligned */
          new_free_space->start=groupnr;
          new_free_space->end=groupnr;
          new_free_space->file_stat=NULL;
          if(td_list_add_sorted_uniq(&new_free_space->list, &list_search_space->list, spacerange_cmp))
	    free(new_free_space);
        }
      }
      else if(strncmp(*current_cmd,"ext2_inode,",11)==0)
      {
	unsigned int inodenr;
	(*current_cmd)+=11;
	mode_ext2=1;
	inodenr=atoi(*current_cmd);
	while(*current_cmd[0]!=',' && *current_cmd[0]!='\0')
	  (*current_cmd)++;
	if(mode_init_space==INIT_SPACE_WHOLE)
	  mode_init_space=INIT_SPACE_EXT2_INODE;
	if(mode_init_space==INIT_SPACE_EXT2_INODE)
	{
          alloc_data_t *new_free_space;
          new_free_space=(alloc_data_t*)MALLOC(sizeof(*new_free_space));
          /* Temporary storage, values need to be multiplied by group size and aligned */
          new_free_space->start=inodenr;
          new_free_space->end=inodenr;
          new_free_space->file_stat=NULL;
          if(td_list_add_sorted_uniq(&new_free_space->list, &list_search_space->list, spacerange_cmp))
	    free(new_free_space);
        }
      }
      else if(isdigit(*current_cmd[0]))
      {
	list_part_t *element;
	unsigned int order;
	order= atoi(*current_cmd);
	while(*current_cmd[0]!=',' && *current_cmd[0]!='\0')
	  (*current_cmd)++;
	for(element=list_part;element!=NULL && element->part->order!=order;element=element->next);
	if(element!=NULL)
	  current_element=element;
      }
      else
      {
	log_critical("Syntax error in command line: %s\n",*current_cmd);
	part_free_list(list_part);
	return;
      }
    }
#ifdef HAVE_NCURSES
    else
    { /* ncurses interface */
      list_part_t *element;
      unsigned int i;
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description_short(disk_car));
      mvwaddstr(stdscr,6,0,msg_PART_HEADER_LONG);
      for(i=0,element=list_part; element!=NULL && i<offset+INTER_SELECT;element=element->next,i++)
      {
	if(i<offset)
	  continue;
	wmove(stdscr,7+i-offset,0);
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
      wmove(stdscr,7+INTER_SELECT,5);
      wclrtoeol(stdscr);
      if(element!=NULL)
	wprintw(stdscr, "Next");
      command = wmenuSelect(stdscr, INTER_SELECT_Y+1, INTER_SELECT_Y, INTER_SELECT_X, menuMain, 8,
	  (expert==0?"SOFQ":"SOFGQ"), MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, menu);
      switch(command)
      {
	case KEY_UP:
	  if(current_element!=NULL && current_element->prev!=NULL)
	  {
	    current_element=current_element->prev;
	    current_element_num--;
	  }
	  break;
	case KEY_PPAGE:
	  for(i=0; (signed)i<INTER_SELECT && current_element->prev!=NULL; i++)
	  {
	    current_element=current_element->prev;
	    current_element_num--;
	  }
	  break;
	case KEY_DOWN:
	  if(current_element->next!=NULL)
	  {
	    current_element=current_element->next;
	    current_element_num++;
	  }
	  break;
	case KEY_NPAGE:
	  for(i=0; (signed)i<INTER_SELECT && current_element->next!=NULL; i++)
	  {
	    current_element=current_element->next;
	    current_element_num++;
	  }
	  break;
	case 's':
	case 'S':
	  if(current_element!=NULL)
	  {
	    char *res;
	    partition_t *partition=current_element->part;
	    ask_mode_ext2(disk_car, partition, &mode_ext2, &carve_free_space_only);
	    menu=0;
	    if(recup_dir!=NULL)
	      res=(char *)recup_dir;
	    else
	    {
	      res=ask_location("Do you want to save recovered files in %s%s ? [Y/N]\nDo not choose to write the files to the same partition they were stored on.", "", NULL);
	      if(res!=NULL)
	      {
		char *new_recup_dir=(char *)MALLOC(strlen(res)+1+strlen(DEFAULT_RECUP_DIR)+1);
		strcpy(new_recup_dir,res);
		strcat(new_recup_dir,"/");
		strcat(new_recup_dir,DEFAULT_RECUP_DIR);
		if(res!=recup_dir)
		  free(res);
		res=new_recup_dir;
	      }
	    }
	    if(res!=NULL)
	    {
	      if(td_list_empty(&list_search_space->list))
	      {
		init_search_space(list_search_space, disk_car, partition);
	      }
	      if(carve_free_space_only>0)
	      {
		aff_copy(stdscr);
		wmove(stdscr,5,0);
		wprintw(stdscr, "Filesystem analysis, please wait...\n");
		wrefresh(stdscr);
		blocksize=remove_used_space(disk_car, partition, list_search_space);
		/* Only free space is carved, list_search_space is modified.
		 * To carve the whole space, need to quit and reselect the partition */
		done = 1;
	      }
	      photorec(disk_car, partition, verbose, paranoid, res, keep_corrupted_file,1,file_enable,mode_ext2, current_cmd, list_search_space,blocksize,expert, lowmem, carve_free_space_only);
	    }
	    if(res!=recup_dir)
	      free(res);
	  }
	  break;
	case 'o':
	case 'O':
	  {
	    int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
	    interface_options_photorec(&paranoid, &allow_partial_last_cylinder,
		&keep_corrupted_file, &mode_ext2, &expert, &lowmem, current_cmd);
	    if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	      hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
	    menu=1;
	  }
	  break;
	case 'f':
	case 'F':
	  interface_file_select(file_enable, current_cmd);
	  menu=2;
	  break;
	case 'g':
	case 'G':
	  if(expert!=0)
	    change_geometry(disk_car, current_cmd);
	  break;
      case 'a':
      case 'A':
	if(disk_car->arch != &arch_none)
	{
	  list_part=add_partition(disk_car, list_part, current_cmd);
	  current_element=list_part;
	  current_element_num=0;
	}
	break;
	case 'q':
	case 'Q':
	  done = 1;
	  break;
      }
      if(current_element_num<offset)
	offset=current_element_num;
      if(current_element_num>=offset+INTER_SELECT)
	offset=current_element_num-INTER_SELECT+1;
    }
#endif
  }
  log_info("\n");
  part_free_list(list_part);
}
