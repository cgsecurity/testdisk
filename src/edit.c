/*

    File: edit.c

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>
#include "types.h"
#include "common.h"
#include "lang.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "fnctdsk.h"
#include "edit.h"
#include "log.h"

#ifdef HAVE_NCURSES
#define EDIT_X			0
#define EDIT_Y			7
#define EDIT_MAX_LINES		14
#define INTER_EDIT_X		EDIT_X
#define INTER_EDIT_Y		22

static void interface_editor_location(const disk_t *disk, uint64_t *lba);
static int dump_editor(const unsigned char *nom_dump,const unsigned int lng, const int menu_pos);
static void interface_editor_ncurses(disk_t *disk);

static void interface_editor_ncurses(disk_t *disk)
{
  int done = 0;
  uint64_t hd_offset=0;
  unsigned char *buffer=(unsigned char *)MALLOC(disk->sector_size);
  log_info("%s\n",disk->description(disk));
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s", disk->description_short(disk));
  while (done==0)
  {
    static const struct MenuItem menuEditor[]=
    {
      { 'C', "Change location", "" },
      { 'D', "Dump", "Dump sector" },
      { 'Q', "Quit",""},
      { 0, NULL, NULL }
    };
    switch ( wmenuSelect(stdscr, INTER_EDIT_Y+1, INTER_EDIT_Y, INTER_EDIT_X, menuEditor, 8, "CDQ", MENU_HORIZ | MENU_BUTTON, 0))
    {
      case 'c':
      case 'C':
	interface_editor_location(disk,&hd_offset);
	break;
      case 'd':
      case 'D':
	{
	  int menu_pos=KEY_DOWN;
	  while(done==0)
	  {
	    wmove(stdscr,5,0);
	    wclrtoeol(stdscr);
	    wprintw(stdscr,"%lu ", (unsigned long)(hd_offset/disk->sector_size));
	    aff_LBA2CHS(disk, hd_offset/disk->sector_size);
	    if((unsigned)disk->pread(disk, buffer, disk->sector_size, hd_offset) != disk->sector_size)
	    {
	      wprintw(stdscr,msg_PART_RD_ERR);
	    }
	    {
	      menu_pos=dump_editor(buffer, disk->sector_size, menu_pos);
	      switch(menu_pos)
	      {
		case KEY_UP:
		  if(hd_offset>0)
		    hd_offset-=disk->sector_size;
		  else
		    menu_pos=KEY_DOWN;
		  break;
		case KEY_DOWN:
		  if(hd_offset<disk->disk_size)
		    hd_offset+=disk->sector_size;
		  else
		    menu_pos=KEY_UP;
		  break;
		default:
		  done = 1;
		  break;
	      }
	    }
	  }
	  done = 0;
	}
	break;
      case key_ESC:
      case 'q':
      case 'Q':
	done = 1;
	break;
    }
  }
  free(buffer);
}

static void interface_editor_location(const disk_t *disk, uint64_t *lba)
{
  const struct MenuItem menuGeometry[]=
  {
    { 'c', "Cylinders", "Change cylinder" },
    { 'h', "Heads", "Change head" },
    { 's', "Sectors", "Change sector" },
    { 'l', "Logical Sectors", "Change logical sector" },
    { 'd', "Done", "Done with changing" },
    { 0, NULL, NULL }
  };
  int default_option=4;
  while (1)
  {
    CHS_t location;
    char def[128];
    char response[128];
    unsigned long int tmp_val;
    int command;
    wmove(stdscr,5,0);
    wclrtoeol(stdscr);
    wprintw(stdscr,"%lu ", (unsigned long)(*lba/disk->sector_size));
    aff_LBA2CHS(disk, *lba / disk->sector_size);
    offset2CHS(disk, *lba, &location);
    wmove(stdscr,INTER_GEOM_Y, INTER_GEOM_X);
    wclrtoeol(stdscr);
    wrefresh(stdscr);
    command=wmenuSimple(stdscr, menuGeometry, default_option);
    switch (command) {
      case 'c':
      case 'C':
	sprintf(def, "%lu", location.cylinder);
	mvwaddstr(stdscr,INTER_GEOM_Y, INTER_GEOM_X, "Enter the number of cylinders: ");
	if (get_string(stdscr, response, sizeof(response), def) > 0) {
	  tmp_val = atol(response);
	  if (tmp_val < disk->geom.cylinders) {
	    location.cylinder = tmp_val;
	    *lba=CHS2offset(disk,&location);
	  } else
	    wprintw(stdscr,"Illegal cylinders value");
	}
	default_option=1;
	break;
      case 'h':
      case 'H':
	sprintf(def, "%u", location.head);
	mvwaddstr(stdscr,INTER_GEOM_Y, INTER_GEOM_X, "Enter the number of heads: ");
	if (get_string(stdscr, response, sizeof(response), def) > 0) {
	  tmp_val = atoi(response);
	  if (tmp_val < disk->geom.heads_per_cylinder) {
	    location.head = tmp_val;
	    *lba=CHS2offset(disk,&location);
	  } else
	    wprintw(stdscr,"Illegal heads value");
	}
	default_option=2;
	break;
      case 's':
      case 'S':
	sprintf(def, "%u", location.sector);
	mvwaddstr(stdscr,INTER_GEOM_Y, INTER_GEOM_X, "Enter the number of sectors per track: ");
	if (get_string(stdscr, response, sizeof(response), def) > 0) {
	  tmp_val = atoi(response);
	  if (tmp_val > 0 && tmp_val <= disk->geom.sectors_per_head ) {
	    location.sector = tmp_val;
	    *lba=CHS2offset(disk,&location);
	  } else
	    wprintw(stdscr,"Illegal sectors value");
	}
	default_option=3;
	break;
      case 'l':
      case 'L':
	{
	  sprintf(def, "%lu", (unsigned long)(*lba / disk->sector_size));
	  mvwaddstr(stdscr,INTER_GEOM_Y, INTER_GEOM_X, "Enter the logical sector offset: ");
	  if (get_string(stdscr, response, sizeof(response), def) > 0) {
	    uint64_t l_sector;
	    l_sector= strtoul(response, NULL, 10);
	    l_sector*=disk->sector_size;
	    if (l_sector <= disk->disk_size) {
	      *lba=l_sector;
	    } else
	      wprintw(stdscr,"Illegal logical sector value");
	  }
	  default_option=4;
	}
	break;
      case key_ESC:
      case 'd':
      case 'D':
	return;
    }
  }
}

static int dump_editor(const unsigned char *nom_dump,const unsigned int lng, const int menu_pos)
{
  unsigned int pos;
  int done=0;
  unsigned int menu;
  const struct MenuItem menuDump[]=
  {
	{ 'P', "Previous",""},
	{ 'N', "Next","" },
	{ 'Q',"Quit","Quit dump section"},
	{ 0, NULL, NULL }
  };
  /* write dump to log file*/
  dump_log(nom_dump, lng);
  /* ncurses interface */
  pos=(menu_pos==KEY_DOWN?0:lng/0x10-EDIT_MAX_LINES);
  menu=(menu_pos==KEY_DOWN?1:0);
  mvwaddstr(stdscr, EDIT_Y, EDIT_X, msg_DUMP_HEXA);
  do
  {
    	unsigned int i,j;
  	unsigned char car;
	for (i=pos; (i<lng/0x10)&&((i-pos)<EDIT_MAX_LINES); i++)
	{
	  wmove(stdscr,EDIT_Y+i-pos,EDIT_X);
	  wclrtoeol(stdscr);
	  wprintw(stdscr,"%04X ",i*0x10);
	  for(j=0; j< 0x10;j++)
	  {
		car=*(nom_dump+i*0x10+j);
		wprintw(stdscr,"%02x", car);
		if(j%4==(4-1))
		  wprintw(stdscr," ");
	  }
	  wprintw(stdscr,"  ");
	  for(j=0; j< 0x10;j++)
	  {
		car=*(nom_dump+i*0x10+j);
		if ((car<32)||(car >= 127))
		  wprintw(stdscr,".");
		else
		  wprintw(stdscr,"%c",  car);
	  }
	}
	switch (wmenuSelect(stdscr, INTER_EDIT_Y+1, INTER_EDIT_Y, INTER_EDIT_X, menuDump, 8, "PNQ", MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, menu))
	{
	  case 'p':
	  case 'P':
	  case KEY_UP:
		menu=0;
		if(pos>0)
		  pos--;
		else
		  done=KEY_UP;
		break;
	  case 'n':
	  case 'N':
	  case KEY_DOWN:
		menu=1;
		if(pos<lng/0x10-EDIT_MAX_LINES)
		  pos++;
		else
		  done = KEY_DOWN;
		break;
	  case KEY_PPAGE:
		menu=0;
		if(pos==0)
		  done=KEY_UP;
		if(pos>EDIT_MAX_LINES-1)
		  pos-=EDIT_MAX_LINES-1;
		else
		  pos=0;
		break;
	  case KEY_NPAGE:
		menu=1;
		if(pos==lng/0x10-EDIT_MAX_LINES)
		  done=KEY_DOWN;
		if(pos<lng/0x10-EDIT_MAX_LINES-(EDIT_MAX_LINES-1))
		  pos+=EDIT_MAX_LINES-1;
		else
		  pos=lng/0x10-EDIT_MAX_LINES;
		break;
	  case key_ESC:
	  case 'q':
	  case 'Q':
		done = 'Q';
		break;
	}
  } while(done==0);
  return done;
}
#endif

void interface_editor(disk_t *disk)
{
#ifdef HAVE_NCURSES
  interface_editor_ncurses(disk);
#endif
}
