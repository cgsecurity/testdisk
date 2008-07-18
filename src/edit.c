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
#else
#include <stdio.h>
#endif
#include "fnctdsk.h"
#include "edit.h"
#include "log.h"

#ifdef HAVE_NCURSES
static void interface_editor_position(const disk_t *disk_car, uint64_t *lba);
static int dump_editor(const unsigned char *nom_dump,const unsigned int lng, const int menu_pos);
static void interface_editor_ncurses(disk_t *disk_car);

static void interface_editor_ncurses(disk_t *disk_car)
{
  int done = 0;
  uint64_t hd_offset=0;
  unsigned char *buffer=(unsigned char *)MALLOC(disk_car->sector_size);
  log_info("%s\n",disk_car->description(disk_car));
  while (done==0)
  {
    static struct MenuItem menuEditor[]=
    {
      { 'C', "Change position", "" },
      { 'D', "Dump", "Dump sector" },
      { 'Q', "Quit",""},
      { 0, NULL, NULL }
    };
    switch ( wmenuSelect(stdscr, 24, INTER_DUMP_Y, INTER_DUMP_X, menuEditor, 8, "CDQ", MENU_HORIZ | MENU_BUTTON, 0))
    {
      case 'c':
      case 'C':
	interface_editor_position(disk_car,&hd_offset);
	break;
      case 'd':
      case 'D':
	{
	  int menu_pos=KEY_DOWN;
	  while(done==0)
	  {
	    wmove(stdscr,4,0);
	    wclrtoeol(stdscr);
	    wprintw(stdscr,"%lu ", (unsigned long)(hd_offset/disk_car->sector_size));
	    aff_LBA2CHS(disk_car,hd_offset/disk_car->sector_size);
	    if(disk_car->read(disk_car,disk_car->sector_size, buffer, hd_offset))
	    {
	      wprintw(stdscr,msg_PART_RD_ERR);
	    }
	    {
	      menu_pos=dump_editor(buffer,disk_car->sector_size,menu_pos);
	      switch(menu_pos)
	      {
		case KEY_UP:
		  if(hd_offset>0)
		    hd_offset-=disk_car->sector_size;
		  else
		    menu_pos=KEY_DOWN;
		  break;
		case KEY_DOWN:
		  if(hd_offset<disk_car->disk_size)
		    hd_offset+=disk_car->sector_size;
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

static void interface_editor_position(const disk_t *disk_car,uint64_t *lba)
{
  CHS_t position;
  int done = 0;
  char def[LINE_LENGTH];
  char response[LINE_LENGTH];
  unsigned int tmp_val;
  int command;
  position.cylinder=offset2cylinder(disk_car,*lba);
  position.head=offset2head(disk_car,*lba);
  position.sector=offset2sector(disk_car,*lba);
  while (done==0) {
	static struct MenuItem menuGeometry[]=
	{
	  { 'c', "Cylinders", "Change cylinder" },
	  { 'h', "Heads", "Change head" },
	  { 's', "Sectors", "Change sector" },
	  { 'd', "Done", "Done with changing" },
	  { 0, NULL, NULL }
	};
	wmove(stdscr,INTER_GEOM_Y, INTER_GEOM_X);
	wclrtoeol(stdscr);
	wrefresh(stdscr);
	command=wmenuSimple(stdscr,menuGeometry, 3);
	switch (command) {
	  case 'c':
	  case 'C':
		sprintf(def, "%u", position.cylinder);
		mvwaddstr(stdscr,INTER_GEOM_Y, INTER_GEOM_X, "Enter the number of cylinders: ");
		if (get_string(response, LINE_LENGTH, def) > 0) {
		  tmp_val = atoi(response);
		  if (tmp_val < disk_car->geom.cylinders) {
			position.cylinder = tmp_val;
		  } else
			wprintw(stdscr,"Illegal cylinders value");
		}
		break;
	  case 'h':
	  case 'H':
		sprintf(def, "%u", position.head);
		mvwaddstr(stdscr,INTER_GEOM_Y, INTER_GEOM_X, "Enter the number of heads: ");
		if (get_string(response, LINE_LENGTH, def) > 0) {
		  tmp_val = atoi(response);
		  if (tmp_val < disk_car->geom.heads_per_cylinder) {
			position.head = tmp_val;
		  } else
			wprintw(stdscr,"Illegal heads value");
		}
		break;
	  case 's':
	  case 'S':
		sprintf(def, "%u", position.sector);
		mvwaddstr(stdscr,INTER_GEOM_Y, INTER_GEOM_X, "Enter the number of sectors per track: ");
		if (get_string(response, LINE_LENGTH, def) > 0) {
		  tmp_val = atoi(response);
		  if (tmp_val > 0 && tmp_val <= disk_car->geom.sectors_per_head ) {
			position.sector = tmp_val;
		  } else
			wprintw(stdscr,"Illegal sectors value");
		}
		break;
	  case key_ESC:
	  case 'd':
	  case 'D':
		done = 1;
		break;
	}
  }
  *lba=CHS2offset(disk_car,&position);
}

static int dump_editor(const unsigned char *nom_dump,const unsigned int lng, const int menu_pos)
{
  unsigned int i,j;
  unsigned int pos;
  unsigned char car;
  int done=0;
  unsigned int menu;
  struct MenuItem menuDump[]=
  {
	{ 'P', "Previous",""},
	{ 'N', "Next","" },
	{ 'Q',"Quit","Quit dump section"},
	{ 0, NULL, NULL }
  };
  /* write dump to log file*/
  dump_log(nom_dump, lng);
  /* ncurses interface */
  pos=(menu_pos==KEY_DOWN?0:lng/0x10-DUMP_MAX_LINES);
  menu=(menu_pos==KEY_DOWN?1:0);
  mvwaddstr(stdscr,DUMP_Y,DUMP_X,msg_DUMP_HEXA);
  do
  {
	for (i=pos; (i<lng/0x10)&&((i-pos)<DUMP_MAX_LINES); i++)
	{
	  wmove(stdscr,DUMP_Y+i-pos,DUMP_X);
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
	switch (wmenuSelect(stdscr, 24, INTER_DUMP_Y, INTER_DUMP_X, menuDump, 8, "PNQ", MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, menu))
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
		if(pos<lng/0x10-DUMP_MAX_LINES)
		  pos++;
		else
		  done = KEY_DOWN;
		break;
	  case KEY_PPAGE:
		menu=0;
		if(pos==0)
		  done=KEY_UP;
		if(pos>DUMP_MAX_LINES-1)
		  pos-=DUMP_MAX_LINES-1;
		else
		  pos=0;
		break;
	  case KEY_NPAGE:
		menu=1;
		if(pos==lng/0x10-DUMP_MAX_LINES)
		  done=KEY_DOWN;
		if(pos<lng/0x10-DUMP_MAX_LINES-(DUMP_MAX_LINES-1))
		  pos+=DUMP_MAX_LINES-1;
		else
		  pos=lng/0x10-DUMP_MAX_LINES;
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

void interface_editor(disk_t *disk_car)
{
#ifdef HAVE_NCURSES
  interface_editor_ncurses(disk_car);
#endif
}
