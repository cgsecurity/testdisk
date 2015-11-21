/*

    File: pblocksize.c

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
#include "types.h"
#include "common.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "log.h"
#include "pblocksize.h"

#ifdef HAVE_NCURSES
void menu_choose_blocksize(unsigned int *blocksize, uint64_t *offset, const unsigned int sector_size)
{
  int command;
  unsigned int menu=0;
  const char *optionsBlocksize="BS512487360ACM";
  static const struct MenuItem menuBlocksize[]=
  {
	{'B',"1",""},
	{'S',"256",""},
	{'5',"512",""},
	{'1',"1024",""},
	{'2',"2048",""},
	{'4',"4096",""},
	{'8',"8192",""},
	{'7',"16384",""},
	{'3',"32768",""},
	{'6',"65536",""},
	{'0',"128k",""},
	{'A',"256k",""},
	{'C',"512k",""},
	{'M',"1M",""},
	{0,NULL,NULL}
  };
  switch(sector_size)
  {
    case 256: optionsBlocksize+=1; break;
    case 512: optionsBlocksize+=2; break;
    case 1024: optionsBlocksize+=3; break;
    case 2048: optionsBlocksize+=4; break;
    case 4096: optionsBlocksize+=5; break;
    case 8192: optionsBlocksize+=6; break;
    case 16384: optionsBlocksize+=7;break;
    case 32768: optionsBlocksize+=8; break;
    case 65536: optionsBlocksize+=9; break;
    case 131072: optionsBlocksize+=10; break;
    case 262144: optionsBlocksize+=11; break;
    case 524288: optionsBlocksize+=12; break;
    case 1048576: optionsBlocksize+=13; break;
  }
  switch(*blocksize)
  {
    case 1: menu=0; break;
    case 256: menu=1; break;
    case 512: menu=2; break;
    case 1024: menu=3; break;
    case 2048: menu=4; break;
    case 4096: menu=5; break;
    case 8192: menu=6; break;
    case 16384: menu=7; break;
    case 32768: menu=8; break;
    case 65536: menu=9; break;
    case 131072: menu=10; break;
    case 262144: menu=11; break;
    case 524288: menu=12; break;
    case 1048576: menu=13; break;
  }
  aff_copy(stdscr);
  wmove(stdscr,INTER_PARTITION_Y-1,0);
  wprintw(stdscr,"Please select the block size, press Enter when done.");
  command = wmenuSelect_ext(stdscr, 23, INTER_PARTITION_Y, INTER_PARTITION_X, menuBlocksize, 7,
      optionsBlocksize, MENU_VERT| MENU_BUTTON|MENU_VERT_WARN, &menu,NULL);
  switch(command)
  {
    case 'B': *blocksize=1; break;
    case 'S': *blocksize=256; break;
    case '5': *blocksize=512; break;
    case '1': *blocksize=1024; break;
    case '2': *blocksize=2048; break;
    case '4': *blocksize=4096; break;
    case '8': *blocksize=8192; break;
    case '7': *blocksize=16384; break;
    case '3': *blocksize=32768; break;
    case '6': *blocksize=65536; break;
    case '0': *blocksize=131072; break;
    case 'A': *blocksize=262144; break;
    case 'C': *blocksize=524288; break;
    case 'M': *blocksize=1048576; break;
  }
  *offset=*offset % *blocksize;
  if(*offset%sector_size!=0)
    *offset=0;
  if(sector_size < *blocksize)
  {
    unsigned int quit=0;
    aff_copy(stdscr);
    wmove(stdscr,INTER_PARTITION_Y-2,0);
    wprintw(stdscr,"Please select the offset (0 - %u). Press Up/Down to increase/decrease it,", *blocksize-sector_size);
    wmove(stdscr,INTER_PARTITION_Y-1,0);
    wprintw(stdscr,"Enter when done.");
    do
    {
      wmove(stdscr,INTER_PARTITION_Y,0);
      wclrtoeol(stdscr);
      wprintw(stdscr,"Offset %u",(unsigned int)(*offset));
      switch(wgetch(stdscr))
      {
	case KEY_ENTER:
#ifdef PADENTER
	case PADENTER:
#endif
	case '\n':
	case '\r':
	  quit=1;
	  break;
	case KEY_PPAGE:
	case KEY_UP:
	case KEY_RIGHT:
	case '+':
	  if(*offset + sector_size < *blocksize)
	    *offset+=sector_size;
	  break;
	case KEY_NPAGE:
	case KEY_DOWN:
	case KEY_LEFT:
	case '-':
	  if(*offset >= sector_size)
	    *offset-=sector_size;
	  break;
      }
    } while(quit==0);
  }
}
#endif
