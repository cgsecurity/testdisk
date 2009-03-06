/*

    File: parti386.c

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

#ifdef HAVE_NCURSES
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include "types.h"
#include "common.h"
#include "fnctdsk.h"
#include "intrf.h"
#include "intrfn.h"
#include "chgtypen.h"
#include "parti386.h"
#include "parti386n.h"

extern const arch_fnct_t arch_i386;

list_part_t *add_partition_i386_ncurses(disk_t *disk_car,list_part_t *list_part, char **current_cmd)
{
  int position=0;
  CHS_t start,end;
  partition_t *new_partition=partition_new(&arch_i386);
  start.cylinder=0;
  start.head=0;
  start.sector=1;
  end.cylinder=disk_car->geom.cylinders-1;
  end.head=disk_car->geom.heads_per_cylinder-1;
  end.sector=disk_car->geom.sectors_per_head;
  {
    int done = 0;
    while (done==0)
    {
      int command;
      static struct MenuItem menuGeometry[]=
      {
	{ 'c', "Cylinder", 	"Change starting cylinder" },
	{ 'h', "Head", 		"Change starting head" },
	{ 's', "Sector", 	"Change starting sector" },
	{ 'C', "Cylinder", 	"Change ending cylinder" },
	{ 'H', "Head", 		"Change ending head" },
	{ 'S', "Sector", 	"Change ending sector" },
	{ 'T' ,"Type",		"Change partition type"},
	{ 'd', "Done", "" },
	{ 0, NULL, NULL }
      };
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      new_partition->part_offset=CHS2offset(disk_car,&start);
      new_partition->part_size=CHS2offset(disk_car,&end) - new_partition->part_offset + disk_car->sector_size;
      wmove(stdscr,10, 0);
      wclrtoeol(stdscr);
      aff_part(stdscr, AFF_PART_BASE, disk_car, new_partition);
      wmove(stdscr,INTER_GEOM_Y, INTER_GEOM_X);
      wclrtoeol(stdscr);
      wrefresh(stdscr);
      command=wmenuSimple(stdscr,menuGeometry, position);
      switch (command)
      {
	case 'c':
	  wmove(stdscr, INTER_GEOM_Y, INTER_GEOM_X);
	  start.cylinder=ask_number(start.cylinder,
	      0, disk_car->geom.cylinders-1, "Enter the starting cylinder ");
	  position=1;
	  break;
	case 'h':
	  wmove(stdscr, INTER_GEOM_Y, INTER_GEOM_X);
	  start.head=ask_number(start.head,
	      0, disk_car->geom.heads_per_cylinder-1, "Enter the starting head ");
	  position=2;
	  break;
	case 's':
	  wmove(stdscr, INTER_GEOM_Y, INTER_GEOM_X);
	  start.sector=ask_number(start.sector,
	      1, disk_car->geom.sectors_per_head, "Enter the starting sector ");
	  position=3;
	  break;
	case 'C':
	  wmove(stdscr, INTER_GEOM_Y, INTER_GEOM_X);
	  end.cylinder=ask_number(end.cylinder,
	      start.cylinder, disk_car->geom.cylinders-1, "Enter the ending cylinder ");
	  position=4;
	  break;
	case 'H':
	  wmove(stdscr, INTER_GEOM_Y, INTER_GEOM_X);
	  end.head=ask_number(end.head,
	      0, disk_car->geom.heads_per_cylinder-1, "Enter the ending head ");
	  position=5;
	  break;
	case 'S':
	  wmove(stdscr, INTER_GEOM_Y, INTER_GEOM_X);
	  end.sector=ask_number(end.sector,
	      1, disk_car->geom.sectors_per_head, "Enter the ending sector ");
	  position=6;
	  break;
	case 'T':
	case 't':
	  change_part_type(disk_car,new_partition,current_cmd);
	  position=7;
	  break;
	case key_ESC:
	case 'd':
	case 'D':
	case 'q':
	case 'Q':
	  done = 1;
	  break;
      }
    }
  }
  if((CHS2offset(disk_car,&end)>new_partition->part_offset)&&(new_partition->part_offset>0)&& new_partition->part_type_i386!=P_NO_OS)
  {
    int insert_error=0;
    list_part_t *new_list_part=insert_new_partition(list_part, new_partition,0, &insert_error);
    if(insert_error>0)
    {
      free(new_partition);
      return new_list_part;
    }
    if(arch_i386.test_structure(list_part)==0)
    { /* Check if the partition can be Logical, Bootable or Primary */
      if(parti386_can_be_ext(disk_car,new_partition)!=0)
      {
	new_partition->status=STATUS_LOG;
	if(arch_i386.test_structure(new_list_part)==0)
	  return new_list_part;
      }
      new_partition->status=STATUS_PRIM_BOOT;
      if(arch_i386.test_structure(new_list_part)==0)
	return new_list_part;
      new_partition->status=STATUS_PRIM;
      if(arch_i386.test_structure(new_list_part)==0)
	return new_list_part;
    }
    new_partition->status=STATUS_DELETED;
    return new_list_part;
  }
  free(new_partition);
  return list_part;
}
#endif


