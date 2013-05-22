/*

    File: geometryn.c

    Copyright (C) 1998-2013 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "log.h"
#include "hdaccess.h"
#include "autoset.h"
#include "geometry.h"
#include "geometryn.h"

#define MAX_HEADS 255u

int change_geometry_ncurses(disk_t *disk_car)
{
  int done = 0;
  int default_option=4;
  int cyl_modified=0;
  int geo_modified=0;
  while (done==0)
  {
    char def[128];
    char response[128];
    long int tmp_val=0;
    int command;
    static const struct MenuItem menuGeometry[]=
    {
      { 'c', "Cylinders", "Change cylinder geometry" },
      { 'h', "Heads", "Change head geometry" },
      { 's', "Sectors", "Change sector geometry" },
      { 'n', "Sector Size", "Change sector size (WARNING: VERY DANGEROUS!)" },
      { 'q', "Ok", "Done with changing geometry" },
      { 0, NULL, NULL }
    };
    aff_copy(stdscr);
    wmove(stdscr,5,0);
    wprintw(stdscr,"%s, sector size=%u\n",disk_car->description(disk_car),disk_car->sector_size);
    wmove(stdscr,7,0);
    wprintw(stdscr,"Because these numbers change the way that TestDisk looks for partitions");
    wmove(stdscr,8,0);
    wprintw(stdscr,"and calculates their sizes, it's important to have the correct disk geometry.");
    wmove(stdscr,9,0);
    wprintw(stdscr,"PC partitioning programs often make partitions end on cylinder boundaries.");
    wmove(stdscr,11,0);
    wprintw(stdscr,"A partition's CHS values are based on disk translations which make them");
    wmove(stdscr,12,0);
    wprintw(stdscr,"different than its physical geometry. The most common CHS head values");
    wmove(stdscr,13,0);
    wprintw(stdscr,"are: 255, 240 and sometimes 16.");
    wmove(stdscr,INTER_GEOM_Y, INTER_GEOM_X);
    wclrtoeol(stdscr);
    wrefresh(stdscr);
    command=wmenuSimple(stdscr,menuGeometry, default_option);
    switch (command) {
      case 'c':
      case 'C':
        {
          sprintf(def, "%lu", disk_car->geom.cylinders);
          mvwaddstr(stdscr,INTER_GEOM_Y, INTER_GEOM_X, "Enter the number of cylinders: ");
	  wclrtoeol(stdscr);
          if (get_string(stdscr, response, sizeof(response), def) > 0) {
            tmp_val = atol(response);
            if (tmp_val > 0) {
              disk_car->geom.cylinders = tmp_val;
              cyl_modified=1;
	      if(geo_modified==0)
		geo_modified=1;
            } else
              wprintw(stdscr,"Illegal cylinders value");
          }
        }
        default_option=1;
        break;
      case 'h':
      case 'H':
        {
          sprintf(def, "%u", disk_car->geom.heads_per_cylinder);
          mvwaddstr(stdscr,INTER_GEOM_Y, INTER_GEOM_X, "Enter the number of heads (1-255): ");
	  wclrtoeol(stdscr);
          if (get_string(stdscr, response, sizeof(response), def) > 0) {
            tmp_val = atoi(response);
            if (tmp_val > 0 && tmp_val <= MAX_HEADS) {
              disk_car->geom.heads_per_cylinder = tmp_val;
	      if(geo_modified==0)
		geo_modified=1;
              if(cyl_modified==0)
		set_cylinders_from_size_up(disk_car);
            } else
              wprintw(stdscr,"Illegal heads value");
          }
        }
        default_option=2;
        break;
      case 's':
      case 'S':
        {
          sprintf(def, "%u", disk_car->geom.sectors_per_head);
          /* FIXME SUN partition can have more than 63 sectors */
          mvwaddstr(stdscr,INTER_GEOM_Y, INTER_GEOM_X, "Enter the number of sectors per track (1-63): ");
	  wclrtoeol(stdscr);
          if (get_string(stdscr, response, sizeof(response), def) > 0)
          {
            tmp_val = atoi(response);
            /* TODO Check for the maximum value */
            if (tmp_val > 0) {
              disk_car->geom.sectors_per_head = tmp_val;
	      if(geo_modified==0)
		geo_modified=1;
              if(cyl_modified==0)
		set_cylinders_from_size_up(disk_car);
            } else
              wprintw(stdscr,"Illegal sectors value");
          }
        }
        default_option=3;
        break;
      case 'n':
      case 'N':
        {
          sprintf(def, "%u", disk_car->sector_size);
          mvwaddstr(stdscr,INTER_GEOM_Y, INTER_GEOM_X, "Enter the sector size (512, 1024, 2048, 4096, 8192): ");
	  wclrtoeol(stdscr);
          if (get_string(stdscr, response, sizeof(response), def) > 0) {
            tmp_val = atoi(response);
	    if(change_sector_size(disk_car, cyl_modified, tmp_val))
	      wprintw(stdscr,"Illegal sector size");
	    else
	      geo_modified=2;
          }
        }
        default_option=4;
        break;
      case key_ESC:
      case 'q':
      case 'Q':
        done = 1;
        break;
    }
    if(cyl_modified!=0)
      disk_car->disk_size=(uint64_t)disk_car->geom.cylinders*disk_car->geom.heads_per_cylinder*disk_car->geom.sectors_per_head*disk_car->sector_size;
  }
  if(geo_modified!=0)
  {
    disk_car->disk_size=(uint64_t)disk_car->geom.cylinders*disk_car->geom.heads_per_cylinder*disk_car->geom.sectors_per_head*disk_car->sector_size;
#ifdef __APPLE__
    /* On MacOSX if HD contains some bad sectors, the disk size may not be correctly detected */
    disk_car->disk_real_size=disk_car->disk_size;
#endif
    log_info("New geometry\n%s sector_size=%u\n", disk_car->description(disk_car), disk_car->sector_size);
    autoset_unit(disk_car);
    if(geo_modified==2)
      return 1;
  }
  return 0;
}
#endif
