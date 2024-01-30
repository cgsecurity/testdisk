/*

    File: intrf.h

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
#ifndef _INTRF_H
#define _INTRF_H
#ifdef __cplusplus
extern "C" {
#endif

struct MenuItem
{
    const int key; /* Keyboard shortcut; if zero, then there is no more items in the menu item table */
    const char *name; /* Item name, should be eight characters with current implementation */
    const char *desc; /* Item description to be printed when item is selected */
};
#define MAX_LINES		200
#define BUFFER_LINE_LENGTH 	255
#define MAXIMUM_PARTS 		60

#define INTER_OPTION_X  	0
#define INTER_OPTION_Y		10
#define INTER_PARTITION_X  	0
#define INTER_PARTITION_Y	8
#define INTER_MAIN_X		0
#define INTER_MAIN_Y		18
#define INTER_GEOM_X		0
#define INTER_GEOM_Y  		18
/* Constants for menuType parameter of menuSelect function */
#define MENU_HORIZ 		1
#define MENU_VERT 		2
#define MENU_ACCEPT_OTHERS 	4
#define MENU_BUTTON 		8
#define MENU_VERT_WARN		16
#define MENU_VERT_ARROW2VALID	32
/* Miscellenous constants */
#define MENU_SPACING 		2
#define MENU_MAX_ITEMS 		256 /* for simpleMenu function */
#define key_CR 			'\015'
#define key_ESC 		'\033'
/* '\014' == ^L */
#define key_REDRAWKEY 		'\014'

/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @*/
void log_CHS_from_LBA(const disk_t *disk_car, const unsigned long int pos_LBA);

/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \separated(disk_car, partition);
  @*/
const char *aff_part_aux(const unsigned int newline, const disk_t *disk_car, const partition_t *partition);

/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \separated(disk_car, partition);
  @*/
void aff_part_buffer(const unsigned int newline, const disk_t *disk_car, const partition_t *partition);

/*@
  @ requires valid_read_string(nptr);
  @ assigns \nothing;
  @*/
uint64_t atouint64(const char *nptr);

/*@
  @ requires \valid(current_cmd);
  @ requires valid_read_string(*current_cmd);
  @ ensures  valid_read_string(*current_cmd);
  @ assigns  *current_cmd;
  @*/
uint64_t ask_number_cli(char **current_cmd, const uint64_t val_cur, const uint64_t val_min, const uint64_t val_max, const char * _format, ...) __attribute__ ((format (printf, 5, 6)));
void screen_buffer_reset(void);
int screen_buffer_add(const char *_format, ...)  __attribute__ ((format (printf, 1, 2)));
void screen_buffer_to_log(void);

/*@
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ terminates \true;
  @ assigns \nothing;
  @*/
int get_partition_status(const partition_t *partition);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
