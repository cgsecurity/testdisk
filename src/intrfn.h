/*

    File: intrfn.h

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#ifdef HAVE_NCURSES
#ifdef HAVE_NCURSES_H
#include <ncurses.h>
#elif defined(HAVE_NCURSESW_NCURSES_H)
#include <ncursesw/ncurses.h>
#elif defined(HAVE_NCURSES_NCURSES_H)
#include <ncurses/ncurses.h>
#elif defined(HAVE_NCURSES_CURSES_H)
#include <ncurses/curses.h>
#elif defined(HAVE_CURSES_H)
#include <curses.h>
#endif

void aff_copy(WINDOW *window);
void aff_part(WINDOW *window, const unsigned int newline, const disk_t *disk_car, const partition_t *partition);
int aff_txt(int line, WINDOW *window, const char *_format, ...) __attribute__ ((format (printf, 3, 4)));
int ask_YN(WINDOW *window);
int check_enter_key_or_s(WINDOW *window);
void dump2(WINDOW *window, const void *dump_1, const void *dump_2, const unsigned int lng);
void dump(WINDOW *window,const void *nom_dump,unsigned int lng);
int screen_buffer_display_ext(WINDOW *window, const char *options_org, const struct MenuItem *menuItems, unsigned int *menu);
int screen_buffer_display(WINDOW *window, const char *options_org, const struct MenuItem *menuItems);
int wgetch_nodelay(WINDOW *window);
int wmenuSelect_ext(WINDOW *window, const int yinfo, int y, int x, const struct MenuItem *menuItems, const unsigned int itemLength, const char *available, int menuType, unsigned int *current, int *real_key);
int wmenuSelect(WINDOW *window, const int yinfo, int y, int x, const struct MenuItem *menuItems, const unsigned int itemLength, const char *available, int menuType, unsigned int menuDefault);
int wmenuSimple(WINDOW *window, const struct MenuItem *menuItems, unsigned int menuDefault);
int wmenuUpdate(WINDOW *window, const int yinfo, int y, int x, const struct MenuItem *menuItems, const unsigned int itemLength, const char *available, const int menuType, unsigned int current);
int start_ncurses(const char *prog_name, const char *real_prog_name);
int end_ncurses(void);
#endif
