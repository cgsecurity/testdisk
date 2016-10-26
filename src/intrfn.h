/*

    File: intrfn.h

    Copyright (C) 2007-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_NCURSES
#ifdef HAVE_NCURSES_H
#include <ncurses.h>
#elif defined(HAVE_NCURSESW_NCURSES_H)
#include <ncursesw/ncurses.h>
#elif defined(HAVE_NCURSESW_CURSES_H)
#include <ncursesw/curses.h>
#elif defined(HAVE_NCURSES_NCURSES_H)
#include <ncurses/ncurses.h>
#elif defined(HAVE_NCURSES_CURSES_H)
#include <ncurses/curses.h>
#elif defined(HAVE_CURSES_H)
#include <curses.h>
#endif

void aff_copy(WINDOW *window);
void aff_copy_short(WINDOW *window);
void aff_LBA2CHS(const disk_t *disk_car, const unsigned long int pos_LBA);
void aff_part(WINDOW *window, const unsigned int newline, const disk_t *disk_car, const partition_t *partition);
uint64_t ask_number(const uint64_t val_cur, const uint64_t val_min, const uint64_t val_max, const char * _format, ...) __attribute__ ((format (printf, 4, 5)));
int ask_YN(WINDOW *window);
int ask_confirmation(const char*_format, ...) __attribute__ ((format (printf, 1, 2)));
int check_enter_key_or_s(WINDOW *window);
void dump2(WINDOW *window, const void *dump_1, const void *dump_2, const unsigned int lng);
void dump(WINDOW *window,const void *nom_dump,unsigned int lng);
void dump_ncurses(const void *nom_dump, unsigned int lng);
void not_implemented(const char *msg);
int screen_buffer_display_ext(WINDOW *window, const char *options_org, const struct MenuItem *menuItems, unsigned int *menu);
int screen_buffer_display(WINDOW *window, const char *options_org, const struct MenuItem *menuItems);
void screen_buffer_to_interface(void);
int wmenuSelect_ext(WINDOW *window, const int yinfo, const int y, const int x, const struct MenuItem *menuItems, const unsigned int itemLength, const char *available, const int menuType, unsigned int *current, int *real_key);
int wmenuSelect(WINDOW *window, const int yinfo, const int y, const int x, const struct MenuItem *menuItems, const unsigned int itemLength, const char *available, const int menuType, const unsigned int menuDefault);
int wmenuSimple(WINDOW *window, const struct MenuItem *menuItems, const unsigned int menuDefault);
int menu_to_command(const unsigned int yinfo, const unsigned int y, const unsigned int x, const struct MenuItem *menuItems, const unsigned int itemLength, const char *available, const int menuType, const unsigned int y_real, const unsigned int x_real);
int start_ncurses(const char *prog_name, const char *real_prog_name);
int end_ncurses(void);
int vaff_txt(int line, WINDOW *window, const char *_format, va_list ap) __attribute__((format(printf, 3, 0)));
char *ask_log_location(const char*filename, const int errsv);
int get_string(WINDOW *window, char *str, const int len, const char *def);
uint64_t ask_int_ncurses(const char *string);
const char *ask_string_ncurses(const char *string);
#endif

const char *td_curses_version(void);
void display_message(const char*msg);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
