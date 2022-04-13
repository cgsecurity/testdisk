/*

    File: askloc.h

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

#ifndef _ASKLOC_H
#define _ASKLOC_H
#ifdef __cplusplus
extern "C" {
#endif

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_NCURSES
#endif

/*@
  @ requires \valid(buf + (0 .. size-1));
  @ ensures  valid_string(buf);
  @ ensures  \result == buf;
  @*/
char *td_getcwd(char *buf, unsigned long size);

#ifdef HAVE_NCURSES
/*@
  @ requires \valid(dst + (0 .. dst_size-1));
  @ requires valid_read_string(msg);
  @ requires \separated(dst, msg, src_dir);
  @ assigns  *(dst + (0 .. dst_size-1));
  @*/
void ask_location(char *dst, const unsigned int dst_size, const char *msg, const char *src_dir);
#endif

// ensures \result == \null || (\freeable(\result) && valid_string(\result));
char *get_default_location(void);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
