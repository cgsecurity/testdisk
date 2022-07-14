/*

    File: poptions.h

    Copyright (C) 2013 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#ifndef _POPTIONS_H
#define _POPTIONS_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(current_cmd);
  @ requires valid_read_string(*current_cmd);
  @ requires \valid(options);
  @ requires \separated(options, current_cmd, *current_cmd);
  @ ensures  valid_read_string(*current_cmd);
  @ */
void interface_options_photorec_cli(struct ph_options *options, char**current_cmd);

/*@
  @ requires \valid_read(options);
  @ */
void interface_options_photorec_log(const struct ph_options *options);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
