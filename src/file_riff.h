/*

    File: file_riff.h

    Copyright (C) 2021 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifndef _FILE_RIFF_H
#define _FILE_RIFF_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires file_recovery->data_check==&data_check_avi_stream;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
data_check_t data_check_avi_stream(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
