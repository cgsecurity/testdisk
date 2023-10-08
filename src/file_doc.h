/*

    File: file_doc.h

    Copyright (C) 2018 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifndef _FILE_DOC_H
#define _FILE_DOC_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires offset <= 4006;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @*/
void file_check_doc_aux(file_recovery_t *file_recovery, const uint64_t offset);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
