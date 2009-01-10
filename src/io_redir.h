/*

    File: io_redir.h

    Copyright (C) 1998-2004 Christophe GRENIER <grenier@cgsecurity.org>
  
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

int io_redir_add_redir(disk_t *disk_car, const uint64_t org_offset, const unsigned int size, const uint64_t new_offset, const void *mem);
int io_redir_del_redir(disk_t *disk_car, uint64_t org_offset);
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
