/*

    File: phrecn.h

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
int photorec(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, char *recup_dir, const int keep_corrupted_file, const int interface, file_enable_t *file_enable, const unsigned int mode_ext2, char **current_cmd, alloc_data_t *list_search_space, unsigned int blocksize, const unsigned int expert, const unsigned int lowmem, const unsigned int carve_free_space_only);
void interface_file_select(file_enable_t *files_enable, char**current_cmd);
void interface_options_photorec(int *paranoid, int *allow_partial_last_cylinder, int *keep_corrupted_file, unsigned int *mode_ext2, unsigned int *expert, unsigned int *lowmem, char**current_cmd);
void free_search_space(alloc_data_t *list_search_space);
