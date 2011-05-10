/*

    File: phbs.h

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
#ifdef __cplusplus
extern "C" {
#endif
int photorec_find_blocksize(disk_t *disk_car, partition_t *partition, const int verbose, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, unsigned int *blocksize, alloc_data_t *list_search_space, const time_t real_start_time);
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif

