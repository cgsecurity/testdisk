/*

    File: ntfs_inc.h

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
#if defined(HAVE_LIBNTFS) || defined(HAVE_LIBNTFS3G)
struct ntfs_dir_struct {
	file_info_t *dir_list;
	ntfs_volume *vol;
	my_data_t *my_data;
	dir_data_t *dir_data;
	unsigned long int inode;
#ifdef HAVE_ICONV
        iconv_t cd;
#endif
};
#endif
