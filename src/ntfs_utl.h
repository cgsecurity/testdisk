/*

    File: ntfs_utl.h

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
#ifdef __cplusplus
extern "C" {
#endif
ATTR_RECORD * find_attribute(const ATTR_TYPES type, ntfs_attr_search_ctx *ctx);
ATTR_RECORD * find_first_attribute(const ATTR_TYPES type, MFT_RECORD *mft);
int utils_cluster_in_use(ntfs_volume *vol, long long lcn);
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
