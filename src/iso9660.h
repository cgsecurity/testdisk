/*

    File: iso9660.h

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _ISO9660_H
#define _ISO9660_H
#ifdef __cplusplus
extern "C" {
#endif
struct iso_primary_descriptor
{
	char type;
	char id[5];
	char version;
	char unused1;
	char system_id[32];
	char volume_id[32];
	char unused2[8];
	char volume_space_size[8];
	char unused3[32];
	char volume_set_size[4];
	char volume_sequence_number[4];
	char logical_block_size[4];
	char path_table_size[8];
	char type_l_path_tabl[4];
	char opt_type_l_path_table[4];
	char type_m_path_table[4];
	char opt_type_m_path_table[4];
	char root_directory_record[34];
	char volume_set_id[128];
	char publisher_id[128];
	char preparer_id[128];
	char application_id[128];
	char copyright_file_id[37];
	char abstract_file_id[37];
	char bibliographic_file_id[37];
	char creation_date[17];
	char modification_date[17];
	char expiration_date[17];
	char effective_date[17];
	char file_structure_version;
	char unused4;
	char application_data[512];
	char unused5[653];
} __attribute__ ((gcc_struct, __packed__));
#define ISO_PD_SIZE (sizeof(struct iso_primary_descriptor))

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
