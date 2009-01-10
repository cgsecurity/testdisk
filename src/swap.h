/*

    file: swap.h

    Copyright (C) 1998-2004,2006,2008 Christophe GRENIER <grenier@cgsecurity.org>
  
    this software is free software; you can redistribute it and/or modify
    it under the terms of the gnu general public license as published by
    the free software foundation; either version 2 of the license, or
    (at your option) any later version.
  
    this program is distributed in the hope that it will be useful,
    but without any warranty; without even the implied warranty of
    merchantability or fitness for a particular purpose.  see the
    gnu general public license for more details.
  
    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 */
#ifdef __cplusplus
extern "C" {
#endif

#define PAGE_SIZE 0x1000        /* PAGE de 4K pour P_LINSWAP */
#define SWAP_SIZE PAGE_SIZE

union swap_header {
  struct
  {
	char reserved[PAGE_SIZE - 10];
	char magic[10];
  } magic;
  struct
  {
	char         bootbits[1024];    /* Space for disklabel etc. */
	unsigned int version;
	unsigned int last_page;
	unsigned int nr_badpages;
/*	char volume_name[16]; */
	unsigned int padding[125];
	unsigned int badpages[1];
  } info;
};

int check_Linux_SWAP(disk_t *disk_car,partition_t *partition,const int verbose);
int recover_Linux_SWAP(disk_t *disk_car, const union swap_header *swap_header,partition_t *partition,const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
