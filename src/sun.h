/*

    File: sun.h

    Copyright (C) 1998-2006 Christophe GRENIER <grenier@cgsecurity.org>
  
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

typedef struct {
  unsigned char info[128];   /* Informative text string */
  unsigned char spare0[14];
  struct sun_info {
    unsigned char spare1;
    unsigned char id;
    unsigned char spare2;
    unsigned char flags;
  } infos[8];
  unsigned char spare1[246]; /* Boot information etc. */
  uint16_t rspeed;     /* Disk rotational speed */
  uint16_t pcylcount;  /* Physical cylinder count */
  uint16_t sparecyl;   /* extra sects per cylinder */
  unsigned char spare2[4];   /* More magic... */
  uint16_t ilfact;     /* Interleave factor */
  uint16_t ncyl;       /* Data cylinder count */
  uint16_t nacyl;      /* Alt. cylinder count */
  uint16_t ntrks;      /* Tracks per cylinder */
  uint16_t nsect;      /* Sectors per track */
  unsigned char spare3[4];   /* Even more magic... */
  struct sun_partition {
    uint32_t start_cylinder;
    uint32_t num_sectors;
  } partitions[8];
  uint16_t magic;      /* Magic number */
  uint16_t csum;       /* Label xor'd checksum */
} sun_disklabel;

#define SUN_PARTITION_I386_SIZE 512

struct struct_sun_partition_i386 {
  unsigned char bootinfo[12];
  uint32_t magic_start;      /* Magic number */
  uint32_t version;
  unsigned char volname[8];
  uint16_t sector_size;
  uint16_t npart;
  unsigned char spare0[40];
  struct sun_info_i386 {
    uint16_t id;
    uint16_t flags;
    uint32_t start_sector;
    uint32_t num_sectors;
  } partitions[16];
  unsigned char spare1[64]; /* timestamps ? */
  unsigned char vollabel[128];
  unsigned char info[52];   /* Informative text string */
  uint16_t magic;      /* Magic number */
  uint16_t csum;       /* Label xor'd checksum */
} __attribute__ ((__packed__));
typedef struct struct_sun_partition_i386 sun_partition_i386;
#define SUN_LABEL_MAGIC         0xDABE
#define SUN_LABEL_MAGIC_START	0x600DDEEE

int recover_sun_i386(disk_t *disk_car, const sun_partition_i386 *sunlabel, partition_t *partition,const int verbose, const int dump_ind);
int check_sun_i386(disk_t *disk_car,partition_t *partition,const int verbose);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
