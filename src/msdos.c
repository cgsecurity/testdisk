/*

    File: msdos.c

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef DJGPP
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <errno.h>
#include "types.h"
#include "common.h"
#include <go32.h>       /* dosmemget/put */
#include <dpmi.h>
#include <bios.h>       /* bios_k* */
#ifdef HAVE_STDLIB_H
#include <stdlib.h>     /* atexit, posix_memalign */
#endif
#include "msdos.h"
#include "fnctdsk.h"
#include "log.h"
#include "hdaccess.h"
#include "alignio.h"

#define HD_RW_BUF_SIZ 0x10
#define HDPARM_BUF_SIZ 0x1A
#define MAX_IO_NBR 3
#define MAX_HD_ERR 100

extern const arch_fnct_t arch_none;

static void free_dos_buffer(void);
static int alloc_cmd_dos_buffer(void);
static int hd_identify_enh_bios(disk_t *param_disk,const int verbose);
static int check_enh_bios(const unsigned int disk, const int verbose);
static int hd_report_error(disk_t *disk_car, const uint64_t hd_offset, const unsigned int count, const int rc);
static const char *disk_description_short(disk_t *disk_car);
static int disk_pread(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t hd_offset);
static int disk_pwrite(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t hd_offset);
static int disk_nopwrite(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset);
static int disk_sync(disk_t *disk_car);
static void disk_clean(disk_t *disk_car);

static int cmd_dos_segment = 0;
static int cmd_dos_selector = 0;

static void free_dos_buffer(void)
{
  __dpmi_free_dos_memory(cmd_dos_selector);
  cmd_dos_segment = cmd_dos_selector = 0;
}

static int alloc_cmd_dos_buffer(void)
{
  if (cmd_dos_segment)
    return 0;
  if ((cmd_dos_segment = __dpmi_allocate_dos_memory(18*DEFAULT_SECTOR_SIZE/16, &cmd_dos_selector))== -1)
  {
    cmd_dos_segment = 0;
    return 1;
  }
#ifdef HAVE_ATEXIT
  atexit(free_dos_buffer);
#endif
  return 0;
}

static void disk_reset_error(disk_t *disk_car)
{
  struct info_disk_struct *data=(struct info_disk_struct *)disk_car->data;
  biosdisk(0, data->disk, 0, 0, 1, 1, NULL);
}

static int hd_pread(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset)
{
  __dpmi_regs r;
  unsigned char buf_cmd[HD_RW_BUF_SIZ];
  int xfer_dos_segment, xfer_dos_selector;
  int nsects;
  unsigned long int hd_offset;
  struct info_disk_struct *data=(struct info_disk_struct *)disk_car->data;
  nsects=count/disk_car->sector_size;
  hd_offset=offset/disk_car->sector_size;
  if(data->mode_enh==0)
  { /* Limite CHS = 1023,255,63 = 8,064Mo ~= 7.8 Go */
    int head, track, sector;
    if(data->geo_phys.sectors_per_head==0)
    {
      log_critical("hd_pread: BUG geo_phys.sectors_per_head=0 !\n");
      return -1;
    }
    sector=(hd_offset%data->geo_phys.sectors_per_head)+1;
    hd_offset/=data->geo_phys.sectors_per_head;
    head=hd_offset%data->geo_phys.heads_per_cylinder;
    track=hd_offset/data->geo_phys.heads_per_cylinder;
    if(track<1024)
    {
      const int res=biosdisk(2, data->disk, head, track, sector, nsects, buf);
      return (res!=0 ? -res: count);
    }
    return -1;
  }
  if(cmd_dos_segment==0)
    if(alloc_cmd_dos_buffer())
      return -1;
  if ( (xfer_dos_segment=__dpmi_allocate_dos_memory((count + 15) >> 4, &xfer_dos_selector)) == -1 )
    return -1;
  *(uint16_t*)&buf_cmd[0]=HD_RW_BUF_SIZ;
  *(uint16_t*)&buf_cmd[2]=nsects;
  *(uint32_t*)&buf_cmd[0x4]=xfer_dos_segment<<16;
  *(uint32_t*)&buf_cmd[0x8]=hd_offset;
  *(uint32_t*)&buf_cmd[0xC]=0;

  r.x.ds = cmd_dos_segment;
  r.x.si = 0;
  r.h.dl = data->disk;
  r.h.ah = 0x42;        /* Extended read */
  dosmemput(&buf_cmd, HD_RW_BUF_SIZ, cmd_dos_segment<<4);
  __dpmi_int(0x13, &r);
  dosmemget(xfer_dos_segment<<4, count, buf);
  __dpmi_free_dos_memory(xfer_dos_selector);
  return (r.h.ah!=0 ? -r.h.ah : count);
}

static int hd_pwrite(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset)
{
  __dpmi_regs r;
  unsigned char buf_cmd[HD_RW_BUF_SIZ];
  int xfer_dos_segment, xfer_dos_selector;
  int nsects;
  unsigned long int hd_offset;
  struct info_disk_struct *data=(struct info_disk_struct *)disk_car->data;
  nsects=count/disk_car->sector_size;
  hd_offset=offset/disk_car->sector_size;

  if(data->mode_enh==0)
  { /* Limite CHS = 1023,255,63 = 8,064Mo ~= 7.8 Go */
    int head, track, sector;
    if(data->geo_phys.sectors_per_head==0)
    {
      log_critical("hd_pwrite: BUG geo_phys.sectors_per_head=0 !\n");
      return -1;
    }
    sector=(hd_offset%data->geo_phys.sectors_per_head)+1;
    hd_offset/=data->geo_phys.sectors_per_head;
    head=hd_offset%data->geo_phys.heads_per_cylinder;
    track=hd_offset/data->geo_phys.heads_per_cylinder;
    if(track<1024)
    {
      const int res=biosdisk(3, data->disk, head, track, sector, nsects, buf);
      return (res!=0 ? -res : count);
    }
    return -1;
  }
  if(cmd_dos_segment==0)
    if(alloc_cmd_dos_buffer())
      return -1;
  if ( (xfer_dos_segment=__dpmi_allocate_dos_memory((count + 15) >> 4, &xfer_dos_selector)) == -1 )
    return -1;
  *(uint16_t*)&buf_cmd[0]=HD_RW_BUF_SIZ;
  *(uint16_t*)&buf_cmd[2]=nsects;
  *(uint32_t*)&buf_cmd[0x4]=xfer_dos_segment<<16;
  *(uint32_t*)&buf_cmd[0x8]=hd_offset;
  *(uint32_t*)&buf_cmd[0xC]=0;

  r.x.ds = cmd_dos_segment;
  r.x.si = 0;
  r.h.dl = data->disk;
  r.x.ax = 0x4300;
  dosmemput(buf, count, xfer_dos_segment<<4);
  dosmemput(&buf_cmd, HD_RW_BUF_SIZ, cmd_dos_segment<<4);
  __dpmi_int(0x13, &r);
  __dpmi_free_dos_memory(xfer_dos_selector);
  return (r.h.ah!=0 ? -r.h.ah : count);
}

static int check_enh_bios(const unsigned int disk, const int verbose)
{
  __dpmi_regs r;
  r.h.ah = 0x41;
  r.x.bx = 0x55AA;
  r.h.dl = disk;
  __dpmi_int(0x13, &r);
  if(r.x.bx != 0xAA55)  /* INT 13 Extensions not installed */
  {
    if(verbose>0)
      log_warning("Disk %02X - INT 13 Extensions not installed\n",disk);
    return 0;
  }
  if(verbose>0)
  {
    log_info("Disk %02X ",disk);
    switch(r.h.ah)
    {
      case 0x01:
	log_info("Enhanced BIOS 1.x");
	break;
      case 0x20:
	log_info("Enhanced BIOS 2.0 / EDD-1.0");
	break;
      case 0x21:
	log_info("Enhanced BIOS 2.1 / EDD-1.1");
	break;
      case 0x30:
	log_info("Enhanced BIOS EDD-3.0");
	break;
      default:
	log_info("Enhanced BIOS unknown %02X",r.h.ah);
	break;
    }
    if((r.x.cx & 1)!=0)
      log_info(" - R/W/I");
    if((r.x.cx & 4)!=0)
      log_info(" - Identify");
    log_info("\n");
  }
  return ((r.x.cx&1)!=0);
}

static int hd_identify_enh_bios(disk_t *disk_car,const int verbose)
{
  uint64_t computed_size;
  int compute_LBA=0;
  __dpmi_regs r;
  unsigned char buf[0x200];	/* Don't change it! */
  struct info_disk_struct *data=(struct info_disk_struct *)disk_car->data;
  if(cmd_dos_segment==0)
    if(alloc_cmd_dos_buffer())
      return 1;
  buf[0]=HDPARM_BUF_SIZ;
  buf[1]=0;
  r.h.ah = 0x48;
  r.x.ds = cmd_dos_segment;
  r.x.si = 0;
  r.h.dl = data->disk;
  dosmemput(&buf, HDPARM_BUF_SIZ, cmd_dos_segment<<4);
  __dpmi_int(0x13, &r);
  dosmemget(cmd_dos_segment<<4, HDPARM_BUF_SIZ, &buf);
  if(r.h.ah)
    return 1;
  disk_car->geom.cylinders=*(uint16_t*)&buf[0x04];
  disk_car->geom.heads_per_cylinder=*(uint16_t*)&buf[0x08];
  disk_car->geom.sectors_per_head=*(uint16_t*)&buf[0x0C];
  disk_car->disk_size=(*(uint32_t*)&buf[0x10])*(uint64_t)disk_car->sector_size;
  if(disk_car->disk_size==0)
  {
    if(disk_car->geom.cylinders==0 || disk_car->geom.heads_per_cylinder==0 || disk_car->geom.sectors_per_head==0)
    {
      if(verbose>0)
	log_warning("hd_identify_enh_bios: No size returned by BIOS.\n");
      return 1;
    }
    else
    {
      compute_LBA=1;
      disk_car->disk_size=(uint64_t)disk_car->geom.cylinders*disk_car->geom.heads_per_cylinder*disk_car->geom.sectors_per_head*disk_car->sector_size;
      if(verbose>0)
        log_verbose("Computes LBA from CHS\n");
    }
  }
  else
  {
    if(disk_car->geom.cylinders>0 && disk_car->geom.heads_per_cylinder>0 && disk_car->geom.sectors_per_head>0)
    {
      /* Some bios are buggy */
      if(disk_car->disk_size>(uint64_t)(disk_car->geom.cylinders+1)*disk_car->geom.heads_per_cylinder*disk_car->geom.sectors_per_head*disk_car->sector_size)
      {
        disk_car->geom.cylinders=disk_car->disk_size /
	  disk_car->geom.heads_per_cylinder /
	  disk_car->geom.sectors_per_head /
	  disk_car->sector_size;
        if(verbose>0)
          log_verbose("Computes C from number of sectors\n");
      }
    }
    else
    {
      if(verbose>0)
        log_verbose("Computes CHS from number of sectors\n");
      disk_car->geom.heads_per_cylinder=255;
      disk_car->geom.sectors_per_head=63;
      disk_car->geom.cylinders=disk_car->disk_size /
	disk_car->geom.heads_per_cylinder /
	disk_car->geom.sectors_per_head /
	disk_car->sector_size;
    }
  }
  if(disk_car->geom.sectors_per_head==0)
  {
    data->bad_geometry=1;
    disk_car->geom.sectors_per_head=1;
    log_critical("Incorrect number of sectors\n");
  }
  if(disk_car->geom.sectors_per_head>63)
  {
/*    data->bad_geometry=1; */
    log_critical("Incorrect number of sectors\n");
  }
  if(disk_car->geom.heads_per_cylinder>255)
  {
    data->bad_geometry=1;
    log_critical("Incorrect number of heads\n");
  }
  computed_size=(uint64_t)disk_car->geom.cylinders*disk_car->geom.heads_per_cylinder*disk_car->geom.sectors_per_head*disk_car->sector_size;
  if(verbose>0 || data->bad_geometry!=0)
    log_info("LBA %lu, computed %lu (CHS=%lu,%u,%u)\n",
	(long unsigned)(disk_car->disk_size/disk_car->sector_size),
	(long unsigned)(computed_size/disk_car->sector_size),
	disk_car->geom.cylinders,
	disk_car->geom.heads_per_cylinder,
	disk_car->geom.sectors_per_head);
  if(compute_LBA)
    disk_car->disk_size=computed_size;
  else
  {
    if(disk_car->disk_size < computed_size)
    {
      log_info("Computes LBA from CHS, previous value may be false.\n");
      disk_car->disk_size=computed_size;
    }
  }
  disk_car->disk_real_size=disk_car->disk_size;
  data->geo_phys.cylinders=disk_car->geom.cylinders;
  data->geo_phys.heads_per_cylinder=disk_car->geom.heads_per_cylinder;
  data->geo_phys.sectors_per_head=disk_car->geom.sectors_per_head;
  if(verbose>0)
  {
    log_info("hd_identify_enh_bios\n");
    log_info("%s\n",disk_description(disk_car));
    log_info("LBA size=%lu\n",(long unsigned)(disk_car->disk_size/disk_car->sector_size));
  }
  return 0;
}

disk_t *hd_identify(const int verbose, const unsigned int disk, const int testdisk_mode)
{
  unsigned char buf[0x200];
  memset(buf,0,sizeof(buf));
  /* standard BIOS access */
  if(biosdisk(8,disk,0,0,1,1,buf))
    return NULL;
  if(verbose>1)
    log_verbose("Disk %02X %u max %02X\n",disk,buf[2],(0x80+buf[2]-1));
  if(disk>(unsigned int)(0x80+buf[2]-1))
    return NULL;
  {
    char device[100];
    struct info_disk_struct*data=(struct info_disk_struct*)MALLOC(sizeof(*data));
    disk_t *disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
    data->disk=disk;
    data->bad_geometry=0;
    data->mode_enh=0;
    disk_car->arch=&arch_none;
    snprintf(device,sizeof(device),"/dev/sda%u",disk);
    disk_car->device=strdup(device);
    disk_car->model=NULL;
    disk_car->write_used=0;
    disk_car->autodetect=0;
    disk_car->sector_size=DEFAULT_SECTOR_SIZE;
    disk_car->description=disk_description;
    disk_car->description_short=disk_description_short;
    disk_car->pread=disk_pread;
    disk_car->pwrite=((testdisk_mode&TESTDISK_O_RDWR)==TESTDISK_O_RDWR?disk_pwrite:disk_nopwrite);
    disk_car->sync=disk_sync;
    disk_car->access_mode=testdisk_mode;
    disk_car->clean=disk_clean;
    disk_car->data=data;
    disk_car->geom.cylinders=1+(((buf[0] & 0x0C0)<<2)|buf[1]);
    disk_car->geom.heads_per_cylinder=1+buf[3];
    disk_car->geom.sectors_per_head=buf[0] & 0x3F;
    if(disk_car->geom.heads_per_cylinder>255)
    { /* Problem found by G Rowe */
      log_critical("BIOS reports an invalid heads number\n");
      data->bad_geometry=1;
      disk_car->geom.heads_per_cylinder=255;
    }
    if(disk_car->geom.sectors_per_head==0)
    { /* Problem found by Brian Barrett */
      log_critical("BIOS reports an invalid number of sectors per head\n");
      data->bad_geometry=1;
      disk_car->geom.sectors_per_head=1;
    }
    disk_car->disk_size=(uint64_t)disk_car->geom.cylinders*disk_car->geom.heads_per_cylinder*disk_car->geom.sectors_per_head*disk_car->sector_size;
    disk_car->disk_real_size=disk_car->disk_size;
    data->geo_phys.cylinders=disk_car->geom.cylinders;
    data->geo_phys.heads_per_cylinder=disk_car->geom.heads_per_cylinder;
    data->geo_phys.sectors_per_head=disk_car->geom.sectors_per_head;
    if(verbose>0)
      log_info("%s\n",disk_description(disk_car));
    if(check_enh_bios(disk,verbose))
    {
      /* enhanced BIOS access */
      disk_t *param_disk_enh=(disk_t*)MALLOC(sizeof(*param_disk_enh));
      param_disk_enh->write_used=0;
      param_disk_enh->sector_size=disk_car->sector_size;
      param_disk_enh->data=data;
      data->mode_enh=1;
      if(!hd_identify_enh_bios(param_disk_enh,verbose))
      {
	/* standard geometry H,S, compute C from LBA */
	disk_car->disk_size=param_disk_enh->disk_size;
	disk_car->disk_real_size=disk_car->disk_size;
	disk_car->geom.cylinders=(disk_car->disk_size/disk_car->geom.heads_per_cylinder)/disk_car->geom.sectors_per_head/disk_car->sector_size;
      }
      else
	data->mode_enh=0;
      free(param_disk_enh);
    }
    disk_car->unit=UNIT_CHS;
    return disk_car;
  }
}

const char *disk_description(disk_t *disk_car)
{
  struct info_disk_struct *data=(struct info_disk_struct *)disk_car->data;
  char buffer_disk_size[100];
  size_to_unit(disk_car->disk_size, buffer_disk_size),
  snprintf(disk_car->description_txt, sizeof(disk_car->description_txt),"Disk %2x - %s - CHS %lu %u %u%s",
      data->disk, buffer_disk_size,
      disk_car->geom.cylinders, disk_car->geom.heads_per_cylinder, disk_car->geom.sectors_per_head,
      data->bad_geometry!=0?" (Buggy BIOS)":"");
  return disk_car->description_txt;
}

static const char *disk_description_short(disk_t *disk_car)
{
  struct info_disk_struct *data=(struct info_disk_struct *)disk_car->data;
  char buffer_disk_size[100];
  size_to_unit(disk_car->disk_size, buffer_disk_size);
  snprintf(disk_car->description_short_txt, sizeof(disk_car->description_txt),"Disk %2x - %s",
      data->disk, buffer_disk_size);
  return disk_car->description_short_txt;
}

static int disk_pread_aux(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset)
{
  struct info_disk_struct *data=(struct info_disk_struct *)disk_car->data;
  if(data->geo_phys.cylinders>0 && offset+count>disk_car->disk_size)
  {
    log_error("disk_pread_aux: Don't read after the end of the disk\n");
    return -1;
  }
  {
    uint64_t read_offset=0;
    do
    {
      int i=0;
      int rc;
      unsigned int read_size;
      read_size=count-read_offset>16*512?16*512:count-read_offset;
      do
      {
        rc=hd_pread(disk_car, (char*)buf+read_offset, read_size, offset+read_offset);
        if(rc < 0)
          disk_reset_error(disk_car);
      } while(rc!=read_size && rc!=-1 && ++i<MAX_IO_NBR);
      // <0 invalid function in AH or invalid parameter
      if(rc < 0)
      {
        log_error("disk_pread_aux failed ");
        hd_report_error(disk_car, offset, count, -rc);
      }
      if(rc != read_size)
	return (read_offset==0 ? rc : read_offset);
      read_offset+=read_size;
    } while(read_offset<count);
  }
  return count;
}

static int disk_pread(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset)
{
  return align_pread(&disk_pread_aux, disk_car, buf, count, offset);
}

static int disk_pwrite_aux(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t hd_offset)
{
  int i=0;
  int rc;
  disk_car->write_used=1;
  {
    rc=hd_pwrite(disk_car, buf, count, hd_offset);
    if(rc < 0)
      disk_reset_error(disk_car);
  } while(rc==-4 && ++i<MAX_IO_NBR);
  /* 4=sector not found/read error */
  if(rc < 0)
  {
    log_error("disk_pwrite error\n");
    hd_report_error(disk_car, hd_offset, count, -rc);
  }
  return rc;
}

static int disk_pwrite(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset)
{
  return align_pwrite(&disk_pread_aux, &disk_pwrite_aux, disk_car, buf, count, offset);
}

static int disk_nopwrite(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset)
{
  struct info_disk_struct *data=(struct info_disk_struct *)disk_car->data;
  log_warning("disk_nopwrite(%d,%u,buffer,%lu(%u/%u/%u)) write refused\n", data->disk,
      (unsigned)(count/disk_car->sector_size),(long unsigned)(offset/disk_car->sector_size),
      offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset));
  return -1;
}

static int disk_sync(disk_t *disk_car)
{
  errno=EINVAL;
  return -1;
}

static void disk_clean(disk_t *disk_car)
{
  /*
  if(disk_car->data!=NULL)
  {
    struct info_disk_struct *data=disk_car->data;
  }
  */
  generic_clean(disk_car);
}

static int hd_report_error(disk_t *disk_car, const uint64_t hd_offset, const unsigned int count, const int rc)
{
  log_error(" lba=%lu(%u/%u/%u) nbr_sector=%u, rc=%d\n",(long unsigned int)(hd_offset/disk_car->sector_size),
      offset2cylinder(disk_car,hd_offset),offset2head(disk_car,hd_offset),offset2sector(disk_car,hd_offset),
      count/disk_car->sector_size,rc);
  switch(rc)
  {
    case 0x00: log_error("successful completion"); break;
    case 0x01: log_error("invalid function in AH or invalid parameter"); break;
    case 0x02: log_error("address mark not found"); break;
    case 0x03: log_error("disk write-protected"); break;
    case 0x04: log_error("sector not found/read error"); break;
    case 0x05: log_error("reset failed (hard disk)"); break;
    case 0x06: log_error("disk changed (floppy)"); break;
    case 0x07: log_error("drive parameter activity failed (hard disk)"); break;
    case 0x08: log_error("DMA overrun"); break;
    case 0x09: log_error("data boundary error (attempted DMA across 64K boundary or >80h sectors)"); break;
    case 0x0A: log_error("bad sector detected (hard disk)"); break;
    case 0x0B: log_error("bad track detected (hard disk)"); break;
    case 0x0C: log_error("unsupported track or invalid media"); break;
    case 0x0D: log_error("invalid number of sectors on format (PS/2 hard disk)"); break;
    case 0x0E: log_error("control data address mark detected (hard disk)"); break;
    case 0x0F: log_error("DMA arbitration level out of range (hard disk)"); break;
    case 0x10: log_error("uncorrectable CRC or ECC error on read"); break;
    case 0x11: log_error("data ECC corrected (hard disk)"); break;
    case 0x20: log_error("controller failure"); break;
    case 0x31: log_error("no media in drive (IBM/MS INT 13 extensions)"); break;
    case 0x32: log_error("incorrect drive type stored in CMOS (Compaq)"); break;
    case 0x40: log_error("seek failed"); break;
    case 0x80: log_error("timeout (not ready)"); break;
    case 0xAA: log_error("drive not ready (hard disk)"); break;
    case 0xB0: log_error("volume not locked in drive (INT 13 extensions)"); break;
    case 0xB1: log_error("volume locked in drive (INT 13 extensions)"); break;
    case 0xB2: log_error("volume not removable (INT 13 extensions)"); break;
    case 0xB3: log_error("volume in use (INT 13 extensions)"); break;
    case 0xB4: log_error("lock count exceeded (INT 13 extensions)"); break;
    case 0xB5: log_error("valid eject request failed (INT 13 extensions)"); break;
    case 0xB6: log_error("volume present but read protected (INT 13 extensions)"); break;
    case 0xBB: log_error("undefined error (hard disk)"); break;
    case 0xCC: log_error("write fault (hard disk)"); break;
    case 0xE0: log_error("status register error (hard disk)"); break;
    case 0xFF: log_error("sense operation failed (hard disk)"); break;
  }
  log_error("\n");
  return 0;
}
#endif
