/*

    File: hdaccess.c

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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
 
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* lseek, read, write, close */
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h> 	/* open */
#endif
#include <stdio.h>
#include <errno.h>
#include "types.h"
#ifdef HAVE_LINUX_TYPES_H
#include <linux/types.h>
#endif
#include "common.h"
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_DISKLABEL_H
#include <sys/disklabel.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>	/* BLKFLSBUF */
#endif
#ifdef HAVE_LINUX_HDREG_H
#include <linux/hdreg.h>
#endif
#ifdef HAVE_SYS_DISK_H
#include <sys/disk.h>
#endif
#ifdef HAVE_FEATURES_H
#include <features.h>
#endif
#ifdef HAVE_SYS_DKIO_H
#include <sys/dkio.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
/* linux/fs.h may not be needed because sys/mount.h is present */
/* #ifdef HAVE_LINUX_FS_H */
/* #include <linux/fs.h> */
/* #endif */
#ifdef HAVE_WINDEF_H
#include <windef.h>
#endif
#ifdef HAVE_WINBASE_H
#include <stdarg.h>
#include <winbase.h>
#endif
#ifdef HAVE_WINIOCTL_H
#include <winioctl.h>
#endif
#ifdef HAVE_FNCTL_H
#include <fnctl.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>     /* atexit, posix_memalign */
#endif

#ifdef DJGPP
#include <go32.h>       /* dosmemget/put */
#include <dpmi.h>
#include <bios.h>       /* bios_k* */
#elif defined(__CYGWIN__)
#include <io.h>
#include <windows.h>
#include <winnt.h>
#endif
#include "fnctdsk.h"
#include "ewf.h"
#include "log.h"
#include "hdaccess.h"

extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_mac;

struct info_file_struct
{
  int handle;
  char file_name[DISKNAME_MAX];
  int mode;
};

static void autoset_geometry(disk_t * disk_car, const unsigned char *buffer, const int verbose);
static const char *file_description(disk_t *disk_car);
static const char *file_description_short(disk_t *disk_car);
static int file_clean(disk_t *disk_car);
static int file_read(disk_t *disk_car, const unsigned int count, void *buf, const uint64_t offset);
static int file_write(disk_t *disk_car, const unsigned int count, const void *buf, const uint64_t offset);
static int file_nowrite(disk_t *disk_car, const unsigned int count, const void *buf, const uint64_t offset);
static int file_sync(disk_t *disk_car);
#ifndef DJGPP
static disk_t *disk_get_geometry(const int hd_h, const char *device, const int verbose);
#endif
#if defined(__CYGWIN__) || defined(__MINGW32__)
static disk_t *disk_get_geometry_win32(HANDLE handle, const char *device, const int verbose);
#endif

static void compute_device_size(disk_t *disk_car);

static int align_read(int (*fnct_read)(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset),
           disk_t *disk_car, void*buf, const unsigned int count, const uint64_t offset)
{
  const uint64_t offset_new=offset+disk_car->offset;
  const unsigned int count_new=((offset_new%disk_car->sector_size)+count+disk_car->sector_size-1)/disk_car->sector_size*disk_car->sector_size;
  if(count!=count_new ||
      ((disk_car->access_mode&TESTDISK_O_DIRECT)!=0 &&
       (((size_t)(buf) & (disk_car->sector_size-1))!=0) &&
       (buf!=disk_car->rbuffer || disk_car->rbuffer_size<count_new))
    )
  {
    if(disk_car->rbuffer==NULL)
      disk_car->rbuffer_size=128*512;
    while(disk_car->rbuffer_size < count_new)
    {
      free(disk_car->rbuffer);
      disk_car->rbuffer=NULL;
      disk_car->rbuffer_size*=2;
    }
    if(disk_car->rbuffer==NULL)
      disk_car->rbuffer=(char*)MALLOC(disk_car->rbuffer_size);
    if(fnct_read(disk_car, disk_car->rbuffer, count_new, offset_new/disk_car->sector_size*disk_car->sector_size)<0)
      return -1;
    memcpy(buf,(char*)disk_car->rbuffer+(offset_new%disk_car->sector_size),count);
    return 0;
  }
  return fnct_read(disk_car, buf, count_new, offset_new);
}

static int align_write(int (*fnct_read)(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset),
    int (*fnct_write)(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset),
    disk_t *disk_car, const void*buf, const unsigned int count, const uint64_t offset)
{
  const uint64_t offset_new=offset+disk_car->offset;
  const unsigned int count_new=((offset_new%disk_car->sector_size)+count+disk_car->sector_size-1)/disk_car->sector_size*disk_car->sector_size;
  if(count!=count_new ||
      ((disk_car->access_mode&TESTDISK_O_DIRECT)!=0 &&
       (((size_t)(buf) & (disk_car->sector_size-1))!=0))
    )
  {
    if(disk_car->wbuffer==NULL)
      disk_car->wbuffer_size=128*512;
    while(disk_car->wbuffer_size < count_new)
    {
      free(disk_car->wbuffer);
      disk_car->wbuffer=NULL;
      disk_car->wbuffer_size*=2;
    }
    if(disk_car->wbuffer==NULL)
      disk_car->wbuffer=(char*)MALLOC(disk_car->wbuffer_size);
    if(fnct_read(disk_car, disk_car->wbuffer, count_new, offset_new/disk_car->sector_size*disk_car->sector_size)<0)
    {
      log_error("read failed but try to write anyway");
      memset(disk_car->wbuffer,0, disk_car->wbuffer_size);
    }
    memcpy((char*)disk_car->wbuffer+(offset_new%disk_car->sector_size),buf,count);
    return fnct_write(disk_car, disk_car->wbuffer, count_new, offset_new/disk_car->sector_size*disk_car->sector_size);
  }
  return fnct_write(disk_car, buf, count_new, offset_new);
}

static int generic_clean(disk_t *disk_car)
{
  free(disk_car->data);
  disk_car->data=NULL;
  free(disk_car->rbuffer);
  free(disk_car->wbuffer);
  disk_car->rbuffer=NULL;
  disk_car->wbuffer=NULL;
  return 0;
}

#ifdef DJGPP
#define HD_RW_BUF_SIZ 0x10
#define HDPARM_BUF_SIZ 0x1A
#define MAX_IO_NBR 3
#define MAX_HD_ERR 100
static void free_dos_buffer(void);
static int alloc_cmd_dos_buffer(void);
static disk_t *hd_identify(const int verbose, const unsigned int disk, const arch_fnct_t *arch, const int testdisk_mode);
static int hd_identify_enh_bios(disk_t *param_disk,const int verbose);
static int check_enh_bios(const unsigned int disk, const int verbose);
static int hd_report_error(disk_t *disk_car, const uint64_t hd_offset, const unsigned int count, const int rc);
static const char *disk_description(disk_t *disk_car);
static const char *disk_description_short(disk_t *disk_car);
static int disk_read(disk_t *disk_car, const unsigned int count, void *buf, const uint64_t hd_offset);
static int disk_write(disk_t *disk_car, const unsigned int count, const void *buf, const uint64_t hd_offset);
static int disk_nowrite(disk_t *disk_car, const unsigned int count, const void *buf, const uint64_t offset);
static int disk_sync(disk_t *disk_car);
static int disk_clean(disk_t *disk_car);
struct info_disk_struct
{
  unsigned int disk;
  CHS_t CHSR;	/* CHS low level */
  int mode_enh;
  int bad_geometry;
};

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
  struct info_disk_struct*data=disk_car->data;
  biosdisk(0, data->disk, 0, 0, 1, 1, NULL);
}

static int hd_read(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset)
{
  __dpmi_regs r;
  unsigned char buf_cmd[HD_RW_BUF_SIZ];
  int xfer_dos_segment, xfer_dos_selector;
  int nsects;
  unsigned long int hd_offset;
  struct info_disk_struct*data=disk_car->data;
  nsects=count/disk_car->sector_size;
  hd_offset=offset/disk_car->sector_size;
  if(data->mode_enh==0)
  { /* Limite CHS = 1023,255,63 = 8,064Mo ~= 7.8 Go */
    int head, track, sector;
    if(data->CHSR.sector==0)
    {
      log_critical("hd_read: BUG CHSR.sector=0 !\n");
      return 1;
    }
    sector=(hd_offset%data->CHSR.sector)+1;
    hd_offset/=data->CHSR.sector;
    head=hd_offset%(data->CHSR.head+1);
    track=hd_offset/(data->CHSR.head+1);
    if(track<1024)
      return biosdisk(2, data->disk, head, track, sector, nsects, buf);
    return 1;
  }
  if(cmd_dos_segment==0)
    if(alloc_cmd_dos_buffer())
      return 1;
  if ( (xfer_dos_segment=__dpmi_allocate_dos_memory((count + 15) >> 4, &xfer_dos_selector)) == -1 )
    return 1;
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
  return r.h.ah;
}

static int hd_write(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset)
{
  __dpmi_regs r;
  unsigned char buf_cmd[HD_RW_BUF_SIZ];
  int xfer_dos_segment, xfer_dos_selector;
  int nsects;
  unsigned long int hd_offset;
  struct info_disk_struct*data=disk_car->data;
  nsects=count/disk_car->sector_size;
  hd_offset=offset/disk_car->sector_size;

  if(data->mode_enh==0)
  { /* Limite CHS = 1023,255,63 = 8,064Mo ~= 7.8 Go */
    int head, track, sector;
    if(data->CHSR.sector==0)
    {
      log_critical("hd_write: BUG CHSR.sector=0 !\n");
      return 1;
    }
    sector=(hd_offset%data->CHSR.sector)+1;
    hd_offset/=data->CHSR.sector;
    head=hd_offset%(data->CHSR.head+1);
    track=hd_offset/(data->CHSR.head+1);
    if(track<1024)
      return biosdisk(3, data->disk, head, track, sector, nsects, buf);
    return 1;
  }
  if(cmd_dos_segment==0)
    if(alloc_cmd_dos_buffer())
      return 1;
  if ( (xfer_dos_segment=__dpmi_allocate_dos_memory((count + 15) >> 4, &xfer_dos_selector)) == -1 )
    return 1;
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
  return r.h.ah;
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
  int compute_LBA=0;
  __dpmi_regs r;
  unsigned char buf[0x200];	/* Don't change it! */
  struct info_disk_struct*data=disk_car->data;
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
  disk_car->CHS.cylinder=*(uint16_t*)&buf[0x04];
  disk_car->CHS.head=*(uint16_t*)&buf[0x08];
  disk_car->CHS.sector=*(uint16_t*)&buf[0x0C];
  disk_car->disk_size=(*(uint32_t*)&buf[0x10])*(uint64_t)disk_car->sector_size;
  if(disk_car->disk_size==0)
  {
    if(disk_car->CHS.cylinder==0 || disk_car->CHS.head==0 || disk_car->CHS.sector==0)
    {
      if(verbose>0)
	log_warning("hd_identify_enh_bios: No size returned by BIOS.\n");
      return 1;
    }
    else
    {
      disk_car->CHS.cylinder--;
      disk_car->CHS.head--;
      compute_LBA=1;
      disk_car->disk_size=(uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size;
      if(verbose>0)
        log_verbose("Computes LBA from CHS\n");
    }
  }
  else
  {
    if(disk_car->CHS.cylinder>0 && disk_car->CHS.head>0 && disk_car->CHS.sector>0)
    {
      disk_car->CHS.cylinder--;
      disk_car->CHS.head--;
      /* Some bios are buggy */
      if(disk_car->disk_size>(uint64_t)(disk_car->CHS.cylinder+2)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size)
      {
        disk_car->CHS.cylinder=(disk_car->disk_size/(disk_car->CHS.head+1))/disk_car->CHS.sector/disk_car->sector_size-1;
        if(verbose>0)
          log_verbose("Computes C from number of sectors\n");
      }
    }
    else
    {
      if(verbose>0)
        log_verbose("Computes CHS from number of sectors\n");
      disk_car->CHS.head=255-1;
      disk_car->CHS.sector=63;
      disk_car->CHS.cylinder=(disk_car->disk_size/(disk_car->CHS.head+1))/disk_car->CHS.sector/disk_car->sector_size-1;
    }
  }
  if(disk_car->CHS.sector==0)
  {
    data->bad_geometry=1;
    disk_car->CHS.sector=1;
    log_critical("Incorrect number of sector\n");
  }
  if(disk_car->CHS.sector>63)
  {
/*    data->bad_geometry=1; */
    log_critical("Incorrect number of sector\n");
  }
  if(disk_car->CHS.head>255-1)
  {
    data->bad_geometry=1;
    log_critical("Incorrect number of head\n");
  }
  if(verbose>0 || data->bad_geometry!=0)
    log_info("LBA %lu, computed %u (CHS=%u,%u,%u)\n",(long unsigned)(disk_car->disk_size/disk_car->sector_size), (disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector,disk_car->CHS.cylinder,disk_car->CHS.head,disk_car->CHS.sector);
  if(compute_LBA)
    disk_car->disk_size=(uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size;
  else
  {
    if(disk_car->disk_size < (uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector/disk_car->sector_size)
    {
      log_info("Computes LBA from CHS, previous value may be false.\n");
      disk_car->disk_size=(uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size;
    }
  }
  disk_car->disk_real_size=disk_car->disk_size;
  data->CHSR.cylinder=disk_car->CHS.cylinder;
  data->CHSR.head=disk_car->CHS.head;
  data->CHSR.sector=disk_car->CHS.sector;
  if(verbose>0)
  {
    log_info("hd_identify_enh_bios\n");
    log_info("%s\n",disk_description(disk_car));
    log_info("LBA size=%lu\n",(long unsigned)(disk_car->disk_size/disk_car->sector_size));
  }
  return 0;
}

static disk_t *hd_identify(const int verbose, const unsigned int disk, const arch_fnct_t *arch, const int testdisk_mode)
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
    disk_car->arch=arch;
    snprintf(device,sizeof(device),"/dev/sda%u",disk);
    disk_car->device=strdup(device);
    disk_car->write_used=0;
    disk_car->autodetect=0;
    disk_car->sector_size=DEFAULT_SECTOR_SIZE;
    disk_car->description=disk_description;
    disk_car->description_short=disk_description_short;
    disk_car->read=disk_read;
    disk_car->write=((testdisk_mode&TESTDISK_O_RDWR)==TESTDISK_O_RDWR?disk_write:disk_nowrite);
    disk_car->sync=disk_sync;
    disk_car->access_mode=testdisk_mode;
    disk_car->clean=disk_clean;
    disk_car->data=data;
    disk_car->CHS.cylinder=((buf[0] & 0x0C0)<<2)|buf[1];
    disk_car->CHS.head=buf[3];
    disk_car->CHS.sector=buf[0] & 0x3F;
    if(disk_car->CHS.head>=255)
    { /* Problem found by G Rowe */
      log_critical("BIOS reports an invalid heads number\n");
      data->bad_geometry=1;
      disk_car->CHS.head=254;
    }
    if(disk_car->CHS.sector==0)
    { /* Problem found by Brian Barrett */
      log_critical("BIOS reports an invalid number of sector per head\n");
      data->bad_geometry=1;
      disk_car->CHS.sector=1;
    }
    disk_car->disk_size=(uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size;
    disk_car->disk_real_size=disk_car->disk_size;
    data->CHSR.cylinder=disk_car->CHS.cylinder;
    data->CHSR.head=disk_car->CHS.head;
    data->CHSR.sector=disk_car->CHS.sector;
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
	disk_car->CHS.cylinder=(disk_car->disk_size/(disk_car->CHS.head+1))/disk_car->CHS.sector/disk_car->sector_size-1;
      }
      else
	data->mode_enh=0;
      free(param_disk_enh);
    }
    disk_car->unit=UNIT_CHS;
    return disk_car;
  }
}

static const char *disk_description(disk_t *disk_car)
{
  struct info_disk_struct*data=disk_car->data;
  char buffer_disk_size[100];
  snprintf(disk_car->description_txt, sizeof(disk_car->description_txt),"Disk %2x - %s - CHS %u %u %u%s",
      data->disk, size_to_unit(disk_car->disk_size,buffer_disk_size),
      disk_car->CHS.cylinder+1, disk_car->CHS.head+1, disk_car->CHS.sector,
      data->bad_geometry!=0?" (Buggy BIOS)":"");
  return disk_car->description_txt;
}

static const char *disk_description_short(disk_t *disk_car)
{
  struct info_disk_struct*data=disk_car->data;
  char buffer_disk_size[100];
  snprintf(disk_car->description_short_txt, sizeof(disk_car->description_txt),"Disk %2x - %s",
      data->disk, size_to_unit(disk_car->disk_size,buffer_disk_size));
  return disk_car->description_short_txt;
}

static int disk_read_aux(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset)
{
  struct info_disk_struct*data=disk_car->data;
  if(data->CHSR.cylinder>0 && offset+count>disk_car->disk_size)
  {
    log_error("disk_read_aux: Don't read after the end of the disk\n");
    return -1;
  }
  {
    unsigned int read_size;
    uint64_t read_offset=0;
    do
    {
      int i=0;
      int rc;
      read_size=count-read_offset>16*512?16*512:count-read_offset;
      do
      {
        rc=hd_read(disk_car, (char*)buf+read_offset, read_size, offset+read_offset);
        if(rc!=0)
          disk_reset_error(disk_car);
      } while(rc!=0 && rc!=1 && ++i<MAX_IO_NBR);
      // 0=successful completion
      // 1=invalid function in AH or invalid parameter
      if(rc!=0)
      {
        log_error("disk_read_aux failed ");
        hd_report_error(disk_car, offset, count, rc);
        return -rc;
      }
      read_offset+=read_size;
    } while(read_offset<count);
  }
  return 0;
}

static int disk_read(disk_t *disk_car, const unsigned int count, void *buf, const uint64_t offset)
{
  return align_read(&disk_read_aux, disk_car, buf, count, offset);
}

static int disk_write_aux(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t hd_offset)
{

  struct info_disk_struct*data=disk_car->data;
  int i=0;
  int rc;
  disk_car->write_used=1;
  {
    rc=hd_write(disk_car, buf, count, hd_offset);
    if(rc!=0)
      disk_reset_error(disk_car);
  } while(rc==4 && ++i<MAX_IO_NBR);
  /* 4=sector not found/read error */
  if(rc!=0)
  {
    log_error("disk_write error\n");
    hd_report_error(disk_car, hd_offset, count, rc);
    return -rc;
  }
  return 0;
}

static int disk_write(disk_t *disk_car, const unsigned int count, const void *buf, const uint64_t offset)
{
  return align_write(&disk_read_aux, &disk_write_aux, disk_car, buf, count, offset);
}

static int disk_nowrite(disk_t *disk_car,const unsigned int count, const void *buf, const uint64_t offset)
{
  struct info_disk_struct *data=disk_car->data;
  log_warning("disk_nowrite(%d,%u,buffer,%lu(%u/%u/%u)) write refused\n", data->disk,
      (unsigned)(count/disk_car->sector_size),(long unsigned)(offset/disk_car->sector_size),
      offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset));
  return -1;
}

static int disk_sync(disk_t *disk_car)
{
  errno=EINVAL;
  return -1;
}

static int disk_clean(disk_t *disk_car)
{
  /*
  if(disk_car->data!=NULL)
  {
    struct info_disk_struct *data=disk_car->data;
  }
  */
  return generic_clean(disk_car);
}

static int hd_report_error(disk_t *disk_car, const uint64_t hd_offset, const unsigned int count, const int rc)
{
  struct info_disk_struct*data=disk_car->data;
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

#if defined(__CYGWIN__) || defined(__MINGW32__)
list_disk_t *insert_new_disk_nodup(list_disk_t *list_disk, disk_t *disk_car, const char *device_name, const int verbose);
list_disk_t *insert_new_disk_nodup(list_disk_t *list_disk, disk_t *disk_car, const char *device_name, const int verbose)
{
  if(disk_car==NULL)
    return list_disk;
  {
    int disk_same_size_present=0;
    list_disk_t *cur;
    for(cur=list_disk;cur!=NULL;cur=cur->next)
    {
      if(cur->disk->disk_size==disk_car->disk_size && cur->disk->sector_size==disk_car->sector_size)
        disk_same_size_present=1;
    }
    if(disk_car->sector_size==512 && disk_same_size_present!=0)
    {
      if(verbose>1)
        log_verbose("%s is available but reject it to avoid duplicate disk.\n", device_name);
      if(disk_car->clean!=NULL)
        disk_car->clean(disk_car);
      free(disk_car->device);
      free(disk_car);
      return list_disk;
    }
    return insert_new_disk(list_disk,disk_car);
  }
}
#endif

list_disk_t *hd_parse(list_disk_t *list_disk, const int verbose, const arch_fnct_t *arch, const int testdisk_mode)
{
  int i;
#ifdef DJGPP
  int ind_stop=0;
  for(i=0x80;(i<0x88)&&!ind_stop;i++)
  {
    disk_t *disk_car=hd_identify(verbose,i,arch,testdisk_mode);
    if(disk_car)
      list_disk=insert_new_disk(list_disk,disk_car);
    else
      ind_stop=1;
  }
#elif defined(__CYGWIN__) || defined(__MINGW32__)
  {
    int do_insert=0;
    char device_hd[]="\\\\.\\PhysicalDrive0";
    char device_cdrom[]="\\\\.\\C:";
#if defined(__CYGWIN__)
    char device_scsi[]="/dev/sda";
    /* Disk */
    for(i=0;i<8;i++)
    {
      device_scsi[strlen(device_scsi)-1]='a'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_scsi,verbose,arch,testdisk_mode));
    }
#endif
    /* Disk */
    if(list_disk==NULL)
      do_insert=1;
    {
      for(i=0;i<8;i++)
      {
	disk_t *disk_car;
	device_hd[strlen(device_hd)-1]='0'+i;
	disk_car=file_test_availability_win32(device_hd,verbose,arch,testdisk_mode);
	if(do_insert>0 || (testdisk_mode&TESTDISK_O_ALL)==TESTDISK_O_ALL)
	  list_disk=insert_new_disk(list_disk,disk_car);
	else
	  list_disk=insert_new_disk_nodup(list_disk,disk_car,device_hd, verbose);
      }
    }
    /* cdrom and digital camera */
    for(i='C';i<='Z';i++)
    {
      disk_t *disk_car;
      device_cdrom[strlen(device_cdrom)-2]=i;
      disk_car=file_test_availability_win32(device_cdrom,verbose,arch,testdisk_mode);
      if((testdisk_mode&TESTDISK_O_ALL)==TESTDISK_O_ALL)
	list_disk=insert_new_disk(list_disk,disk_car);
      else
	list_disk=insert_new_disk_nodup(list_disk,disk_car,device_cdrom, verbose);
    }
  }
#elif defined(__APPLE__)
  {
    char device_scsi[]="/dev/disk0";
    char device_raw[]="/dev/rdisk0";
    /* Disk */
    for(i=0;i<10;i++)
    {
      device_scsi[strlen(device_scsi)-1]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_scsi,verbose,arch,testdisk_mode));
    }
    for(i=0;i<10;i++)
    {
      device_raw[strlen(device_raw)-1]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_raw,verbose,arch,testdisk_mode));
    }
  }
#elif defined(TARGET_LINUX)
  {
    int j;
    char device[100];
    char device_ide[]="/dev/hda";
    char device_scsi[]="/dev/sda";
    char device_ida[]="/dev/ida/c0d0";
    char device_cciss[]="/dev/cciss/c0d0";
    char device_p_ide[]="/dev/pda";
    char device_i2o_hd[]="/dev/i2o/hda";
    /* Disk IDE */
    for(i=0;i<8;i++)
    {
      device_ide[strlen(device_ide)-1]='a'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_ide,verbose,arch,testdisk_mode));
    }
    /* Disk SCSI */
    for(i=0;i<26;i++)
    {
      device_scsi[strlen(device_scsi)-1]='a'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_scsi,verbose,arch,testdisk_mode));
    }
    /* Device RAID Compaq */
    for(j=0;j<8;j++)
    {
      device_ida[strlen(device_ida)-3]='0'+j;
      for(i=0;i<8;i++)
      {
	device_ida[strlen(device_ida)-1]='0'+i;
	list_disk=insert_new_disk(list_disk,file_test_availability(device_ida,verbose,arch,testdisk_mode));
      }
    }
    for(i=0;i<8;i++)
    {
      device_cciss[strlen(device_cciss)-1]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_cciss,verbose,arch,testdisk_mode));
    }
    /* Device RAID */
    for(i=0;i<10;i++)
    {
      snprintf(device,sizeof(device),"/dev/rd/c0d%u",i);
      list_disk=insert_new_disk(list_disk,file_test_availability(device,verbose,arch,testdisk_mode));
    }
    /* Device RAID IDE */
    for(i=0;i<15;i++)
    {
      snprintf(device,sizeof(device),"/dev/ataraid/d%u",i);
      list_disk=insert_new_disk(list_disk,file_test_availability(device,verbose,arch,testdisk_mode));
    }
    /* Parallel port IDE disk */
    for(i=0;i<4;i++)
    {
      device_p_ide[strlen(device_p_ide)-1]='a'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_p_ide,verbose,arch,testdisk_mode));
    }
    /* I2O hard disk */
    for(i=0;i<26;i++)
    {
      device_i2o_hd[strlen(device_i2o_hd)-1]='a'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_i2o_hd,verbose,arch,testdisk_mode));
    }
  }
#elif defined(TARGET_SOLARIS)
  {
    char rdsk[]="/dev/rdsk/c0t0d0s2";
    for(i=0;i<15;i++)
    {
      if(i!=7)
      {
	rdsk[13]='0'+i;
	list_disk=insert_new_disk(list_disk,file_test_availability(rdsk,verbose,arch,testdisk_mode));
      }
    }
  }
#else
  {
    /* Need to check http://mattriffle.com/mirrors/freebsd/doc/en_US.ISO8859-1/books/handbook/disks-naming.html#DISK-NAMING-PHYSICAL-TABLE */
    char device_ide[]= "/dev/rwd0";	/* raw winchester disk */
    char device_ide2[]="/dev/rad0";
    char device_ide3[]="/dev/wd0d";    	/* NetBSD 1.6.2 IDE */
    char device_ide4[]="/dev/rwd0c";    /* OpenBSD 3.5 IDE */
    char device_scsi[]="/dev/rda0";	/* raw scsci disk */
    char device_scsi2[]="/dev/rsd0c";	/* OpenBSD 3.5 SCSI */
    char device_optdisk[]="/dev/rod0";
    char device_ide_hd[]="/dev/ad0";
    char device_scsi_hd[]="/dev/da0";
    char device_cd[]="/dev/acd0";
    /* wd da */
    /* Disk IDE */
    for(i=0;i<8;i++)
    {
      device_ide[strlen(device_ide)-1]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_ide,verbose,arch,testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_ide2[strlen(device_ide2)-1]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_ide2,verbose,arch,testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_ide3[strlen(device_ide3)-2]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_ide3,verbose,arch,testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_ide4[strlen(device_ide4)-2]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_ide4,verbose,arch,testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_ide_hd[strlen(device_ide_hd)-1]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_ide_hd,verbose,arch,testdisk_mode));
    }
    /* Disk SCSI */
    for(i=0;i<8;i++)
    {
      device_scsi[strlen(device_scsi)-1]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_scsi,verbose,arch,testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_scsi2[strlen(device_scsi2)-1]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_scsi2,verbose,arch,testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_scsi_hd[strlen(device_scsi_hd)-1]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_scsi_hd,verbose,arch,testdisk_mode));
    }
    /* optical disks */
    for(i=0;i<8;i++)
    {
      device_optdisk[strlen(device_scsi)-1]='a'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_optdisk,verbose,arch,testdisk_mode));
    } 
    /* CD */
    for(i=0;i<8;i++)
    {
      device_cd[strlen(device_cd)-1]='0'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_cd,verbose,arch,testdisk_mode));
    }
  }
#endif
  return list_disk;
}

#if defined(__CYGWIN__) || defined(__MINGW32__)
static disk_t *disk_get_geometry_win32(HANDLE handle, const char *device, const int verbose)
{
  disk_t *disk_car=NULL;
  DISK_GEOMETRY geometry;
  DWORD gotbytes;
  if (DeviceIoControl( handle
        , IOCTL_DISK_GET_DRIVE_GEOMETRY
        , NULL
        , 0
        , &geometry
        , sizeof(geometry)
        , &gotbytes
        , NULL
        )) {
    disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
    disk_car->CHS.cylinder= geometry.Cylinders.QuadPart-1;
    disk_car->CHS.head=geometry.TracksPerCylinder-1;
    disk_car->CHS.sector= geometry.SectorsPerTrack;
    disk_car->sector_size=geometry.BytesPerSector;
    disk_car->disk_size=(uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size;
    disk_car->disk_real_size=disk_car->disk_size;
    if(verbose>1)
    {
      log_verbose("disk_get_geometry_win32(%s) ok\n",device);
      log_verbose("CHS (%u, %u, %u), sector_size=%u\n", disk_car->CHS.cylinder+1, disk_car->CHS.head+1, disk_car->CHS.sector, disk_car->sector_size);
    }
  }
  else
  {
    if(verbose>1)
    {
#ifdef __MINGW32__
      log_error("DeviceIoControl failed\n");
#else
      LPVOID buf;
      FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
          , NULL
          , GetLastError()
          , MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
          , (LPTSTR)&buf
          , 0
          , NULL 
          );
      log_error("DeviceIoControl failed: %s: %s\n", device,(const char*)buf);
      LocalFree(buf);
#endif
    }
  }
  return disk_car;
}
#endif

#ifndef DJGPP
static disk_t *disk_get_geometry(const int hd_h, const char *device, const int verbose)
{
  disk_t *disk_car=NULL;
  unsigned int sector_size=0;
#ifdef BLKSSZGET
  {
    int arg=0;
    if (ioctl(hd_h, BLKSSZGET, &arg) == 0)
    {
      sector_size=arg;
      if(verbose>1)
      {
        log_verbose("disk_get_geometry BLKSSZGET %s sector_size=%u\n",device,sector_size);
      }
    }
  }
#endif
#ifdef DIOCGSECTORSIZE
  {
    unsigned int arg=0;
    if(ioctl(hd_h,DIOCGSECTORSIZE,&arg)==0)
    {
      sector_size=arg;
      if(verbose>1)
      {
        log_verbose("disk_get_geometry DIOCGSECTORSIZE %s sector_size=%u\n",device,sector_size);
      }
    }
  }
#endif
#ifdef BLKFLSBUF
  /* Little trick from Linux fdisk */
  /* Blocks are visible in more than one way:
     e.g. as block on /dev/hda and as block on /dev/hda3
     By a bug in the Linux buffer cache, we will see the old
     contents of /dev/hda when the change was made to /dev/hda3.
     In order to avoid this, discard all blocks on /dev/hda. */
  ioctl(hd_h, BLKFLSBUF);	/* ignore errors */
#endif
#ifdef HDIO_GETGEO_BIG
  {
    struct hd_big_geometry geometry_big;
    if (ioctl(hd_h, HDIO_GETGEO_BIG, &geometry_big)>=0)
    { /* I can get the geometry */
      if(verbose>1)
      {
        log_verbose("disk_get_geometry HDIO_GETGEO_BIG %s Ok (%u,%u,%u)\n",device,geometry_big.cylinders,geometry_big.heads,geometry_big.sectors);
      }
      disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
      disk_car->disk_size=0;
      disk_car->CHS.cylinder= geometry_big.cylinders-1;
      disk_car->CHS.head=geometry_big.heads-1;
      disk_car->CHS.sector= geometry_big.sectors;
    }
    else
    {
      if(verbose>1)
      {
        log_error("disk_get_geometry HDIO_GETGEO_BIG %s failed %s\n",device,strerror(errno));
      }
    }
  }
#endif
#ifdef HDIO_GETGEO
  if (disk_car==NULL)
  {
    struct hd_geometry geometry;
    if(ioctl(hd_h, HDIO_GETGEO, &geometry)>=0)
    { /* I can get the geometry */
      if(verbose>1)
      {
	log_verbose("disk_get_geometry HDIO_GETGEO %s Ok (%u,%u,%u)\n",device,geometry.cylinders,geometry.heads,geometry.sectors);
      }
      disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
      disk_car->disk_size=0;
      disk_car->CHS.cylinder= geometry.cylinders-1;
      disk_car->CHS.head=geometry.heads-1;
      disk_car->CHS.sector= geometry.sectors;
    }
  }
#endif
#ifdef DKIOCGGEOM
  if(disk_car==NULL)
  {
    struct dk_geom dkgeom;
    if (ioctl (hd_h, DKIOCGGEOM, &dkgeom)>=0) {
      disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
      disk_car->disk_size=0;
      disk_car->CHS.cylinder= dkgeom.dkg_ncyl-1;
      disk_car->CHS.head=dkgeom.dkg_nhead-1;
      disk_car->CHS.sector=dkgeom.dkg_nsect;
    }
  }
#endif
  if(disk_car!=NULL && disk_car->CHS.sector>0)
  {
#ifdef BLKGETSIZE64
    uint64_t longsectors64=0;
    if (ioctl(hd_h, BLKGETSIZE64, &longsectors64)>=0)
    {
      unsigned int cylinder_max;
      disk_car->disk_size=longsectors64;
      if(verbose>1)
      {
	log_verbose("disk_get_geometry BLKGETSIZE64 %s size %llu\n", device, (long long unsigned)longsectors64);
      }
      if(sector_size<=0)
      {
	sector_size=DEFAULT_SECTOR_SIZE;
      }
      cylinder_max=longsectors64 / ((uint64_t)disk_car->CHS.head+1) / (uint64_t)disk_car->CHS.sector/(uint64_t)sector_size-1;
      if(disk_car->CHS.cylinder!= cylinder_max)
      { /* Handle a strange bug */
	log_warning("disk_get_geometry BLKGETSIZE64 %s number of cylinders %u !=  %u (calculated)\n",
	    device,disk_car->CHS.cylinder+1,cylinder_max+1);
	disk_car->CHS.cylinder= cylinder_max;
      }
    }
    else
#endif
    {
#ifdef BLKGETSIZE
      unsigned long longsectors=0;
      if (ioctl(hd_h, BLKGETSIZE, &longsectors)>=0)
      {
        unsigned int cylinder_max;
        if(verbose>1)
        {
          log_verbose("disk_get_geometry BLKGETSIZE %s, number of sectors=%lu\n",device,longsectors);
        }
        if(sector_size<=0)
        {
          sector_size=DEFAULT_SECTOR_SIZE;
        }
        if(DEFAULT_SECTOR_SIZE!=sector_size)
        {
          log_warning("disk_get_geometry, TestDisk assumes BLKGETSIZE returns the number of 512 byte sectors.\n");
        }
        disk_car->disk_size=longsectors*sector_size;
        cylinder_max=(uint64_t)longsectors * DEFAULT_SECTOR_SIZE/(uint64_t)sector_size / ((uint64_t)disk_car->CHS.head+1) / ((uint64_t)disk_car->CHS.sector)-1;
        if(disk_car->CHS.cylinder!=cylinder_max)
        { /* Handle a strange bug */
          log_warning("disk_get_geometry BLKGETSIZE %s number of cylinders %u !=  %u (calculated)\n",
              device,disk_car->CHS.cylinder+1,cylinder_max+1);
          disk_car->CHS.cylinder=cylinder_max;
        }
      }
#endif
    }
  }
#if defined(__CYGWIN__) || defined(__MINGW32__)
  if(disk_car==NULL)
  {
    HANDLE handle;
#if defined(__CYGWIN__)
    handle=(HANDLE)get_osfhandle(hd_h);
#else
    handle=(HANDLE)_get_osfhandle(hd_h);
#endif
    disk_car=disk_get_geometry_win32(handle,device,verbose);
    if(disk_car!=NULL)
      sector_size=disk_car->sector_size;
  }
#endif
#ifdef DIOCGDINFO
  if(disk_car==NULL)
  {
    struct disklabel geometry;
    if (ioctl(hd_h, DIOCGDINFO, &geometry)==0)
    { /* I can get the geometry */
      if(verbose>1)
      {
	log_verbose("disk_get_geometry DIOCGDINFO %s Ok\n",device);
      }
      disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
      disk_car->disk_size=0;
      disk_car->CHS.cylinder=geometry.d_ncylinders-1;
      disk_car->CHS.head=geometry.d_ntracks-1;
      disk_car->CHS.sector=geometry.d_nsectors;
      sector_size=geometry.d_secsize;
    }
    else
    {
      if(verbose>1)
      {
	log_error("disk_get_geometry DIOCGDINFO %s failed %s\n",device,strerror(errno));
      }
    }
  }
#endif
#ifdef DIOCGFWSECTORS
  if(disk_car==NULL)
  {
    int error;
    unsigned int u,sectors,heads,cyls;
    off_t o;
    error = ioctl(hd_h, DIOCGFWSECTORS, &u);
    if(error==0 && u>0)
    {
      sectors=u;
    }
    else
    {
      sectors=63;
      if(verbose>1)
      {
	log_error("disk_get_geometry DIOCGFWSECTORS %s failed %s\n",device,strerror(errno));
      }
    }
    error = ioctl(hd_h, DIOCGFWHEADS, &u);
    if(error==0 && u>0)
    {
      heads=u;
    }
    else
    {
      heads=255;
      if(verbose>1)
      {
	log_error("disk_get_geometry DIOCGFWHEADS %s failed %s\n",device,strerror(errno));
      }
    }
    error = ioctl(hd_h, DIOCGMEDIASIZE, &o);
    if(error==0)
    {
      if(sector_size<=0)
      {
	sector_size=DEFAULT_SECTOR_SIZE;
      }
      cyls = o / (sector_size * heads * sectors);
      disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
      disk_car->disk_size=o;
      disk_car->disk_size=0;
      disk_car->CHS.cylinder=cyls-1;
      disk_car->CHS.head=heads-1;
      disk_car->CHS.sector=sectors;
    }
    else
    {
      if(verbose>1)
      {
	log_error("disk_get_geometry DIOCGMEDIASIZE %s failed %s\n",device,strerror(errno));
      }
    }
  }
#endif
  if(disk_car==NULL)
  {
    if(sector_size>0)
    {
      disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
      disk_car->disk_size=0;
      disk_car->CHS.cylinder=0;
      disk_car->CHS.head=0;
      disk_car->CHS.sector=0;
      disk_car->sector_size=sector_size;
    }
  }
  else
  {
    if(sector_size<=0)
    {
      sector_size=DEFAULT_SECTOR_SIZE;
    }
    disk_car->sector_size=sector_size;
  }
  return disk_car;
}
#endif

static const char *file_description(disk_t *disk_car)
{
  const struct info_file_struct *data=disk_car->data;
  char buffer_disk_size[100];
  snprintf(disk_car->description_txt, sizeof(disk_car->description_txt),"Disk %s - %s - CHS %u %u %u%s",
      data->file_name, size_to_unit(disk_car->disk_size,buffer_disk_size),
      disk_car->CHS.cylinder+1, disk_car->CHS.head+1, disk_car->CHS.sector,((data->mode&O_RDWR)==O_RDWR?"":" (RO)"));
  return disk_car->description_txt;
}

static const char *file_description_short(disk_t *disk_car)
{
  const struct info_file_struct *data=disk_car->data;
  char buffer_disk_size[100];
  snprintf(disk_car->description_short_txt, sizeof(disk_car->description_txt),"Disk %s - %s%s",
      data->file_name, size_to_unit(disk_car->disk_size,buffer_disk_size),((data->mode&O_RDWR)==O_RDWR?"":" (RO)"));
  return disk_car->description_short_txt;
}

static int file_clean(disk_t *disk_car)
{
  if(disk_car->data!=NULL)
  {
    struct info_file_struct *data=disk_car->data;
    /*
#ifdef BLKRRPART
    if (ioctl(data->handle, BLKRRPART, NULL)) {
      log_error("%s BLKRRPART failed\n",disk_car->description(disk_car));
    } else {
      log_debug("%s BLKRRPART ok\n",disk_car->description(disk_car));
    }
#endif
    */
    close(data->handle);
  }
  return generic_clean(disk_car);
}

static int file_read_aux(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset)
{
  long int ret=-1;
  int fd=((struct info_file_struct *)disk_car->data)->handle;
#if defined(HAVE_PREAD) && !defined(__CYGWIN__)
  ret=pread(fd,buf,count,offset);
  if(ret<0 && errno == ENOSYS)
#endif
  {
#ifdef __MINGW32__
    if(_lseeki64(fd,offset,SEEK_SET)==-1)
    {
      log_error("file_read(%d,%u,buffer,%lu(%u/%u/%u)) seek err %s\n", fd,
          (unsigned)(count/disk_car->sector_size), (long unsigned int)(offset/disk_car->sector_size),
          offset2cylinder(disk_car,offset), offset2head(disk_car,offset), offset2sector(disk_car,offset),
          strerror(errno));
      return -1;
    }
#else
    if(lseek(fd,offset,SEEK_SET)==(off_t)-1)
    {
      log_error("file_read(%d,%u,buffer,%lu(%u/%u/%u)) lseek err %s\n", fd,
          (unsigned)(count/disk_car->sector_size), (long unsigned int)(offset/disk_car->sector_size),
          offset2cylinder(disk_car,offset), offset2head(disk_car,offset), offset2sector(disk_car,offset),
          strerror(errno));
      return -1;
    }
#endif
#if defined(__CYGWIN__)
    {
      /* November 28, 2004, CGR: cygwin read function is about 10 times slower
         because it reads 60k each time, so lets call ReadFile directly */
      DWORD dwByteRead;
      HANDLE handle=(HANDLE)get_osfhandle(fd);
      ret=ReadFile(handle, buf,count,&dwByteRead,NULL);
      if(ret==0)
        ret=-1;
      else
        ret=dwByteRead;
    }
#else
    ret=read(fd, buf, count);
#endif
  }
  if(ret!=count)
  {
    if(offset+count <= disk_car->disk_size && offset+count <= disk_car->disk_real_size)
    {
      log_error("file_read(%d,%u,buffer,%lu(%u/%u/%u)) read err: ", fd,
          (unsigned)(count/disk_car->sector_size), (long unsigned)(offset/disk_car->sector_size),
          offset2cylinder(disk_car,offset), offset2head(disk_car,offset), offset2sector(disk_car,offset));
      if(ret<0)
        log_error("%s\n", strerror(errno));
      else if(ret==0)
        log_error("read after end of file\n");
      else
        log_error("Partial read\n");
    }
    if(ret<=0)
      return -1;
    memset((char*)buf+ret,0,count-ret);
  }
  return 0;
}

static int file_read(disk_t *disk_car,const unsigned int count, void *buf, const uint64_t offset)
{
  return align_read(&file_read_aux, disk_car, buf, count, offset);
}

static int file_write_aux(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset)
{
  int fd=((struct info_file_struct *)disk_car->data)->handle;
  long int ret=-1;
#if defined(HAVE_PWRITE) && !defined(__CYGWIN__)
  ret=pwrite(fd,buf,count,offset);
  if(ret<0 && errno == ENOSYS)
#endif
  {
#ifdef __MINGW32__
    if(_lseeki64(fd,offset,SEEK_SET)==-1)
    {
      log_error("file_write(%d,%u,buffer,%lu(%u/%u/%u)) seek err %s\n", fd,
          (unsigned)(count/disk_car->sector_size),
          (long unsigned)(offset/disk_car->sector_size),
          offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset),strerror(errno));
      return -1;
    }
#else
    if(lseek(fd,offset,SEEK_SET)==-1)
    {
      log_error("file_write(%d,%u,buffer,%lu(%u/%u/%u)) seek err %s\n", fd,(unsigned)(count/disk_car->sector_size),(long unsigned)(offset/disk_car->sector_size),
          offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset),strerror(errno));
      return -1;
    }
#endif
    ret=write(fd, buf, count);
  }
  disk_car->write_used=1;
  if(ret!=count)
  {
    log_error("file_write(%d,%u,buffer,%lu(%u/%u/%u)) write err %s\n", fd,(unsigned)(count/disk_car->sector_size),(long unsigned)(offset/disk_car->sector_size),
        offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset),(ret<0?strerror(errno):"File truncated"));
    return -1;
  }
  return 0;
}

static int file_write(disk_t *disk_car, const unsigned int count, const void *buf, const uint64_t offset)
{
  return align_write(&file_read_aux, &file_write_aux, disk_car, buf, count, offset);
}

static int file_nowrite(disk_t *disk_car,const unsigned int count, const void *buf, const uint64_t offset)
{
  struct info_file_struct *data=disk_car->data;
  log_warning("file_nowrite(%d,%u,buffer,%lu(%u/%u/%u)) write refused\n", data->handle,
      (unsigned)(count/disk_car->sector_size),(long unsigned)(offset/disk_car->sector_size),
      offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset));
  return -1;
}

static int file_sync(disk_t *disk_car)
{
  struct info_file_struct *data=disk_car->data;
  return fsync(data->handle);
}

static void autoset_geometry(disk_t * disk_car, const unsigned char *buffer, const int verbose)
{
  if(disk_car->arch->get_geometry_from_mbr!=NULL)
  {
    CHS_t geometry;
    geometry.cylinder=0;
    geometry.head=0;
    geometry.sector=0;
    disk_car->arch->get_geometry_from_mbr(buffer, verbose, &geometry);
    disk_car->autodetect=1;
    if(geometry.sector>0)
    {
      disk_car->CHS.head=geometry.head;
      disk_car->CHS.sector=geometry.sector;
    }
    else
    {
      disk_car->CHS.head=255-1;
      disk_car->CHS.sector=63;
    }
  }
  /* Round up because file is often truncated. */
  if((disk_car->disk_size/disk_car->sector_size+(uint64_t)disk_car->CHS.sector*(disk_car->CHS.head+1)-1)/disk_car->CHS.sector/(disk_car->CHS.head+1)==0)
    disk_car->CHS.cylinder=0;
  else
    disk_car->CHS.cylinder=(disk_car->disk_size/disk_car->sector_size+(uint64_t)disk_car->CHS.sector*(disk_car->CHS.head+1)-1)/disk_car->CHS.sector/(disk_car->CHS.head+1)-1;
}

static void compute_device_size(disk_t *disk_car)
{
  /* This function can failed if there are bad sectors */
  uint64_t min_offset, max_offset;
  char *buffer=MALLOC(disk_car->sector_size);
  min_offset=0;
  max_offset=disk_car->sector_size;
  /* Search the maximum device size */
  while(disk_car->read(disk_car,1,buffer,max_offset)==0)
  {
    min_offset=max_offset;
    max_offset*=2;
  }
  /* Search the device size by dichotomy */
  while(min_offset<=max_offset)
  {
    uint64_t cur_offset;
    cur_offset=(min_offset+max_offset)/2/disk_car->sector_size*disk_car->sector_size;
    if(disk_car->read(disk_car,1,buffer,cur_offset)==0)
      min_offset=cur_offset+disk_car->sector_size;
    else
    {
      if(cur_offset>=disk_car->sector_size)
	max_offset=cur_offset-disk_car->sector_size;
      else
	break;
    }
  }
  if(disk_car->read(disk_car,1,buffer,min_offset)==0)
    min_offset+=disk_car->sector_size;
  disk_car->disk_size=min_offset;
  disk_car->disk_real_size=disk_car->disk_size;
  free(buffer);
}


disk_t *file_test_availability(const char *device, const int verbose, const arch_fnct_t *arch, int testdisk_mode)
{
  disk_t *disk_car=NULL;
  unsigned int offset=0;
  int mode=0;
  int hd_h=-1;
  int try_readonly=1;
  int mode_basic=0;
#ifdef O_BINARY
    mode_basic|=O_BINARY;
#endif
#ifdef O_LARGEFILE
    mode_basic|=O_LARGEFILE;
#endif
#ifdef O_DIRECT
    if((testdisk_mode&TESTDISK_O_DIRECT)==TESTDISK_O_DIRECT)
      mode_basic|=O_DIRECT;
#endif
  if((testdisk_mode&TESTDISK_O_RDWR)==TESTDISK_O_RDWR)
  {
    mode=O_RDWR|O_EXCL|mode_basic;
    hd_h = open(device, mode);
    if(hd_h<0 && (errno==EBUSY || errno==EINVAL))
    {
      mode=O_RDWR|mode_basic;
      hd_h = open(device, mode);
    }
    if(hd_h<0)
    {
      switch(errno)
      {
        case ENXIO:
        case ENOENT:
#ifdef ENOMEDIUM
        case ENOMEDIUM:
#endif
        try_readonly=0;
          break;
        default:
          break;
      }
    }
    else
    {
#ifdef BLKROGET
      int readonly;
      /* If the device can be opened read-write, then
       * check whether BKROGET says that it is read-only.
       * read-only loop devices may be openend read-write,
       * use BKROGET to detect the problem
       */
      if (ioctl(hd_h, BLKROGET, &readonly) >= 0)
      {
        if(readonly>0)
        {
          try_readonly=1;
          close(hd_h);
        }
      }
#endif
    }
  }
  if(try_readonly>0)
  {
    testdisk_mode&=~TESTDISK_O_RDWR;
    if(hd_h<0)
    {
      mode=O_RDONLY|O_EXCL|mode_basic;
      hd_h = open(device, mode);
    }
    if(hd_h<0 && (errno==EBUSY || errno==EINVAL))
    {
      mode=O_RDONLY|mode_basic;
      hd_h = open(device, mode);
    }
  }
  if(verbose>1)
    log_error("file_test_availability %s: %s\n", device,strerror(errno));
  if(hd_h>=0)
  {
    struct stat stat_rec;
    if(fstat(hd_h,&stat_rec)<0)
    {
      if(verbose>1)
      {
	log_error("file_test_availability %s: fstat failed\n",device);
      }
#ifdef __MINGW32__
      stat_rec.st_mode=S_IFBLK;
      stat_rec.st_size=0;
#else
      close(hd_h);
      return NULL;
#endif
    }
#ifndef DJGPP
    if(!S_ISREG(stat_rec.st_mode))
    {
      if(verbose>1)
      {
        log_verbose("file_test_availability %s: not a regular file\n",device);
      }
      disk_car=disk_get_geometry(hd_h, device, verbose);
      if(disk_car!=NULL)
      {
	disk_car->arch=arch;
	disk_car->autodetect=0;
	if(disk_car->disk_size<(uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size)
	{
	  disk_car->disk_size=(uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size;
	}
      }
    }
#endif
    if(disk_car==NULL)
    {
      disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
      disk_car->disk_size=0;
      disk_car->arch=arch;
      disk_car->sector_size=DEFAULT_SECTOR_SIZE;
    }
    disk_car->disk_real_size=disk_car->disk_size;
    if(disk_car->disk_size==0)
    {
      unsigned char *buffer;
      const uint8_t evf_file_signature[8] = { 'E', 'V', 'F', 0x09, 0x0D, 0x0A, 0xFF, 0x00 };
      buffer=(unsigned char*)MALLOC(DEFAULT_SECTOR_SIZE);
      if(read(hd_h,buffer,DEFAULT_SECTOR_SIZE)<0)
      {
	memset(buffer,0,DEFAULT_SECTOR_SIZE);
      }
      if(memcmp(buffer,"DOSEMU",6)==0 && *(unsigned long*)(buffer+11)>0)
      {
	log_info("%s DOSEMU\n",device);
	disk_car->CHS.cylinder=*(unsigned long*)(buffer+15)-1;
	disk_car->CHS.head=*(unsigned long*)(buffer+7)-1;
	disk_car->CHS.sector=*(unsigned long*)(buffer+11);
	disk_car->disk_size=(uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size;
	disk_car->disk_real_size=disk_car->disk_size;
	offset=*(unsigned long*)(buffer+19);
	disk_car->autodetect=0;
      }
      else if(memcmp(buffer, evf_file_signature, 8)==0)
      {
	free(buffer);
	close(hd_h);
#if defined(HAVE_LIBEWF_H) && defined(HAVE_LIBEWF)
	return fewf_init(device,verbose,arch,testdisk_mode);
#else
	return NULL;
#endif
      }
      else
      {
	disk_car->CHS.cylinder=0;
	disk_car->CHS.head=255-1;
	disk_car->CHS.sector=63;
	if(stat_rec.st_size>offset)
	{
	  disk_car->disk_size=(uint64_t)(stat_rec.st_size-offset+disk_car->sector_size-1)/disk_car->sector_size*disk_car->sector_size;
	}
	else
	{
	  off_t pos;
	  pos=lseek(hd_h,0,SEEK_END);
	  if(pos>offset)
	    disk_car->disk_size=(uint64_t)(pos-offset);
	  else
	    disk_car->disk_size=0;
	}
	disk_car->disk_real_size=disk_car->disk_size;
	autoset_geometry(disk_car,buffer,verbose);
      }
      free(buffer);
    }
    if(disk_car!=NULL)
    {
      struct info_file_struct *data;
      data=MALLOC(sizeof(*data));
      strncpy(data->file_name,device,sizeof(data->file_name));
      data->file_name[sizeof(data->file_name)-1]='\0';
      data->handle=hd_h;
#if defined(POSIX_FADV_SEQUENTIAL) && defined(HAVE_POSIX_FADVISE)
      posix_fadvise(hd_h,0,0,POSIX_FADV_SEQUENTIAL);
#endif
      data->mode=mode;
      disk_car->rbuffer=NULL;
      disk_car->wbuffer=NULL;
      disk_car->rbuffer_size=0;
      disk_car->wbuffer_size=0;
      disk_car->device=strdup(device);
      disk_car->write_used=0;
      disk_car->description_txt[0]='\0';
      disk_car->description=file_description;
      disk_car->description_short=file_description_short;
      disk_car->read=file_read;
      disk_car->write=((mode&O_RDWR)==O_RDWR?file_write:file_nowrite);
      disk_car->sync=file_sync;
      disk_car->access_mode=((mode&O_RDWR)==O_RDWR?TESTDISK_O_RDWR:TESTDISK_O_RDONLY);
#ifdef O_DIRECT
      if((mode&O_DIRECT)==O_DIRECT)
        disk_car->access_mode|=TESTDISK_O_DIRECT;
#endif
      disk_car->clean=file_clean;
      disk_car->data=data;
      /* Note, some Raid reserves the first 1024 512-sectors */
      disk_car->offset=offset;
      if(disk_car->disk_size==0)
      {
        /* Handle Mac */
        compute_device_size(disk_car);
        if(verbose>1)
        {
          log_verbose("file_test_availability compute_device_size %s size %llu\n", device, (long long unsigned)disk_car->disk_size);
        }
        /* Round up because file is often truncated. */
        if((disk_car->disk_size/disk_car->sector_size+(uint64_t)disk_car->CHS.sector*(disk_car->CHS.head+1)-1)/disk_car->CHS.sector/(disk_car->CHS.head+1)==0)
          disk_car->CHS.cylinder=0;
        else
          disk_car->CHS.cylinder=(disk_car->disk_size/disk_car->sector_size+(uint64_t)disk_car->CHS.sector*(disk_car->CHS.head+1)-1)/disk_car->CHS.sector/(disk_car->CHS.head+1)-1;
      }
      if(disk_car->disk_size==0)
      {
	log_warning("Warning: can't get size for %s\n",device);
	free(data);
	free(disk_car->device);
	free(disk_car);
	close(hd_h);
	return NULL;
      }
      disk_car->unit=UNIT_CHS;
      return disk_car;
    }
    close(hd_h);
  }
  else if(strncmp(device,"/dev/",5)!=0)
  {
#if defined(HAVE_LIBEWF_H) && defined(HAVE_LIBEWF) && defined(HAVE_GLOB_H)
    return fewf_init(device,verbose,arch,testdisk_mode);
#endif
  }
#ifdef DJGPP
  {
   int   dos_nr=0;
   /* Check for device name. It must be like /dev/sdaXX and *
    * XX is a value between 128 and 135 (0x80 to 0x88)      */
   if(strcmp(device, "/dev/sda128") == 0)
     dos_nr = 0x80;
   else if(strcmp(device, "/dev/sda129") == 0)
     dos_nr = 0x81;
   else if(strcmp(device, "/dev/sda130") == 0)
     dos_nr = 0x82;
   else if(strcmp(device, "/dev/sda131") == 0)
     dos_nr = 0x83;
   else if(strcmp(device, "/dev/sda132") == 0)
     dos_nr = 0x84;
   else if(strcmp(device, "/dev/sda133") == 0)
     dos_nr = 0x85;
   else if(strcmp(device, "/dev/sda134") == 0)
     dos_nr = 0x86;
   else if(strcmp(device, "/dev/sda135") == 0)
     dos_nr = 0x87;
   if(dos_nr>0)
     disk_car = hd_identify(verbose, dos_nr, arch, testdisk_mode);
  }
#endif
  return disk_car;
}

void hd_update_geometry(disk_t *disk_car, const int allow_partial_last_cylinder, const int verbose)
{
  unsigned char *buffer;
  uint64_t pos;
  CHS_t pos_CHS;
  buffer=MALLOC(disk_car->sector_size);
  if(disk_car->autodetect!=0)
  {
    if(disk_car->read(disk_car,disk_car->sector_size, buffer, 0)==0)
    {
      if(verbose>1)
      {
	log_trace("autoset_geometry\n");
      }
      autoset_geometry(disk_car,buffer,1);
    }
  }
  dup_CHS(&pos_CHS,&disk_car->CHS);
  pos_CHS.cylinder++;
  if(allow_partial_last_cylinder) {
    pos_CHS.head=0;
    pos_CHS.sector=1;
  }
  pos=CHS2offset(disk_car,&pos_CHS);
#ifdef DJGPP
  if(disk_car->description==disk_description)
  {
    struct info_disk_struct*data=disk_car->data;
    data->CHSR.cylinder=0;
  }
#endif
  if((unsigned int)(disk_car->CHS.cylinder+1)!=0)	/* Avoid to wrap */
  {
    if(disk_car->read(disk_car,disk_car->sector_size, buffer, pos)==0)
    {
      disk_car->CHS.cylinder++;
      if(disk_car->disk_size < (uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size)
      {
	disk_car->disk_size=(uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size;
	log_info("Computes LBA from CHS for %s\n",disk_car->description(disk_car));
      }
    }
  }
#ifdef DJGPP
  if(disk_car->description==disk_description)
  {
    struct info_disk_struct*data=disk_car->data;
    data->CHSR.cylinder=disk_car->CHS.cylinder;
  }
#endif
  free(buffer);
}

void hd_update_all_geometry(const list_disk_t * list_disk, const int allow_partial_last_cylinder, const int verbose)
{
  const list_disk_t *element_disk;
  if(verbose>1)
  {
    log_trace("hd_update_all_geometry\n");
  }
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    hd_update_geometry(element_disk->disk,allow_partial_last_cylinder,verbose);
}

#if defined(__CYGWIN__) || defined(__MINGW32__)
// Try to handle cdrom
static const char *file_win32_description(disk_t *disk_car);
static const char *file_win32_description_short(disk_t *disk_car);
static int file_win32_clean(disk_t *disk_car);
static unsigned int file_win32_compute_sector_size(HANDLE handle, const unsigned int sector_size_default);
static int file_win32_read(disk_t *disk_car, const unsigned int count, void *buf, const uint64_t offset);
static int file_win32_write(disk_t *disk_car,const unsigned int count, const void *buf, const uint64_t offset);
static int file_win32_nowrite(disk_t *disk_car, const unsigned int count, const void *buf, const uint64_t offset);
static int file_win32_sync(disk_t *disk_car);
uint64_t filewin32_getfilesize(HANDLE handle, const char *device);
uint64_t filewin32_setfilepointer(HANDLE handle, const char *device);

struct info_file_win32_struct
{
  HANDLE handle;
  char file_name[DISKNAME_MAX];
  int mode;
};

uint64_t filewin32_getfilesize(HANDLE handle, const char *device)
{
  DWORD lpFileSizeLow;
  DWORD lpFileSizeHigh;
  lpFileSizeLow=GetFileSize(handle,&lpFileSizeHigh);
  if(lpFileSizeLow==INVALID_FILE_SIZE && GetLastError() != NO_ERROR)
  {
    LPVOID lpMsgBuf;
    DWORD dw = GetLastError(); 
    FormatMessage(
	FORMAT_MESSAGE_ALLOCATE_BUFFER | 
	FORMAT_MESSAGE_FROM_SYSTEM,
	NULL,
	dw,
	MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	(LPTSTR) &lpMsgBuf,
	0, NULL );
    log_error("filewin32_getfilesize(%s) GetFileSize err %s\n", device, (char*)lpMsgBuf);
    LocalFree(lpMsgBuf);
    return 0;
  }
  log_verbose("filewin32_getfilesize(%s) ok\n",device);
  return lpFileSizeLow+((uint64_t)lpFileSizeHigh>>32);
}

uint64_t filewin32_setfilepointer(HANDLE handle, const char *device)
{
  LARGE_INTEGER li;
  li.QuadPart = 0;
  li.LowPart = SetFilePointer(handle, li.LowPart, &li.HighPart, FILE_END);
  if(li.LowPart==INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
  {
    LPVOID lpMsgBuf;
    DWORD dw = GetLastError(); 
    FormatMessage(
	FORMAT_MESSAGE_ALLOCATE_BUFFER | 
	FORMAT_MESSAGE_FROM_SYSTEM,
	NULL,
	dw,
	MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	(LPTSTR) &lpMsgBuf,
	0, NULL );
    log_error("filewin32_setfilepointer(%s) SetFilePointer err %s\n", device, (char*)lpMsgBuf);
    LocalFree(lpMsgBuf);
    return 0;
  }
  log_verbose("filewin32_setfilepointer(%s) ok\n",device);
  return li.LowPart+((uint64_t)li.HighPart>>32);
}

disk_t *file_test_availability_win32(const char *device, const int verbose, const arch_fnct_t *arch, int testdisk_mode)
{
  disk_t *disk_car=NULL;
  HANDLE handle=INVALID_HANDLE_VALUE;
  int mode=0;
  int try_readonly=1;
  if((testdisk_mode&TESTDISK_O_RDWR)==TESTDISK_O_RDWR)
  {
    mode = FILE_READ_DATA | FILE_WRITE_DATA;
    handle = CreateFile(device,mode, (FILE_SHARE_WRITE | FILE_SHARE_READ),
	NULL, OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE)
    {
      if(verbose>1)
      {
#ifdef __MINGW32__
	log_error("file_test_availability_win32 RW failed %s\n", device);
#else
	LPVOID buf;
	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
	    , NULL
	    , GetLastError()
	    , MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
	    , (LPTSTR)&buf
	    , 0
	    , NULL 
	    );
	log_error("file_test_availability_win32 RW failed: %s: %s\n", device,(const char*)buf);
	LocalFree(buf);
#endif
      }
      try_readonly=0;
    }
  }
  if(handle==INVALID_HANDLE_VALUE && try_readonly>0)
  {
    testdisk_mode&=~TESTDISK_O_RDWR;
    mode = FILE_READ_DATA;
    handle = CreateFile(device,mode, (FILE_SHARE_WRITE | FILE_SHARE_READ),
	NULL, OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE)
    {
      if(verbose>1)
      {
#ifdef __MINGW32__
	log_error("file_test_availability_win32 RO %s error\n", device);
#else
	LPVOID buf;
	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
	    , NULL
	    , GetLastError()
	    , MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
	    , (LPTSTR)&buf
	    , 0
	    , NULL 
	    );
	log_error("file_test_availability_win32 RO failed: %s: %s\n", device,(const char*)buf);
	LocalFree(buf);
#endif
      }
    }
  }
  if(handle!=INVALID_HANDLE_VALUE)
  {
    struct info_file_win32_struct *data;
    disk_car=disk_get_geometry_win32(handle,device,verbose);
    if (disk_car==NULL)
    {
      uint64_t i64FreeBytesToCaller, i64TotalBytes, i64FreeBytes;
      DWORD dwSectPerClust, 
	    dwBytesPerSect, 
	    dwFreeClusters, 
	    dwTotalClusters;
      disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
      disk_car->disk_size=0;
      disk_car->sector_size=0;
      disk_car->CHS.cylinder=0;
      disk_car->CHS.head=0;
      disk_car->CHS.sector=1;
      if(GetDiskFreeSpaceA (&device[4], 
	    &dwSectPerClust, 
	    &dwBytesPerSect,
	    &dwFreeClusters, 
	    &dwTotalClusters)!=0)
      {
	disk_car->sector_size=dwBytesPerSect;
      }
      if(GetDiskFreeSpaceEx (&device[4],
	  (PULARGE_INTEGER)&i64FreeBytesToCaller,
	  (PULARGE_INTEGER)&i64TotalBytes,
	  (PULARGE_INTEGER)&i64FreeBytes)!=0)
      {
	disk_car->disk_size=i64TotalBytes;
	if(disk_car->sector_size==0)
	  disk_car->sector_size=file_win32_compute_sector_size(handle,DEFAULT_SECTOR_SIZE);
      }
      else
      {
	disk_car->sector_size=file_win32_compute_sector_size(handle,DEFAULT_SECTOR_SIZE);
	disk_car->disk_size=filewin32_getfilesize(handle, device);
	if(disk_car->disk_size==0)
	  disk_car->disk_size=filewin32_setfilepointer(handle, device);
      }
    }
    disk_car->arch=arch;
    data=MALLOC(sizeof(*data));
    strncpy(data->file_name,device,sizeof(data->file_name));
    data->file_name[sizeof(data->file_name)-1]='\0';
    data->handle=handle;
    data->mode=mode;
    disk_car->rbuffer=NULL;
    disk_car->wbuffer=NULL;
    disk_car->rbuffer_size=0;
    disk_car->wbuffer_size=0;
    disk_car->device=strdup(device);
    disk_car->write_used=0;
    disk_car->description_txt[0]='\0';
    disk_car->description=file_win32_description;
    disk_car->description_short=file_win32_description_short;
    disk_car->read=file_win32_read;
    disk_car->write=((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?file_win32_write:file_win32_nowrite);
    disk_car->sync=file_win32_sync;
    disk_car->access_mode=testdisk_mode;
    disk_car->clean=file_win32_clean;
    disk_car->data=data;
    disk_car->offset=0;
    if(disk_car->disk_size==0)
    {
      compute_device_size(disk_car);
      if(verbose>1)
      {
        log_verbose("file_test_availability compute_device_size %s size %llu\n", device, (long long unsigned)disk_car->disk_size);
      }
    }
    if(disk_car->disk_size==0)
    {
      log_warning("Warning: can't get size for %s\n",device);
      free(data);
      free(disk_car->device);
      free(disk_car);
      CloseHandle(handle);
      return NULL;
    }
    disk_car->CHS.cylinder=(disk_car->disk_size/(disk_car->CHS.head+1))/disk_car->CHS.sector/disk_car->sector_size-1;
    disk_car->unit=UNIT_CHS;
    return disk_car;
  }
  return NULL;
}

static const char *file_win32_description(disk_t *disk_car)
{
  struct info_file_win32_struct *data=disk_car->data;
  char buffer_disk_size[100];
  if(data->file_name[0]=='\\' && data->file_name[1]=='\\' && data->file_name[2]=='.' && data->file_name[3]=='\\' && data->file_name[5]==':')
    snprintf(disk_car->description_txt, sizeof(disk_car->description_txt),"Drive %c: - %s - CHS %u %u %u%s",
	data->file_name[4], size_to_unit(disk_car->disk_size,buffer_disk_size),
	disk_car->CHS.cylinder+1, disk_car->CHS.head+1, disk_car->CHS.sector,
	((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?"":" (RO)"));
  else
    snprintf(disk_car->description_txt, sizeof(disk_car->description_txt),"Disk %s - %s - CHS %u %u %u%s",
	data->file_name, size_to_unit(disk_car->disk_size,buffer_disk_size),
	disk_car->CHS.cylinder+1, disk_car->CHS.head+1, disk_car->CHS.sector,
	((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?"":" (RO)"));
  return disk_car->description_txt;
}

static const char *file_win32_description_short(disk_t *disk_car)
{
  struct info_file_win32_struct *data=disk_car->data;
  char buffer_disk_size[100];
  if(data->file_name[0]=='\\' && data->file_name[1]=='\\' && data->file_name[2]=='.' && data->file_name[3]=='\\' && data->file_name[5]==':')
    snprintf(disk_car->description_short_txt, sizeof(disk_car->description_txt),"Drive %c: - %s%s",
	data->file_name[4], size_to_unit(disk_car->disk_size,buffer_disk_size),
	((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?"":" (RO)"));
  else
    snprintf(disk_car->description_short_txt, sizeof(disk_car->description_txt),"Disk %s - %s%s",
	data->file_name, size_to_unit(disk_car->disk_size,buffer_disk_size),
	((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?"":" (RO)"));
  return disk_car->description_short_txt;
}

static int file_win32_clean(disk_t *disk_car)
{
  if(disk_car->data!=NULL)
  {
    struct info_file_win32_struct *data=disk_car->data;
    CloseHandle(data->handle);
  }
  return generic_clean(disk_car);
}

static unsigned int file_win32_compute_sector_size(HANDLE handle, const unsigned int sector_size_default)
{
  unsigned int sector_size;
  char *buffer=MALLOC(4096);
  for(sector_size=sector_size_default;sector_size<=4096;sector_size*=2)
  {
    long int ret;
    DWORD dwByteRead;
    ret=ReadFile(handle, buffer,sector_size,&dwByteRead,NULL);
    if(ret && dwByteRead==sector_size)
    {
      free(buffer);
      return sector_size;
    }
  }
  free(buffer);
  return sector_size_default;
}

static int file_win32_read_aux(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset)
{
  long int ret;
  HANDLE fd=((struct info_file_win32_struct *)disk_car->data)->handle;
  LARGE_INTEGER li;
  li.QuadPart = offset;
  li.LowPart = SetFilePointer(fd, li.LowPart, &li.HighPart, FILE_BEGIN);
  if (li.LowPart == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
  {
    LPVOID lpMsgBuf;
    DWORD dw = GetLastError(); 
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );
    log_error("file_win32_read(%d,%u,buffer,%lu(%u/%u/%u)) seek err %s\n", (int)fd,
        (unsigned)(count/disk_car->sector_size), (long unsigned int)(offset/disk_car->sector_size),
        offset2cylinder(disk_car,offset), offset2head(disk_car,offset), offset2sector(disk_car,offset),
        (char*)lpMsgBuf);
    LocalFree(lpMsgBuf);
    return -1;
  }
  {
    DWORD dwByteRead;
    ret=ReadFile(fd, buf,count,&dwByteRead,NULL);
    if(ret)
      ret=dwByteRead;
  }
  if(ret!=count)
  {
    if(ret>0 || offset<disk_car->disk_size)
    {
      log_error("file_win32_read(%d,%u,buffer,%lu(%u/%u/%u)) read err: ", (int)fd,
          (unsigned)(count/disk_car->sector_size), (long unsigned)(offset/disk_car->sector_size),
          offset2cylinder(disk_car,offset), offset2head(disk_car,offset), offset2sector(disk_car,offset));
      if(ret<0)
      {
        LPVOID lpMsgBuf;
        DWORD dw = GetLastError(); 
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            dw,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL );
        log_error("%s\n", (char*)lpMsgBuf);
        LocalFree(lpMsgBuf);
      }
      else if(ret==0)
        log_error("read after end of file\n");
      else
        log_error("Partial read\n");
    }
    if(ret<=0)
      return -1;
    memset((char*)buf+ret,0,count-ret);
  }
  return 0;
}

static int file_win32_read(disk_t *disk_car,const unsigned int count, void *buf, const uint64_t offset)
{
  return align_read(&file_win32_read_aux, disk_car, buf, count, offset);
}

static int file_win32_write_aux(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset)
{
  long int ret;
  HANDLE fd=((struct info_file_win32_struct *)disk_car->data)->handle;
  LARGE_INTEGER li;
  li.QuadPart = offset;
  li.LowPart = SetFilePointer(fd, li.LowPart, &li.HighPart, FILE_BEGIN);
  if (li.LowPart == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
  {
    LPVOID lpMsgBuf;
    DWORD dw = GetLastError(); 
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );
    log_error("file_win32_write(%d,%u,buffer,%lu(%u/%u/%u)) seek err %s\n", (int)fd,
        (unsigned)(count/disk_car->sector_size), (long unsigned int)(offset/disk_car->sector_size),
        offset2cylinder(disk_car,offset), offset2head(disk_car,offset), offset2sector(disk_car,offset),
        (char*)lpMsgBuf);
    LocalFree(lpMsgBuf);
    return -1;
  }
  {
    DWORD dwByteRead;
    ret=WriteFile(fd, buf,count,&dwByteRead,NULL);
    if(ret)
      ret=dwByteRead;
  }
  disk_car->write_used=1;
  if(ret!=count)
  {
    log_error("file_win32_write(%u,%u,buffer,%lu(%u/%u/%u)) write err\n", (int)fd,
        (unsigned)(count/disk_car->sector_size), (long unsigned)(offset/disk_car->sector_size),
        offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset));
    return -1;
  }
  return 0;
}

static int file_win32_write(disk_t *disk_car,const unsigned int count, const void *buf, const uint64_t offset)
{
  return align_write(&file_win32_read_aux, &file_win32_write_aux, disk_car, buf, count, offset);
}

static int file_win32_nowrite(disk_t *disk_car,const unsigned int count, const void *buf, const uint64_t offset)
{
  const struct info_file_win32_struct *data=disk_car->data;
  log_warning("file_win32_nowrite(%d,%u,buffer,%lu(%u/%u/%u)) write refused\n", (unsigned int)data->handle,
      (unsigned)(count/disk_car->sector_size),(long unsigned)(offset/disk_car->sector_size),
      offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset));
  return -1;
}

static int file_win32_sync(disk_t *disk_car)
{
  const struct info_file_win32_struct *data=disk_car->data;
  if(FlushFileBuffers(data->handle)==0)
  {
    errno=EINVAL;
    return -1;
  }
  errno=0;
  return 0;
}
#endif

void autoset_unit(disk_t *disk_car)
{
  if(disk_car==NULL)
    return ;
  if(disk_car->arch==&arch_mac || 
      disk_car->arch==&arch_gpt || 
      (disk_car->CHS.head==0 && disk_car->CHS.sector==1))
    disk_car->unit=UNIT_SECTOR;
  else
    disk_car->unit=UNIT_CHS;
}
