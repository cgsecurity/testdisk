/*

    File: hdaccess.c

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
#include <stdlib.h>     /* free, atexit, posix_memalign */
#endif
#include <ctype.h>	/* isspace */
#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

#if defined(__CYGWIN__) || defined(__MINGW32__)
#include "win32.h"
#include "hdwin32.h"
#endif
#if defined(DJGPP)
#include "msdos.h"
#endif
#if defined(__CYGWIN__)
#include <io.h>
#endif
#include "fnctdsk.h"
#include "ewf.h"
#include "log.h"
#include "hdaccess.h"
#include "alignio.h"
#include "hpa_dco.h"

#if defined(HAVE_PREAD) && defined(TARGET_LINUX)
//#define HDCLONE 1
#endif

extern const arch_fnct_t arch_none;

struct tdewf_file_header
{
        /* The EWF file signature (magic header)
         * consists of 8 bytes containing
         * EVF 0x09 0x0d 0x0a 0xff 0x00
         */
        uint8_t signature[ 8 ];
        /* The fields start
         * consists of 1 byte (8 bit) containing
         * 0x01
         */
        uint8_t fields_start;
        /* The fields segment number
         * consists of 2 bytes (16 bits) containing
         */
        uint16_t fields_segment;
        /* The fields end
         * consists of 2 bytes (16 bits) containing
         * 0x00 0x00
         */
        uint16_t fields_end;
} __attribute__ ((__packed__));


struct info_file_struct
{
  int handle;
#ifdef HDCLONE
  int handle_clone;
#endif
  char file_name[DISKNAME_MAX];
  int mode;
};

static void autoset_geometry(disk_t * disk_car, const unsigned char *buffer, const int verbose);
static void file_clean(disk_t *disk);
static int file_pread(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset);
static int file_pwrite(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset);
static int file_nopwrite(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset);
static int file_sync(disk_t *disk_car);
#ifndef DJGPP
static uint64_t compute_device_size(const int hd_h, const char *device, const int verbose, const unsigned int sector_size);
#endif

void generic_clean(disk_t *disk)
{
  free(disk->device);
  free(disk->model);
  free(disk->serial_no);
  free(disk->fw_rev);
  free(disk->data);
  free(disk->rbuffer);
  free(disk->wbuffer);
  disk->device=NULL;
  disk->model=NULL;
  disk->serial_no=NULL;
  disk->fw_rev=NULL;
  disk->data=NULL;
  disk->rbuffer=NULL;
  disk->wbuffer=NULL;
  free(disk);
}

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
      if(cur->disk->sector_size==disk_car->sector_size &&
	  ((cur->disk->model==NULL && disk_car->model==NULL && cur->disk->disk_size==disk_car->disk_size) ||
	   (cur->disk->model!=NULL && disk_car->model!=NULL && strcmp(cur->disk->model, disk_car->model)==0)))
        disk_same_size_present=1;
    }
    if(disk_car->sector_size==512 && disk_same_size_present!=0)
    {
      if(verbose>1)
        log_verbose("%s is available but reject it to avoid duplicate disk.\n", device_name);
      disk_car->clean(disk_car);
      return list_disk;
    }
    return insert_new_disk(list_disk,disk_car);
  }
}
#endif

#ifdef HAVE_GLOB_H
static list_disk_t *hd_glob_parse(const char *device_pattern, list_disk_t *list_disk, const int verbose, const int testdisk_mode)
{
  glob_t globbuf;
  globbuf.gl_offs = 0;
  glob(device_pattern, GLOB_DOOFFS, NULL, &globbuf);
  if(globbuf.gl_pathc>0)
  {
    unsigned int i;
    for (i=0; i<globbuf.gl_pathc; i++)
    {
      list_disk=insert_new_disk(list_disk, file_test_availability(globbuf.gl_pathv[i], verbose, testdisk_mode));
    }
  }
  globfree(&globbuf);
  return list_disk;
}
#endif


list_disk_t *hd_parse(list_disk_t *list_disk, const int verbose, const int testdisk_mode)
{
  unsigned int i;
#ifdef DJGPP
  int ind_stop=0;
  for(i=0x80;(i<0x88)&&!ind_stop;i++)
  {
    disk_t *disk_car=hd_identify(verbose, i, testdisk_mode);
    if(disk_car)
      list_disk=insert_new_disk(list_disk,disk_car);
    else
      ind_stop=1;
  }
#elif defined(__CYGWIN__) || defined(__MINGW32__)
  {
    int do_insert=0;
    char device_hd[]="\\\\.\\PhysicalDrive00";
    char device_cdrom[]="\\\\.\\C:";
#if defined(__CYGWIN__)
    char device_scsi[]="/dev/sda";
    /* Disk */
    for(i=0;i<16;i++)
    {
      device_scsi[strlen(device_scsi)-1]='a'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_scsi, verbose, testdisk_mode));
    }
#endif
    /* Disk */
    if(list_disk==NULL)
      do_insert=1;
    {
      for(i=0;i<16;i++)
      {
	disk_t *disk_car;
	sprintf(device_hd,"\\\\.\\PhysicalDrive%u", i);
	disk_car=file_test_availability_win32(device_hd, verbose, testdisk_mode);
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
      disk_car=file_test_availability_win32(device_cdrom, verbose, testdisk_mode);
      if((testdisk_mode&TESTDISK_O_ALL)==TESTDISK_O_ALL)
	list_disk=insert_new_disk(list_disk,disk_car);
      else
	list_disk=insert_new_disk_nodup(list_disk,disk_car,device_cdrom, verbose);
    }
  }
#elif defined(__APPLE__)
  {
    char device[100];
    /* Disk */
    for(i=0;i<20;i++)
    {
      snprintf(device, sizeof(device), "/dev/disk%u", i);
      list_disk=insert_new_disk(list_disk, file_test_availability(device, verbose, testdisk_mode));
    }
    for(i=0;i<20;i++)
    {
      snprintf(device, sizeof(device), "/dev/rdisk%u", i);
      list_disk=insert_new_disk(list_disk, file_test_availability(device, verbose, testdisk_mode));
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
    char device_mmc[]="/dev/mmcblk0";
    /* Disk IDE */
    for(i=0;i<8;i++)
    {
      device_ide[strlen(device_ide)-1]='a'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_ide, verbose, testdisk_mode));
    }
    /* Disk SCSI */
    for(i=0;i<26;i++)
    {
      device_scsi[strlen(device_scsi)-1]='a'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_scsi, verbose, testdisk_mode));
    }
    /* Device RAID Compaq */
    for(j=0;j<8;j++)
    {
      device_ida[strlen(device_ida)-3]='0'+j;
      for(i=0;i<8;i++)
      {
	device_ida[strlen(device_ida)-1]='0'+i;
	list_disk=insert_new_disk(list_disk, file_test_availability(device_ida, verbose, testdisk_mode));
      }
    }
    for(i=0;i<8;i++)
    {
      device_cciss[strlen(device_cciss)-1]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_cciss, verbose, testdisk_mode));
    }
    /* Device RAID */
    for(i=0;i<10;i++)
    {
      snprintf(device,sizeof(device),"/dev/rd/c0d%u",i);
      list_disk=insert_new_disk(list_disk, file_test_availability(device, verbose, testdisk_mode));
    }
    /* Device RAID IDE */
    for(i=0;i<15;i++)
    {
      snprintf(device,sizeof(device),"/dev/ataraid/d%u",i);
      list_disk=insert_new_disk(list_disk, file_test_availability(device, verbose, testdisk_mode));
    }
    /* Parallel port IDE disk */
    for(i=0;i<4;i++)
    {
      device_p_ide[strlen(device_p_ide)-1]='a'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_p_ide, verbose, testdisk_mode));
    }
    /* I2O hard disk */
    for(i=0;i<26;i++)
    {
      device_i2o_hd[strlen(device_i2o_hd)-1]='a'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_i2o_hd, verbose, testdisk_mode));
    }
    /* Memory card */
    for(i=0;i<10;i++)
    {
      device_mmc[strlen(device_mmc)-1]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_mmc, verbose, testdisk_mode));
    }
#ifdef HAVE_GLOB_H
    list_disk=hd_glob_parse("/dev/mapper/*", list_disk, verbose, testdisk_mode);
    /* Software Raid (partition level) */
    list_disk=hd_glob_parse("/dev/md*", list_disk, verbose, testdisk_mode);
    list_disk=hd_glob_parse("/dev/sr?", list_disk, verbose, testdisk_mode);
    /* Software (ATA)Raid configured (disk level) via dmraid */
    list_disk=hd_glob_parse("/dev/dm-*", list_disk, verbose, testdisk_mode);
    /* Xen virtual disks */
    list_disk=hd_glob_parse("/dev/xvd?", list_disk, verbose, testdisk_mode);
#endif
  }
#elif defined(TARGET_SOLARIS)
  {
    char rdsk[]="/dev/rdsk/c0t0d0s2";
    for(i=0;i<15;i++)
    {
      if(i!=7)
      {
	rdsk[13]='0'+i;
	list_disk=insert_new_disk(list_disk, file_test_availability(rdsk, verbose, testdisk_mode));
      }
    }
  }
#elif defined(__HAIKU__)
  {
#ifdef HAVE_GLOB_H
    list_disk=hd_glob_parse("/dev/disk/*/*/master/raw", list_disk, verbose, testdisk_mode);
#endif
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
    char device_vnd[]="/dev/rsvnd0c";	/* virtual node driver, interface to a disk image file */
    /* wd da */
    /* Disk IDE */
    for(i=0;i<8;i++)
    {
      device_ide[strlen(device_ide)-1]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_ide, verbose, testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_ide2[strlen(device_ide2)-1]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_ide2, verbose, testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_ide3[strlen(device_ide3)-2]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_ide3, verbose, testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_ide4[strlen(device_ide4)-2]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_ide4, verbose, testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_ide_hd[strlen(device_ide_hd)-1]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_ide_hd, verbose, testdisk_mode));
    }
    /* Disk SCSI */
    for(i=0;i<8;i++)
    {
      device_scsi[strlen(device_scsi)-1]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_scsi, verbose, testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_scsi2[strlen(device_scsi2)-2]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_scsi2, verbose, testdisk_mode));
    }
    for(i=0;i<8;i++)
    {
      device_scsi_hd[strlen(device_scsi_hd)-1]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_scsi_hd, verbose, testdisk_mode));
    }
    /* optical disks */
    for(i=0;i<8;i++)
    {
      device_optdisk[strlen(device_scsi)-1]='a'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_optdisk, verbose, testdisk_mode));
    } 
    /* CD */
    for(i=0;i<8;i++)
    {
      device_cd[strlen(device_cd)-1]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_cd, verbose, testdisk_mode));
    }
    /* VND */
    for(i=0;i<4;i++)
    {
      device_vnd[strlen(device_vnd)-2]='0'+i;
      list_disk=insert_new_disk(list_disk, file_test_availability(device_vnd, verbose, testdisk_mode));
    }
  }
#endif
  return list_disk;
}

#ifndef DJGPP
static unsigned int disk_get_sector_size(const int hd_h, const char *device, const int verbose)
{
  unsigned int sector_size=0;
#ifdef BLKSSZGET
  {
    int arg=0;
    if (ioctl(hd_h, BLKSSZGET, &arg) == 0)
    {
      sector_size=arg;
      if(verbose>1)
      {
	log_verbose("disk_get_sector_size BLKSSZGET %s sector_size=%u\n", device, sector_size);
      }
      if(sector_size!=0)
	return sector_size;
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
	log_verbose("disk_get_sector_size DIOCGSECTORSIZE %s sector_size=%u\n",device,sector_size);
      }
      if(sector_size!=0)
	return sector_size;
    }
  }
#endif
#ifdef DIOCGDINFO
  {
    struct disklabel geometry;
    if (ioctl(hd_h, DIOCGDINFO, &geometry)==0)
    { /* I can get the geometry */
      sector_size=geometry.d_secsize;
      if(verbose>1)
      {
	log_verbose("disk_get_sector_size DIOCGDINFO %s Ok\n",device);
      }
      if(sector_size!=0)
	return sector_size;
    }
  }
#endif
#ifdef DKIOCGETBLOCKSIZE
  {
    /* Mac */
    uint32_t arg=0;
    if(ioctl(hd_h,DKIOCGETBLOCKSIZE,&arg)==0)
    {
      sector_size=arg;
      if(verbose>1)
      {
	log_verbose("disk_get_sector_size DKIOCGETBLOCKSIZE %s sector_size=%u\n",
	    device, sector_size);
      }
      if(sector_size!=0)
	return sector_size;
    }
  }
#endif
#if defined(__CYGWIN__) || defined(__MINGW32__)
  {
    DWORD dwSectPerClust, 
	  dwBytesPerSect, 
	  dwFreeClusters, 
	  dwTotalClusters;
    if(GetDiskFreeSpaceA (&device[4], 
	  &dwSectPerClust, 
	  &dwBytesPerSect,
	  &dwFreeClusters, 
	  &dwTotalClusters)!=0)
    {
      sector_size=dwBytesPerSect;
      if(verbose>1)
      {
	log_verbose("disk_get_sector_size GetDiskFreeSpaceA %s Ok\n",device);
      }
      /* sector_size <= 16MB*/
      if(sector_size>0 && sector_size <= (1<<24))
	return sector_size;
    }
  }
  {
    HANDLE handle;
#if defined(__CYGWIN__)
    handle=(HANDLE)get_osfhandle(hd_h);
#else
    handle=(HANDLE)_get_osfhandle(hd_h);
#endif
    return disk_get_sector_size_win32(handle, device, verbose);
  }
#endif
  if(verbose>1)
  {
    log_verbose("disk_get_sector_size default sector size for %s\n",device);
  }
  return DEFAULT_SECTOR_SIZE;
}

static void disk_get_geometry(CHSgeometry_t *geom, const int hd_h, const char *device, const int verbose)
{
  if(verbose>1)
    log_verbose("disk_get_geometry for %s\n", device);
#ifdef HDIO_GETGEO_BIG
  if(geom->sectors_per_head==0)
  {
    struct hd_big_geometry geometry;
    if (ioctl(hd_h, HDIO_GETGEO_BIG, &geometry)>=0)
    { /* I can get the geometry */
      if(verbose>1)
      {
        log_verbose("disk_get_geometry HDIO_GETGEO_BIG %s Ok (%u,%u,%u)\n",
	    device, geometry.cylinders, geometry.heads, geometry.sectors);
      }
      geom->cylinders=geometry.cylinders;
      geom->heads_per_cylinder=geometry.heads;
      geom->sectors_per_head=geometry.sectors;
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
  if(geom->sectors_per_head==0)
  {
    struct hd_geometry geometry;
    if(ioctl(hd_h, HDIO_GETGEO, &geometry)>=0)
    { /* I can get the geometry */
      if(verbose>1)
      {
	log_verbose("disk_get_geometry HDIO_GETGEO %s Ok (%u,%u,%u)\n",
	    device, geometry.cylinders, geometry.heads, geometry.sectors);
      }
      geom->cylinders=geometry.cylinders;
      geom->heads_per_cylinder=geometry.heads;
      geom->sectors_per_head=geometry.sectors;
    }
  }
#endif
#ifdef DKIOCGGEOM
  if(geom->sectors_per_head==0)
  {
    struct dk_geom dkgeom;
    if (ioctl (hd_h, DKIOCGGEOM, &dkgeom)>=0) {
      geom->cylinders= dkgeom.dkg_ncyl;
      geom->heads_per_cylinder=dkgeom.dkg_nhead;
      geom->sectors_per_head=dkgeom.dkg_nsect;
      if(verbose>1)
      {
	log_verbose("disk_get_geometry DKIOCGGEOM %s Ok\n",device);
      }
    }
  }
#endif
#ifdef DIOCGDINFO
  if(geom->sectors_per_head==0)
  {
    struct disklabel geometry;
    if (ioctl(hd_h, DIOCGDINFO, &geometry)==0)
    { /* I can get the geometry */
      if(verbose>1)
      {
	log_verbose("disk_get_geometry DIOCGDINFO %s Ok\n",device);
      }
      geom->cylinders=geometry.d_ncylinders;
      geom->heads_per_cylinder=geometry.d_ntracks;
      geom->sectors_per_head=geometry.d_nsectors;
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
  if(geom->sectors_per_head==0)
  {
    int error;
    unsigned int u;
    error = ioctl(hd_h, DIOCGFWSECTORS, &u);
    if(error==0 && u>0)
    {
      unsigned int sectors,heads;
      sectors=u;
      if(verbose>1)
      {
	log_verbose("disk_get_geometry DIOCGFWSECTORS %s Ok\n",device);
      }
      error = ioctl(hd_h, DIOCGFWHEADS, &u);
      if(error==0 && u>0)
      {
	heads=u;
	if(verbose>1)
	{
	  log_verbose("disk_get_geometry DIOCGFWHEADS %s Ok\n",device);
	}
	geom->cylinders=0;
	geom->heads_per_cylinder=heads;
	geom->sectors_per_head=sectors;
      }
    }
  }
#endif
#if defined(__CYGWIN__) || defined(__MINGW32__)
  {
    HANDLE handle;
#if defined(__CYGWIN__)
    handle=(HANDLE)get_osfhandle(hd_h);
#else
    handle=(HANDLE)_get_osfhandle(hd_h);
#endif
    return disk_get_geometry_win32(geom, handle, device, verbose);
  }
#endif
  if(geom->sectors_per_head>0 && geom->heads_per_cylinder>0)
    return ;
  geom->cylinders=0;
  geom->heads_per_cylinder=1;
  geom->sectors_per_head=1;
  if(verbose>1)
  {
    log_error("disk_get_geometry default geometry for %s\n", device);
  }
}

static uint64_t disk_get_size(const int hd_h, const char *device, const int verbose, const unsigned int sector_size)
{
  if(verbose>1)
    log_verbose("disk_get_size for %s\n", device);
#ifdef BLKGETSIZE64
  {
    uint64_t longsectors64=0;
    if (ioctl(hd_h, BLKGETSIZE64, &longsectors64)>=0)
    {
      if(verbose>1)
      {
	log_verbose("disk_get_size BLKGETSIZE64 %s size %llu\n", device, (long long unsigned)longsectors64);
      }
      return longsectors64;
    }
  }
#endif
#ifdef BLKGETSIZE
  {
    unsigned long longsectors=0;
    if (ioctl(hd_h, BLKGETSIZE, &longsectors)>=0)
    {
      if(verbose>1)
      {
	log_verbose("disk_get_size BLKGETSIZE %s, number of sectors=%lu\n",device,longsectors);
      }
      if(DEFAULT_SECTOR_SIZE!=sector_size)
      {
	log_warning("disk_get_size, TestDisk assumes BLKGETSIZE returns the number of 512 byte sectors.\n");
      }
      return (uint64_t)longsectors*sector_size;
    }
  }
#endif
#ifdef DKIOCGETBLOCKCOUNT
  {
    uint64_t longsectors64=0;
    if (ioctl(hd_h, DKIOCGETBLOCKCOUNT, &longsectors64)>=0)
    {
      if(verbose>1)
      {
	log_verbose("disk_get_size DKIOCGETBLOCKCOUNT %s size %llu\n",
	    device, (long long unsigned)longsectors64*sector_size);
      }
      return longsectors64*sector_size;
    }
  }
#endif
#ifdef DIOCGMEDIASIZE
  {
    off_t o;
    int error;
    error = ioctl(hd_h, DIOCGMEDIASIZE, &o);
    if(error==0)
    {
      if(verbose>1)
      {
	log_verbose("disk_get_size DIOCGMEDIASIZE %s size %llu\n",
	    device, (long long unsigned)o);
      }
      return o;
    }
  }
#endif
#if defined(__CYGWIN__) || defined(__MINGW32__)
  {
    HANDLE handle;
#if defined(__CYGWIN__)
    handle=(HANDLE)get_osfhandle(hd_h);
#else
    handle=(HANDLE)_get_osfhandle(hd_h);
#endif
    return disk_get_size_win32(handle, device, verbose);
  }
#endif
  return compute_device_size(hd_h, device, verbose, sector_size);
}
#endif

void update_disk_car_fields(disk_t *disk_car)
{
  if(disk_car->disk_real_size==0)
  {
    if(disk_car->geom.cylinders>0)
    {
      log_warning("Fix disk size using CHS\n");
      disk_car->disk_real_size=(uint64_t)disk_car->geom.cylinders * disk_car->geom.heads_per_cylinder *
	disk_car->geom.sectors_per_head * disk_car->sector_size;
    }
  }
  else
  {
    const unsigned long int cylinder_num=disk_car->disk_real_size /
      (uint64_t)disk_car->geom.heads_per_cylinder /
      (uint64_t)disk_car->geom.sectors_per_head /
      (uint64_t)disk_car->sector_size;
    if(cylinder_num>0 && disk_car->geom.cylinders != cylinder_num)
    {
      log_debug("Fix cylinder count for %s: number of cylinders %lu !=  %lu (calculated)\n",
	  disk_car->device, disk_car->geom.cylinders, cylinder_num);
      disk_car->geom.cylinders = cylinder_num;
    }
  }
  if(disk_car->geom.cylinders == 0)
    disk_car->geom.cylinders++;
  disk_car->disk_size=disk_car->disk_real_size;
}

#ifdef TARGET_LINUX
/* This function reads the /sys entry named "file" for device "disk_car". */
static char * read_device_sysfs_file (const disk_t *disk_car, const char *file)
{
  FILE *f;
  char name_buf[128];
  char buf[256];

  snprintf (name_buf, 127, "/sys/block/%s/device/%s",
      basename (disk_car->device), file);

  if ((f = fopen (name_buf, "r")) == NULL)
    return NULL;

  if (fgets (buf, 255, f) == NULL)
  {
    fclose (f);
    return NULL;
  }

  fclose (f);
  return strip_dup (buf);
}
#endif

/* This function sends a query to a SCSI device for vendor and product
 * information.  It uses the deprecated SCSI_IOCTL_SEND_COMMAND to
 * issue this query.
 */
#ifdef TARGET_LINUX
#ifdef HAVE_SCSI_SCSI_H
#include <scsi/scsi.h>
#endif
#ifdef HAVE_SCSI_SCSI_IOCTL_H
#include <scsi/scsi_ioctl.h>
#endif
#ifdef HAVE_SCSI_SG_H
#include <scsi/sg.h>
#endif
#endif

#if defined(TARGET_LINUX) && defined(INQUIRY) && defined(SG_GET_VERSION_NUM)
typedef struct _scsi_inquiry_data
{
  uint8_t peripheral_info;
  uint8_t device_info;
  uint8_t version_info;
  uint8_t _field1;
  uint8_t additional_length;
  uint8_t _reserved1;
  uint8_t _reserved2;
  uint8_t _field2;
  uint8_t vendor_id[8];
  uint8_t product_id[16];
  uint8_t product_revision[4];
  uint8_t vendor_specific[20];
  uint8_t _reserved3[40];
} __attribute__((packed)) scsi_inquiry_data_t;
#define INQ_CMD_LEN	6
#define INQ_REPLY_LEN	sizeof(scsi_inquiry_data_t)

static int scsi_query_product_info (const int sg_fd, char **vendor, char **product, char **fw_rev)
{
  unsigned char inqCmdBlk[INQ_CMD_LEN] = {INQUIRY, 0, 0, 0, INQ_REPLY_LEN, 0};
  scsi_inquiry_data_t inqBuff;
  unsigned char sense_buffer[32];
  sg_io_hdr_t io_hdr;
  int k;
  char    buf[32];
  *vendor = NULL;
  *product = NULL;

  /* It is prudent to check we have a sg device by trying an ioctl */
  if (ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0 || k < 30000)
    return -1;
  /* Prepare INQUIRY command */
  memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
  io_hdr.interface_id = 'S';
  io_hdr.cmd_len = sizeof(inqCmdBlk);
  /* io_hdr.iovec_count = 0; */  /* memset takes care of this */
  io_hdr.mx_sb_len = sizeof(sense_buffer);
  io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
  io_hdr.dxfer_len = INQ_REPLY_LEN;
  io_hdr.dxferp = (unsigned char*)&inqBuff;
  io_hdr.cmdp = inqCmdBlk;
  io_hdr.sbp = sense_buffer;
  io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
  /* io_hdr.flags = 0; */     /* take defaults: indirect IO, etc */
  /* io_hdr.pack_id = 0; */
  /* io_hdr.usr_ptr = NULL; */

  if (ioctl(sg_fd, SG_IO, &io_hdr) < 0)
    return -1;

  /* now for the error processing */
  if ((io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK)
    return -1;

  memcpy (buf, inqBuff.vendor_id, 8);
  buf[8] = '\0';
  *vendor = strip_dup (buf);

  memcpy (buf, inqBuff.product_id, 16);
  buf[16] = '\0';
  *product = strip_dup (buf);

  /* Information is truncated */
  memcpy (buf, inqBuff.product_revision, 4);
  buf[4] = '\0';
  *fw_rev= strip_dup (buf);

  return 0;
}
#endif

#ifndef DJGPP
static void disk_get_model(const int hd_h, disk_t *dev, const unsigned int verbose)
{
#ifdef HDIO_GET_IDENTITY
  if(dev->model!=NULL)
    return;
  {
    struct hd_driveid       hdi;
    memset(&hdi, 0, sizeof(hdi));
    if (ioctl (hd_h, HDIO_GET_IDENTITY, &hdi)==0)
    {
      char tmp[41];
      if(dev->model==NULL)
      {
	memcpy (tmp, hdi.model, 40);
	tmp[40] = '\0';
	dev->model=strip_dup(tmp);
      }
      if(dev->serial_no==NULL)
      {
	memcpy (tmp, hdi.serial_no, 20);
	tmp[20] = '\0';
	dev->serial_no=strip_dup(tmp);
      }
      if(dev->fw_rev==NULL)
      {
	memcpy (tmp, hdi.fw_rev, 8);
	tmp[8] = '\0';
	dev->fw_rev=strip_dup(tmp);
      }
    }
  }
#endif
#if defined(TARGET_LINUX) && defined(SCSI_IOCTL_GET_IDLUN) && defined(SCSI_IOCTL_SEND_COMMAND)
  if(dev->model!=NULL)
    return;
  {
    /* Uses direct queries via the deprecated ioctl SCSI_IOCTL_SEND_COMMAND */
    char *vendor=NULL;
    char *product=NULL;
    scsi_query_product_info (hd_h, &vendor, &product, &dev->fw_rev);
    if (vendor && product)
    {
      dev->model = (char*) MALLOC (8 + 16 + 2);
      sprintf (dev->model, "%.8s %.16s", vendor, product);
    }
    free(vendor);
    free(product);
  }
#endif
#ifdef TARGET_LINUX
  if(dev->model!=NULL)
    return;
  {
    /* Use modern /sys interface for SCSI device */
    char *vendor;
    char *product;
    vendor = read_device_sysfs_file (dev, "vendor");
    product = read_device_sysfs_file (dev, "model");
    if (vendor && product)
    {
      dev->model = (char*) MALLOC(8 + 16 + 2);
      sprintf (dev->model, "%.8s %.16s", vendor, product);
    }
    free(vendor);
    free(product);
  }
#endif
#if defined(__CYGWIN__) || defined(__MINGW32__)
  if(dev->model!=NULL)
    return;
  {
    HANDLE handle;
#if defined(__CYGWIN__)
    handle=(HANDLE)get_osfhandle(hd_h);
#else
    handle=(HANDLE)_get_osfhandle(hd_h);
#endif
    file_win32_disk_get_model(handle, dev, verbose);
  }
#endif
}

static uint64_t compute_device_size(const int hd_h, const char *device, const int verbose, const unsigned int sector_size)
{
#ifdef HAVE_PREAD
  /* This function can failed if there are bad sectors */
  uint64_t min_offset, max_offset;
  char *buffer=(char *)MALLOC(sector_size);
  min_offset=0;
  max_offset=sector_size;
  /* Search the maximum device size */
  while(pread(hd_h, buffer, sector_size, max_offset) == sector_size)
  {
    min_offset=max_offset;
    max_offset*=2;
  }
  /* Search the device size by dichotomy */
  while(min_offset<=max_offset)
  {
    uint64_t cur_offset;
    cur_offset=(min_offset+max_offset)/2/sector_size*sector_size;
    if(pread(hd_h, buffer, sector_size, cur_offset) == sector_size)
      min_offset=cur_offset+sector_size;
    else
    {
      if(cur_offset>=sector_size)
	max_offset=cur_offset-sector_size;
      else
	break;
    }
  }
  if(pread(hd_h, buffer, sector_size, min_offset) == sector_size)
    min_offset+=sector_size;
  free(buffer);
  if(verbose>1)
  {
    log_verbose("file_test_availability compute_device_size %s size %llu\n",
	device, (long long unsigned)min_offset);
  }
  return min_offset;
#else
  return 0;
#endif
}
#endif

static const char *file_description(disk_t *disk)
{
  const struct info_file_struct *data=(const struct info_file_struct *)disk->data;
  char buffer_disk_size[100];
  size_to_unit(disk->disk_size, buffer_disk_size);
  if(disk->geom.heads_per_cylinder == 1 && disk->geom.sectors_per_head == 1)
    snprintf(disk->description_txt, sizeof(disk->description_txt),
	"Disk %s - %s - %llu sectors%s",
	disk->device, buffer_disk_size,
	(long long unsigned)(disk->disk_size / disk->sector_size),
	((data->mode&O_RDWR)==O_RDWR?"":" (RO)"));
  else
    snprintf(disk->description_txt, sizeof(disk->description_txt),
	"Disk %s - %s - CHS %lu %u %u%s",
	disk->device, buffer_disk_size,
	disk->geom.cylinders, disk->geom.heads_per_cylinder, disk->geom.sectors_per_head,
	((data->mode&O_RDWR)==O_RDWR?"":" (RO)"));
  return disk->description_txt;
}

static const char *file_description_short(disk_t *disk_car)
{
  const struct info_file_struct *data=(const struct info_file_struct *)disk_car->data;
  char buffer_disk_size[100];
  size_to_unit(disk_car->disk_size, buffer_disk_size);
  if(disk_car->model==NULL)
    snprintf(disk_car->description_short_txt, sizeof(disk_car->description_txt),"Disk %s - %s%s",
      disk_car->device, buffer_disk_size,
      ((data->mode&O_RDWR)==O_RDWR?"":" (RO)"));
  else
    snprintf(disk_car->description_short_txt, sizeof(disk_car->description_txt),"Disk %s - %s%s - %s",
      disk_car->device, buffer_disk_size,
      ((data->mode&O_RDWR)==O_RDWR?"":" (RO)"),
      disk_car->model);
  return disk_car->description_short_txt;
}

static void file_clean(disk_t *disk)
{
  if(disk->data!=NULL)
  {
    struct info_file_struct *data=(struct info_file_struct *)disk->data;
    /*
#ifdef BLKRRPART
    if (ioctl(data->handle, BLKRRPART, NULL)) {
      log_error("%s BLKRRPART failed\n",disk->description(disk));
    } else {
      log_debug("%s BLKRRPART ok\n",disk->description(disk));
    }
#endif
    */
#ifdef HDCLONE
    if(data->handle_clone>0)
    {
      close(data->handle_clone);
      data->handle_clone=0;
    }
#endif
    close(data->handle);
    data->handle=0;
  }
  generic_clean(disk);
}

static int file_pread_aux(disk_t *disk, void *buf, const unsigned int count, const uint64_t offset)
{
  long int ret;
  int fd=((struct info_file_struct *)disk->data)->handle;
#if defined(__CYGWIN__)
  if(lseek(fd,offset,SEEK_SET) < 0)
  {
    log_error("file_pread(%d,%u,buffer,%lu(%u/%u/%u)) lseek err %s\n",
	fd, (unsigned)(count/disk->sector_size),
	(long unsigned int)(offset/disk->sector_size),
	offset2cylinder(disk,offset),
	offset2head(disk,offset),
	offset2sector(disk,offset),
	strerror(errno));
    return -1;
  }
  {
    /* November 28, 2004, CGR: cygwin read function is about 10 times slower
       because it reads 60k each time, so lets call ReadFile directly */
    DWORD dwByteRead;
    HANDLE handle=(HANDLE)get_osfhandle(fd);
    if(ReadFile(handle, buf,count,&dwByteRead,NULL)==0)
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
      log_error("file_pread(%d,%u,buffer,%lu(%u/%u/%u)) ReadFile %s\n",
	fd, (unsigned)(count/disk->sector_size),
	(long unsigned int)(offset/disk->sector_size),
	offset2cylinder(disk, offset),
	offset2head(disk, offset),
	offset2sector(disk, offset),
	(char*)lpMsgBuf);
      LocalFree(lpMsgBuf);
      return -1;
    }
    return dwByteRead;
  }
#elif defined(__MINGW32__)
  if(_lseeki64(fd,offset,SEEK_SET) < 0)
  {
    log_error("file_pread(%d,%u,buffer,%lu(%u/%u/%u)) seek err %s\n",
	fd, (unsigned)(count/disk->sector_size),
	(long unsigned int)(offset/disk->sector_size),
	offset2cylinder(disk, offset),
	offset2head(disk, offset),
	offset2sector(disk, offset),
	strerror(errno));
    return -1;
  }
  ret=read(fd, buf, count);
#else
#if defined(HAVE_PREAD)
  ret=pread(fd,buf,count,offset);
  if(ret<0 && errno == ENOSYS)
#endif
  {
    if(lseek(fd,offset,SEEK_SET)==(off_t)-1)
    {
      log_error("file_pread(%d,%u,buffer,%lu(%u/%u/%u)) lseek err %s\n",
	  fd, (unsigned)(count/disk->sector_size),
	  (long unsigned int)(offset/disk->sector_size),
          offset2cylinder(disk, offset),
	  offset2head(disk, offset),
	  offset2sector(disk, offset),
          strerror(errno));
      return -1;
    }
    ret=read(fd, buf, count);
  }
#endif
  if(ret!=count)
  {
    if(offset+count <= disk->disk_size && offset+count <= disk->disk_real_size)
    {
      log_error("file_pread(%d,%u,buffer,%lu(%u/%u/%u)) read err: ",
	  fd, (unsigned)(count/disk->sector_size),
	  (long unsigned)(offset/disk->sector_size),
          offset2cylinder(disk, offset),
	  offset2head(disk, offset),
	  offset2sector(disk, offset));
      if(ret<0)
        log_error("%s\n", strerror(errno));
      else if(ret==0)
        log_error("read after end of file\n");
      else
        log_error("Partial read\n");
    }
    if(ret<=0)
    {
      memset(buf, 0, count);
      return -1;
    }
    memset((char*)buf+ret,0,count-ret);
  }
#ifdef HDCLONE
  if(ret>0)
  {
    int handle_clone=((struct info_file_struct *)disk->data)->handle_clone;
    if(handle_clone>0)
    {
      pwrite(handle_clone, buf, ret, offset);
//      fdatasync(handle_clone);
    }
  }
#endif
  return ret;
}

static int file_pread(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset)
{
  return align_pread(&file_pread_aux, disk_car, buf, count, offset);
}

static int file_pwrite_aux(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset)
{
  int fd=((struct info_file_struct *)disk_car->data)->handle;
  long int ret;
#if defined(HAVE_PWRITE) && !defined(__CYGWIN__)
  ret=pwrite(fd,buf,count,offset);
  if(ret<0 && errno == ENOSYS)
#endif
  {
#ifdef __MINGW32__
    if(_lseeki64(fd,offset,SEEK_SET)==-1)
    {
      log_error("file_pwrite(%d,%u,buffer,%lu(%u/%u/%u)) seek err %s\n", fd,
          (unsigned)(count/disk_car->sector_size),
          (long unsigned)(offset/disk_car->sector_size),
          offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset),strerror(errno));
      return -1;
    }
#else
    if(lseek(fd,offset,SEEK_SET)==-1)
    {
      log_error("file_pwrite(%d,%u,buffer,%lu(%u/%u/%u)) seek err %s\n", fd,(unsigned)(count/disk_car->sector_size),(long unsigned)(offset/disk_car->sector_size),
          offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset),strerror(errno));
      return -1;
    }
#endif
    ret=write(fd, buf, count);
  }
  disk_car->write_used=1;
  if(ret!=count)
  {
    log_error("file_pwrite(%d,%u,buffer,%lu(%u/%u/%u)) write err %s\n", fd,(unsigned)(count/disk_car->sector_size),(long unsigned)(offset/disk_car->sector_size),
        offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset),(ret<0?strerror(errno):"File truncated"));
    return -1;
  }
  return ret;
}

static int file_pwrite(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset)
{
  return align_pwrite(&file_pread_aux, &file_pwrite_aux, disk_car, buf, count, offset);
}

static int file_nopwrite(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset)
{
  struct info_file_struct *data=(struct info_file_struct *)disk_car->data;
  log_warning("file_nopwrite(%d,%u,buffer,%lu(%u/%u/%u)) write refused\n", data->handle,
      (unsigned)(count/disk_car->sector_size),(long unsigned)(offset/disk_car->sector_size),
      offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset));
  return -1;
}

static int file_sync(disk_t *disk_car)
{
#ifdef HAVE_FSYNC
  struct info_file_struct *data=(struct info_file_struct *)disk_car->data;
  return fsync(data->handle);
#else
  errno=EINVAL;
  return -1;
#endif
}

static void autoset_geometry(disk_t *disk, const unsigned char *buffer, const int verbose)
{
  if(disk->arch->get_geometry_from_mbr!=NULL)
  {
    CHSgeometry_t geometry;
    geometry.cylinders=0;
    geometry.heads_per_cylinder=0;
    geometry.sectors_per_head=0;
    geometry.bytes_per_sector=0;
    disk->arch->get_geometry_from_mbr(buffer, verbose, &geometry);
    disk->autodetect=1;
    if(geometry.sectors_per_head > 0)
    {
      disk->geom.heads_per_cylinder=geometry.heads_per_cylinder;
      disk->geom.sectors_per_head=geometry.sectors_per_head;
      if(geometry.bytes_per_sector!=0)
      {
	disk->geom.bytes_per_sector=geometry.bytes_per_sector;
	disk->sector_size=geometry.bytes_per_sector;
      }
    }
    else
    {
      disk->geom.heads_per_cylinder=255;
      disk->geom.sectors_per_head=63;
    }
  }
  /* Round up because file is often truncated. */
  disk->geom.cylinders=(disk->disk_size / disk->sector_size +
      (uint64_t)disk->geom.sectors_per_head * disk->geom.heads_per_cylinder - 1) /
    disk->geom.sectors_per_head / disk->geom.heads_per_cylinder;
}

disk_t *file_test_availability(const char *device, const int verbose, int testdisk_mode)
{
  disk_t *disk_car=NULL;
  struct stat stat_rec;
  int device_is_a_file=0;
  struct info_file_struct *data;
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
	  hd_h = -1;
        }
      }
#endif
    }
  }
  if(hd_h<0 && try_readonly>0)
  {
    testdisk_mode&=~TESTDISK_O_RDWR;
    mode=O_RDONLY|O_EXCL|mode_basic;
    hd_h = open(device, mode);
    if(hd_h<0 && (errno==EBUSY || errno==EINVAL))
    {
      mode=O_RDONLY|mode_basic;
      hd_h = open(device, mode);
    }
  }
  if(hd_h<0)
  {
    if(verbose>1)
      log_error("file_test_availability %s: %s\n", device, strerror(errno));
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
	disk_car = hd_identify(verbose, dos_nr, testdisk_mode);
      if(disk_car!=NULL)
	return disk_car;
    }
#endif
    /* Handle 'testdisk disk.E*' or 'photorec "disk.E*"' case */
    if(strncmp(device,"/dev/",5)!=0)
    {
#if defined(HAVE_LIBEWF_H) && defined(HAVE_LIBEWF) && defined(HAVE_GLOB_H)
      return fewf_init(device, testdisk_mode);
#endif
    }
    return NULL;
  }
  disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
  disk_car->arch=&arch_none;
  init_disk(disk_car);
  disk_car->device=strdup(device);
  data=(struct info_file_struct *)MALLOC(sizeof(*data));
  data->handle=hd_h;
  data->mode=mode;
  disk_car->data=data;
  disk_car->description=file_description;
  disk_car->description_short=file_description_short;
  disk_car->pread=file_pread;
  disk_car->pwrite=((mode&O_RDWR)==O_RDWR?file_pwrite:file_nopwrite);
  disk_car->sync=file_sync;
  disk_car->access_mode=((mode&O_RDWR)==O_RDWR?TESTDISK_O_RDWR:TESTDISK_O_RDONLY);
#ifdef O_DIRECT
  if((mode&O_DIRECT)==O_DIRECT)
    disk_car->access_mode|=TESTDISK_O_DIRECT;
#endif
  disk_car->clean=file_clean;
  if(fstat(hd_h,&stat_rec)>=0)
  {
    if(S_ISREG(stat_rec.st_mode) && stat_rec.st_size > 0)
    {
      device_is_a_file=1;
    }
  }
#ifndef DJGPP
  if(device_is_a_file==0)
  {
    if(verbose>1)
      log_info("file_test_availability %s is a device\n", device);
    disk_car->sector_size=disk_get_sector_size(hd_h, device, verbose);
    disk_get_geometry(&disk_car->geom, hd_h, device, verbose);
    disk_car->disk_real_size=disk_get_size(hd_h, device, verbose, disk_car->sector_size);
#ifdef BLKFLSBUF
    /* Little trick from Linux fdisk */
    /* Blocks are visible in more than one way:
       e.g. as block on /dev/hda and as block on /dev/hda3
       By a bug in the Linux buffer cache, we will see the old
       contents of /dev/hda when the change was made to /dev/hda3.
       In order to avoid this, discard all blocks on /dev/hda. */
    (void)ioctl(hd_h, BLKFLSBUF);	/* ignore errors */
#endif
    disk_get_model(hd_h, disk_car, verbose);
    disk_get_hpa_dco(hd_h, disk_car);
  }
  else
#endif
  {
    unsigned char *buffer;
    const struct tdewf_file_header *ewf;
    const uint8_t evf_file_signature[8] = { 'E', 'V', 'F', 0x09, 0x0D, 0x0A, 0xFF, 0x00 };
    if(verbose>1)
      log_verbose("file_test_availability %s is a file\n", device);
    disk_car->sector_size=DEFAULT_SECTOR_SIZE;
    buffer=(unsigned char*)MALLOC(DEFAULT_SECTOR_SIZE);
    ewf=(const struct tdewf_file_header *)buffer;
    if(read(hd_h,buffer,DEFAULT_SECTOR_SIZE)<0)
    {
      memset(buffer,0,DEFAULT_SECTOR_SIZE);
    }
    if(memcmp(buffer,"DOSEMU",6)==0 && *(unsigned long*)(buffer+11)>0)
    {
      log_info("%s DOSEMU\n",device);
      disk_car->geom.cylinders=*(unsigned long*)(buffer+15);
      disk_car->geom.heads_per_cylinder=*(unsigned long*)(buffer+7);
      disk_car->geom.sectors_per_head=*(unsigned long*)(buffer+11);
      disk_car->disk_real_size=(uint64_t)disk_car->geom.cylinders * disk_car->geom.heads_per_cylinder * disk_car->geom.sectors_per_head * disk_car->sector_size;
      disk_car->offset=*(unsigned long*)(buffer+19);
    }
    else if(memcmp(buffer, evf_file_signature, 8)==0 && le16(ewf->fields_segment)==1)
    {
      free(buffer);
      free(data);
      free(disk_car->device);
      free(disk_car->model);
      free(disk_car);
      close(hd_h);
#if defined(HAVE_LIBEWF_H) && defined(HAVE_LIBEWF)
      log_info("EWF format detected.\n");
      return fewf_init(device, testdisk_mode);
#else
      log_info("EWF format detected but missing library.\n");
      return NULL;
#endif
    }
    else
    {
      disk_car->geom.cylinders=0;
      disk_car->geom.heads_per_cylinder=255;
      disk_car->geom.sectors_per_head=63;
#if 0
      if((uint64_t)stat_rec.st_size > disk_car->offset)
      {
	disk_car->disk_real_size=((uint64_t)stat_rec.st_size-disk_car->offset+disk_car->sector_size-1)/disk_car->sector_size*disk_car->sector_size;
      }
      else
#endif
      {
	off_t pos;
	pos=lseek(hd_h,0,SEEK_END);
	if(pos>0 && (uint64_t)pos > disk_car->offset)
	  disk_car->disk_real_size=(uint64_t)pos-disk_car->offset;
	else
	  disk_car->disk_real_size=0;
      }
      autoset_geometry(disk_car,buffer,verbose);
    }
    free(buffer);
  }
  update_disk_car_fields(disk_car);
#if defined(POSIX_FADV_SEQUENTIAL) && defined(HAVE_POSIX_FADVISE)
//  posix_fadvise(hd_h,0,0,POSIX_FADV_SEQUENTIAL);
#endif
  if(disk_car->disk_real_size!=0)
  {
#ifdef HDCLONE
    if(strncmp(device, "/dev/", 5)==0)
    {
      char *new_file=(char *)MALLOC(strlen(device)+5);
      sprintf(new_file, "%s.dd", device);
#ifdef O_LARGEFILE
      data->handle_clone=open(new_file, O_CREAT|O_LARGEFILE|O_RDWR,00600);
#else
      data->handle_clone=open(new_file, O_CREAT|O_RDWR,00600);
#endif
      free(new_file);
    }
#endif
    return disk_car;
  }
  if(disk_car->model==NULL)
    log_warning("Warning: can't get size for %s, sector size=%u\n",
	disk_car->description(disk_car), disk_car->sector_size);
  else
    log_warning("Warning: can't get size for %s, sector size=%u - %s\n",
	disk_car->description(disk_car), disk_car->sector_size, disk_car->model);
  free(data);
  free(disk_car->device);
  free(disk_car->model);
  free(disk_car);
  close(hd_h);
  return NULL;
}

void hd_update_geometry(disk_t *disk, const int verbose)
{
  if(disk->autodetect!=0)
  {
    unsigned char *buffer=(unsigned char *)MALLOC(disk->sector_size);
    if((unsigned)disk->pread(disk, buffer, disk->sector_size, 0) == disk->sector_size)
    {
      if(verbose>1)
      {
	log_trace("autoset_geometry\n");
      }
      autoset_geometry(disk,buffer,1);
    }
    free(buffer);
  }
#ifdef DJGPP
  if(disk->description==disk_description)
  {
    struct info_disk_struct*data=(struct info_disk_struct*)disk->data;
    data->geo_phys.cylinders=disk->geom.cylinders;
  }
#endif
}

void hd_update_all_geometry(const list_disk_t * list_disk, const int verbose)
{
  const list_disk_t *element_disk;
  if(verbose>1)
  {
    log_trace("hd_update_all_geometry\n");
  }
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    hd_update_geometry(element_disk->disk, verbose);
}

void init_disk(disk_t *disk)
{
  disk->autodetect=0;
  disk->disk_size=0;
  disk->user_max=0;
  disk->native_max=0;
  disk->dco=0;
  /* Note, some Raid reserve the first 1024 512-sectors */
  disk->offset=0;
  disk->rbuffer=NULL;
  disk->wbuffer=NULL;
  disk->rbuffer_size=0;
  disk->wbuffer_size=0;
  disk->model=NULL;
  disk->serial_no=NULL;
  disk->fw_rev=NULL;
  disk->write_used=0;
  disk->description_txt[0]='\0';
  disk->unit=UNIT_CHS;
}
