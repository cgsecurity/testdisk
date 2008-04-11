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
static uint64_t compute_device_size(const int hd_h, const char *device, const int verbose, const unsigned int sector_size);
static void disk_get_model(const int hd_h, disk_t *disk_car, const int verbose);
#endif

int generic_clean(disk_t *disk_car)
{
  free(disk_car->data);
  disk_car->data=NULL;
  free(disk_car->rbuffer);
  free(disk_car->wbuffer);
  disk_car->rbuffer=NULL;
  disk_car->wbuffer=NULL;
  return 0;
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
      if(disk_car->clean!=NULL)
        disk_car->clean(disk_car);
      free(disk_car->device);
      free(disk_car->model);
      free(disk_car);
      return list_disk;
    }
    return insert_new_disk(list_disk,disk_car);
  }
}
#endif

#ifdef HAVE_GLOB_H
static list_disk_t *hd_glob_parse(const char *device_pattern, list_disk_t *list_disk, const int verbose, const arch_fnct_t *arch, const int testdisk_mode)
{
  glob_t globbuf;
  globbuf.gl_offs = 0;
  glob(device_pattern, GLOB_DOOFFS, NULL, &globbuf);
  if(globbuf.gl_pathc>0)
  {
    unsigned int i;
    for (i=0; i<globbuf.gl_pathc; i++)
    {
      list_disk=insert_new_disk(list_disk,file_test_availability(globbuf.gl_pathv[i], verbose,arch,testdisk_mode));
    }
  }
  globfree(&globbuf);
  return list_disk;
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
    char device_hd[]="\\\\.\\PhysicalDrive00";
    char device_cdrom[]="\\\\.\\C:";
#if defined(__CYGWIN__)
    char device_scsi[]="/dev/sda";
    /* Disk */
    for(i=0;i<16;i++)
    {
      device_scsi[strlen(device_scsi)-1]='a'+i;
      list_disk=insert_new_disk(list_disk,file_test_availability(device_scsi,verbose,arch,testdisk_mode));
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
#ifdef HAVE_GLOB_H
    list_disk=hd_glob_parse("/dev/mapper/*", list_disk, verbose, arch, testdisk_mode);
    list_disk=hd_glob_parse("/dev/md?", list_disk, verbose, arch, testdisk_mode);
    list_disk=hd_glob_parse("/dev/sr?", list_disk, verbose, arch, testdisk_mode);
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
      if(sector_size!=0)
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

static void disk_get_geometry(CHS_t *CHS, const int hd_h, const char *device, const int verbose)
{
  if(verbose>1)
    log_verbose("disk_get_geometry for %s\n", device);
#ifdef HDIO_GETGEO_BIG
  if(CHS->sector==0)
  {
    struct hd_big_geometry geometry_big;
    if (ioctl(hd_h, HDIO_GETGEO_BIG, &geometry_big)>=0)
    { /* I can get the geometry */
      if(verbose>1)
      {
        log_verbose("disk_get_geometry HDIO_GETGEO_BIG %s Ok (%u,%u,%u)\n",device,geometry_big.cylinders,geometry_big.heads,geometry_big.sectors);
      }
      CHS->cylinder= geometry_big.cylinders-1;
      CHS->head=geometry_big.heads-1;
      CHS->sector= geometry_big.sectors;
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
  if(CHS->sector==0)
  {
    struct hd_geometry geometry;
    if(ioctl(hd_h, HDIO_GETGEO, &geometry)>=0)
    { /* I can get the geometry */
      if(verbose>1)
      {
	log_verbose("disk_get_geometry HDIO_GETGEO %s Ok (%u,%u,%u)\n",device,geometry.cylinders,geometry.heads,geometry.sectors);
      }
      CHS->cylinder= geometry.cylinders-1;
      CHS->head=geometry.heads-1;
      CHS->sector= geometry.sectors;
    }
  }
#endif
#ifdef DKIOCGGEOM
  if(CHS->sector==0)
  {
    struct dk_geom dkgeom;
    if (ioctl (hd_h, DKIOCGGEOM, &dkgeom)>=0) {
      CHS->cylinder= dkgeom.dkg_ncyl-1;
      CHS->head=dkgeom.dkg_nhead-1;
      CHS->sector=dkgeom.dkg_nsect;
      if(verbose>1)
      {
	log_verbose("disk_get_geometry DKIOCGGEOM %s Ok\n",device);
      }
    }
  }
#endif
#ifdef DIOCGDINFO
  if(CHS->sector==0)
  {
    struct disklabel geometry;
    if (ioctl(hd_h, DIOCGDINFO, &geometry)==0)
    { /* I can get the geometry */
      if(verbose>1)
      {
	log_verbose("disk_get_geometry DIOCGDINFO %s Ok\n",device);
      }
      CHS->cylinder=geometry.d_ncylinders-1;
      CHS->head=geometry.d_ntracks-1;
      CHS->sector=geometry.d_nsectors;
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
  if(CHS->sector==0)
  {
    int error;
    unsigned int u,sectors,heads,cyls;
    off_t o;
    error = ioctl(hd_h, DIOCGFWSECTORS, &u);
    if(error==0 && u>0)
    {
      sectors=u;
      if(verbose>1)
      {
	log_verbose("disk_get_geometry DIOCGFWSECTORS %s Ok\n",device);
      }
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
	log_error("disk_get_geometry DIOCGFWHEADS %s failed %s\n", device, strerror(errno));
      }
    }
    error = ioctl(hd_h, DIOCGMEDIASIZE, &o);
    if(error==0)
    {
      cyls = o / ((off_t)sector_size * heads * sectors);
      CHS->cylinder=cyls-1;
      CHS->head=heads-1;
      CHS->sector=sectors;
    }
    else
    {
      if(verbose>1)
      {
	log_error("disk_get_geometry DIOCGMEDIASIZE %s failed %s\n", device, strerror(errno));
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
    return disk_get_geometry_win32(CHS, handle, device, verbose);
  }
#endif
  if(CHS->sector!=0)
    return ;
  CHS->cylinder=0;
  CHS->head=0;
  CHS->sector=1;
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
  /* Handle Mac */
  return compute_device_size(hd_h, device, verbose, sector_size);
}
#endif

void update_disk_car_fields(disk_t *disk_car)
{
  if(disk_car->disk_real_size==0)
  {
    if(disk_car->CHS.cylinder>0)
    {
      log_warning("Fix disk size using CHS\n");
      disk_car->disk_real_size=(uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size;
    }
  }
  else
  {
    unsigned int cylinder_num;
    cylinder_num=disk_car->disk_real_size / ((uint64_t)disk_car->CHS.head+1) / (uint64_t)disk_car->CHS.sector/(uint64_t)disk_car->sector_size;
    if(cylinder_num>0 && disk_car->CHS.cylinder+1!= cylinder_num)
    {
      log_debug("Fix cylinder count for %s: number of cylinders %u !=  %u (calculated)\n",
	  disk_car->device, disk_car->CHS.cylinder+1, cylinder_num);
      disk_car->CHS.cylinder= cylinder_num-1;
    }
  }
  disk_car->disk_size=disk_car->disk_real_size;
  /*
  disk_car->disk_size=td_max(disk_car->disk_real_size,
      (uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size);
  */
}

#ifdef TARGET_LINUX
static char* strip_name(char* str)
{
  int     i;
  int     end = 0;

  for (i = 0; str[i] != 0; i++) {
    if (!isspace (str[i])
	|| (isspace (str[i]) && !isspace (str[i+1]) && str[i+1])) {
      str [end] = str[i];
      end++;
    }
  }
  str[end] = 0;
  return strdup (str);
}

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
                return NULL;

        fclose (f);
        return strip_name (buf);
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
#endif

#if defined(TARGET_LINUX) && defined(SCSI_IOCTL_GET_IDLUN) && defined(SCSI_IOCTL_SEND_COMMAND)
static int scsi_query_product_info (const int hd_h, char **vendor, char **product)
{
  /* The following are defined by the SCSI-2 specification. */
  typedef struct _scsi_inquiry_cmd
  {
    uint8_t op;
    uint8_t lun;          /* bits 5-7 denote the LUN */
    uint8_t page_code;
    uint8_t reserved;
    uint8_t alloc_length;
    uint8_t control;
  } __attribute__((packed)) scsi_inquiry_cmd_t;

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

  struct scsi_arg
  {
    unsigned int inlen;
    unsigned int outlen;

    union arg_data
    {
      scsi_inquiry_data_t out;
      scsi_inquiry_cmd_t  in;
    } data;
  } arg;

  struct scsi_idlun
  {
    uint32_t dev_id;
    uint32_t host_unique_id;
  } idlun;

  char    buf[32];

  *vendor = NULL;
  *product = NULL;

  if (ioctl (hd_h, SCSI_IOCTL_GET_IDLUN, &idlun) < 0)
    return -1;


  memset (&arg, 0x00, sizeof(struct scsi_arg));
  arg.inlen  = 0;
  arg.outlen = sizeof(scsi_inquiry_data_t);
  arg.data.in.op  = INQUIRY;
  arg.data.in.lun = idlun.host_unique_id << 5;
  arg.data.in.alloc_length = sizeof(scsi_inquiry_data_t);
  arg.data.in.page_code = 0;
  arg.data.in.reserved = 0;
  arg.data.in.control = 0;

  if (ioctl (hd_h, SCSI_IOCTL_SEND_COMMAND, &arg) < 0)
    return -1;

  memcpy (buf, arg.data.out.vendor_id, 8);
  buf[8] = '\0';
  *vendor = strip_name (buf);

  memcpy (buf, arg.data.out.product_id, 16);
  buf[16] = '\0';
  *product = strip_name (buf);

  return 0;
}
#endif

#ifndef DJGPP
static void disk_get_model(const int hd_h, disk_t *dev, const int verbose)
{
#ifdef TARGET_LINUX
  if(dev->model==NULL)
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
#ifdef HDIO_GET_IDENTITY
  if(dev->model==NULL)
  {
    struct hd_driveid       hdi;
    if (ioctl (hd_h, HDIO_GET_IDENTITY, &hdi)==0)
    {
      char hdi_buf[41];
      memcpy (hdi_buf, hdi.model, 40);
      hdi_buf[40] = '\0';
      if(dev!=NULL)
	dev->model=strdup(hdi_buf);
    }
  }
#endif
#if defined(TARGET_LINUX) && defined(SCSI_IOCTL_GET_IDLUN) && defined(SCSI_IOCTL_SEND_COMMAND)
  if(dev->model==NULL)
  {
    /* Uses direct queries via the deprecated ioctl SCSI_IOCTL_SEND_COMMAND */
    char *vendor=NULL;
    char *product=NULL;
    scsi_query_product_info (hd_h, &vendor, &product);
    if (vendor && product)
    {
      dev->model = (char*) MALLOC (8 + 16 + 2);
      sprintf (dev->model, "%.8s %.16s", vendor, product);
    }
    free(vendor);
    free(product);
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
    file_win32_disk_get_model(handle, dev, verbose);
  }
#endif
}

static uint64_t compute_device_size(const int hd_h, const char *device, const int verbose, const unsigned int sector_size)
{
#ifdef HAVE_PREAD
  /* This function can failed if there are bad sectors */
  uint64_t min_offset, max_offset;
  char *buffer=MALLOC(sector_size);
  min_offset=0;
  max_offset=sector_size;
  /* Search the maximum device size */
  while(pread(hd_h, buffer, sector_size, max_offset)==0)
  {
    min_offset=max_offset;
    max_offset*=2;
  }
  /* Search the device size by dichotomy */
  while(min_offset<=max_offset)
  {
    uint64_t cur_offset;
    cur_offset=(min_offset+max_offset)/2/sector_size*sector_size;
    if(pread(hd_h, buffer, sector_size, cur_offset)==0)
      min_offset=cur_offset+sector_size;
    else
    {
      if(cur_offset>=sector_size)
	max_offset=cur_offset-sector_size;
      else
	break;
    }
  }
  if(pread(hd_h, buffer, sector_size, min_offset)==0)
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

static const char *file_description(disk_t *disk_car)
{
  const struct info_file_struct *data=disk_car->data;
  char buffer_disk_size[100];
  snprintf(disk_car->description_txt, sizeof(disk_car->description_txt),"Disk %s - %s - CHS %u %u %u%s",
      disk_car->device, size_to_unit(disk_car->disk_size,buffer_disk_size),
      disk_car->CHS.cylinder+1, disk_car->CHS.head+1, disk_car->CHS.sector,
      ((data->mode&O_RDWR)==O_RDWR?"":" (RO)"));
  return disk_car->description_txt;
}

static const char *file_description_short(disk_t *disk_car)
{
  const struct info_file_struct *data=disk_car->data;
  char buffer_disk_size[100];
  if(disk_car->model==NULL)
    snprintf(disk_car->description_short_txt, sizeof(disk_car->description_txt),"Disk %s - %s%s",
      disk_car->device, size_to_unit(disk_car->disk_size,buffer_disk_size),
      ((data->mode&O_RDWR)==O_RDWR?"":" (RO)"));
  else
    snprintf(disk_car->description_short_txt, sizeof(disk_car->description_txt),"Disk %s - %s%s - %s",
      disk_car->device, size_to_unit(disk_car->disk_size,buffer_disk_size),
      ((data->mode&O_RDWR)==O_RDWR?"":" (RO)"),
      disk_car->model);
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
#ifdef HAVE_FSYNC
  return fsync(data->handle);
#else
  errno=EINVAL;
  return -1;
#endif
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
  disk_car->CHS.cylinder=(disk_car->disk_size / disk_car->sector_size +
      (uint64_t)disk_car->CHS.sector*(disk_car->CHS.head+1) - 1) /
    disk_car->CHS.sector / (disk_car->CHS.head+1);
  if(disk_car->CHS.cylinder > 0)
    disk_car->CHS.cylinder--;
}

disk_t *file_test_availability(const char *device, const int verbose, const arch_fnct_t *arch, int testdisk_mode)
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
	  hd_h=-1;
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
	disk_car = hd_identify(verbose, dos_nr, arch, testdisk_mode);
    }
#endif
    return disk_car;
  }
  disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
  disk_car->arch=arch;
  disk_car->autodetect=0;
  disk_car->disk_size=0;
  /* Note, some Raid reserves the first 1024 512-sectors */
  disk_car->offset=0;
  data=MALLOC(sizeof(*data));
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
  disk_car->model=NULL;
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
  disk_car->unit=UNIT_CHS;
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
    disk_get_geometry(&disk_car->CHS, hd_h, device, verbose);
    disk_car->disk_real_size=disk_get_size(hd_h, device, verbose, disk_car->sector_size);
#ifdef BLKFLSBUF
    /* Little trick from Linux fdisk */
    /* Blocks are visible in more than one way:
       e.g. as block on /dev/hda and as block on /dev/hda3
       By a bug in the Linux buffer cache, we will see the old
       contents of /dev/hda when the change was made to /dev/hda3.
       In order to avoid this, discard all blocks on /dev/hda. */
    ioctl(hd_h, BLKFLSBUF);	/* ignore errors */
#endif
    disk_get_model(hd_h, disk_car, verbose);
  }
  else
#endif
  {
    unsigned char *buffer;
    const uint8_t evf_file_signature[8] = { 'E', 'V', 'F', 0x09, 0x0D, 0x0A, 0xFF, 0x00 };
    if(verbose>1)
      log_verbose("file_test_availability %s is a file\n", device);
    disk_car->sector_size=DEFAULT_SECTOR_SIZE;
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
      disk_car->disk_real_size=(uint64_t)(disk_car->CHS.cylinder+1)*(disk_car->CHS.head+1)*disk_car->CHS.sector*disk_car->sector_size;
      disk_car->offset=*(unsigned long*)(buffer+19);
    }
    else if(memcmp(buffer, evf_file_signature, 8)==0)
    {
      free(buffer);
      close(hd_h);
      free(disk_car);
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
      if((uint64_t)stat_rec.st_size > disk_car->offset)
      {
	disk_car->disk_real_size=((uint64_t)stat_rec.st_size-disk_car->offset+disk_car->sector_size-1)/disk_car->sector_size*disk_car->sector_size;
      }
      else
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
  if(disk_car->disk_real_size!=0)
    return disk_car;
  log_warning("Warning: can't get size for %s\n", device);
  free(data);
  free(disk_car->device);
  free(disk_car->model);
  free(disk_car);
  close(hd_h);
  return NULL;
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

