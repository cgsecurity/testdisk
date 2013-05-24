/*

    File: win32.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include <stdio.h>
#include <errno.h>
#if defined(__CYGWIN__) || defined(__MINGW32__)
#include "types.h"
#include "common.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>     /* free */
#endif
#ifdef HAVE_WINDEF_H
#include <windef.h>
#endif
#ifdef HAVE_WINBASE_H
#include <stdarg.h>
#include <winbase.h>
#endif
#include <ctype.h>	/* isspace */
#ifdef HAVE_WINIOCTL_H
#include <winioctl.h>
#endif
#if defined(__CYGWIN__)
#include <io.h>
#include <windows.h>
#include <winnt.h>
#endif
#include "fnctdsk.h"
#include "log.h"
#include "win32.h"
#include "hdwin32.h"
#include "hdaccess.h"
#include "alignio.h"

extern const arch_fnct_t arch_none;

static unsigned int file_win32_compute_sector_size(HANDLE handle);
static uint64_t filewin32_getfilesize(HANDLE handle, const char *device);
static const char *file_win32_description(disk_t *disk_car);
static const char *file_win32_description_short(disk_t *disk_car);
static void file_win32_clean(disk_t *disk_car);
static int file_win32_pread(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset);
static int file_win32_pwrite(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset);
static int file_win32_nopwrite(disk_t *disk_car, const void *buf, const unsigned int count,  const uint64_t offset);
static int file_win32_sync(disk_t *disk_car);
static uint64_t filewin32_setfilepointer(HANDLE handle, const char *device);

unsigned int disk_get_sector_size_win32(HANDLE handle, const char *device, const int verbose)
{
  unsigned int sector_size;
  DWORD gotbytes;
  DISK_GEOMETRY geometry;
  DISK_GEOMETRY_EX geometry_ex;
  if (DeviceIoControl( handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
	&geometry_ex, sizeof(geometry_ex), &gotbytes, NULL))
  {
    if(geometry_ex.Geometry.BytesPerSector <= (1<<24))
      return geometry_ex.Geometry.BytesPerSector;
  }
  if (DeviceIoControl( handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
	&geometry, sizeof(geometry), &gotbytes, NULL))
  {
    if(geometry.BytesPerSector <= (1<<24))
      return geometry.BytesPerSector;
  }
  sector_size=file_win32_compute_sector_size(handle);
  if(sector_size==0)
    sector_size=DEFAULT_SECTOR_SIZE;
  return sector_size;
}

uint64_t disk_get_size_win32(HANDLE handle, const char *device, const int verbose)
{
  uint64_t disk_size=0;
  {
    GET_LENGTH_INFORMATION buf;
    DWORD i;
    if (DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &buf, sizeof(buf), &i, NULL))
    {
      disk_size=(uint64_t)buf.Length.QuadPart;
      log_info("disk_get_size_win32 IOCTL_DISK_GET_LENGTH_INFO(%s)=%llu\n",
	  device, (long long unsigned)disk_size);
      return disk_size;
    }
  }
  disk_size=filewin32_getfilesize(handle, device);
  if(disk_size!=0)
    return disk_size;
  if(device[0]!='\0' && device[1]!='\0' && device[2]!='\0' && device[3]!='\0' && device[4]!='\0')
  {
    uint64_t i64FreeBytesToCaller, i64TotalBytes, i64FreeBytes;
    if(GetDiskFreeSpaceEx (&device[4],
	  (PULARGE_INTEGER)&i64FreeBytesToCaller,
	  (PULARGE_INTEGER)&i64TotalBytes,
	  (PULARGE_INTEGER)&i64FreeBytes)!=0)
    {
      if(verbose>1)
	log_info("disk_get_size_win32 GetDiskFreeSpaceEx %s: %llu\n",
	    device, (long long unsigned)i64TotalBytes);
      return i64TotalBytes;
    }
  }
  {
    DWORD gotbytes;
    DISK_GEOMETRY_EX geometry_ex;
    if (DeviceIoControl( handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
	  &geometry_ex, sizeof(geometry_ex), &gotbytes, NULL))
    {
      disk_size=(uint64_t)geometry_ex.DiskSize.QuadPart;
      if(verbose>1)
	log_info("disk_get_size_win32 IOCTL_DISK_GET_DRIVE_GEOMETRY_EX %s: %llu\n",
	    device, (long long unsigned)disk_size);
    }
  }
  if(disk_size!=0)
    return disk_size;
  return filewin32_setfilepointer(handle, device);
}

void disk_get_geometry_win32(CHSgeometry_t *geom, HANDLE handle, const char *device, const int verbose)
{
  if(geom->sectors_per_head!=0)
    return;
  {
    DWORD gotbytes;
    DISK_GEOMETRY_EX geometry_ex;
    if (DeviceIoControl( handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
	  &geometry_ex, sizeof(geometry_ex), &gotbytes, NULL))
    {
      geom->cylinders= geometry_ex.Geometry.Cylinders.QuadPart;
      geom->heads_per_cylinder=geometry_ex.Geometry.TracksPerCylinder;
      geom->sectors_per_head= geometry_ex.Geometry.SectorsPerTrack;
      if(geom->sectors_per_head!=0)
      {
	if(verbose>1)
	  log_verbose("IOCTL_DISK_GET_DRIVE_GEOMETRY_EX %s Ok (%lu, %u, %u)\n",
	      device, geom->cylinders, geom->heads_per_cylinder, geom->sectors_per_head);
	return ;
      }
    }
  }
  {
    DWORD gotbytes;
    DISK_GEOMETRY geometry;
    if (DeviceIoControl( handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
	  &geometry, sizeof(geometry), &gotbytes, NULL))
    {
      geom->cylinders= geometry.Cylinders.QuadPart;
      geom->heads_per_cylinder=geometry.TracksPerCylinder;
      geom->sectors_per_head= geometry.SectorsPerTrack;
      if(geom->sectors_per_head!=0)
      {
	if(verbose>1)
	  log_verbose("IOCTL_DISK_GET_DRIVE_GEOMETRY %s Ok (%lu, %u, %u)\n",
	      device, geom->cylinders, geom->heads_per_cylinder, geom->sectors_per_head);
	return ;
      }
    }
  }
  geom->cylinders=0;
  geom->heads_per_cylinder=1;
  geom->sectors_per_head=1;
}
// Try to handle cdrom

struct info_file_win32_struct
{
  HANDLE handle;
  char file_name[DISKNAME_MAX];
  int mode;
};

static uint64_t filewin32_getfilesize(HANDLE handle, const char *device)
{
  uint64_t disk_size;
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
  disk_size=lpFileSizeLow+((uint64_t)lpFileSizeHigh>>32);
  log_verbose("filewin32_getfilesize(%s)=%llu\n",
      device, (long long unsigned)disk_size );
  return disk_size;
}

static uint64_t filewin32_setfilepointer(HANDLE handle, const char *device)
{
  uint64_t disk_size;
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
  disk_size=li.LowPart+((uint64_t)li.HighPart>>32);
  log_verbose("filewin32_setfilepointer(%s)=%llu\n",
      device, (long long unsigned)disk_size );
  return disk_size;
}

disk_t *file_test_availability_win32(const char *device, const int verbose, int testdisk_mode)
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
  if(handle==INVALID_HANDLE_VALUE)
    return NULL;
  {
    struct info_file_win32_struct *data;
    disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
    init_disk(disk_car);
    disk_car->arch=&arch_none;
    disk_car->device=strdup(device);
    data=(struct info_file_win32_struct *)MALLOC(sizeof(*data));
    data->handle=handle;
    data->mode=mode;
    disk_car->data=data;
    disk_car->description=file_win32_description;
    disk_car->description_short=file_win32_description_short;
    disk_car->pread=file_win32_pread;
    disk_car->pwrite=((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?file_win32_pwrite:file_win32_nopwrite);
    disk_car->sync=file_win32_sync;
    disk_car->access_mode=testdisk_mode;
    disk_car->clean=file_win32_clean;
    disk_car->sector_size=disk_get_sector_size_win32(handle, device, verbose);
    disk_get_geometry_win32(&disk_car->geom, handle, device, verbose);
    disk_car->disk_real_size=disk_get_size_win32(handle, device, verbose);
    file_win32_disk_get_model(handle, disk_car, verbose);
    update_disk_car_fields(disk_car);
    if(disk_car->disk_real_size!=0)
      return disk_car;
    log_warning("Warning: can't get size for %s\n",device);
    file_win32_clean(disk_car);
  }
  return NULL;
}

static const char *file_win32_description(disk_t *disk_car)
{
  struct info_file_win32_struct *data=(struct info_file_win32_struct *)disk_car->data;
  char buffer_disk_size[100];
  size_to_unit(disk_car->disk_size, buffer_disk_size);
  if(disk_car->device[0]=='\\' && disk_car->device[1]=='\\' && disk_car->device[2]=='.' && disk_car->device[3]=='\\' && disk_car->device[5]==':')
    snprintf(disk_car->description_txt, sizeof(disk_car->description_txt),"Drive %c: - %s - CHS %lu %u %u%s",
	disk_car->device[4], buffer_disk_size,
	disk_car->geom.cylinders, disk_car->geom.heads_per_cylinder, disk_car->geom.sectors_per_head,
	((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?"":" (RO)"));
  else
    snprintf(disk_car->description_txt, sizeof(disk_car->description_txt),"Disk %s - %s - CHS %lu %u %u%s",
	disk_car->device, buffer_disk_size,
	disk_car->geom.cylinders, disk_car->geom.heads_per_cylinder, disk_car->geom.sectors_per_head,
	((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?"":" (RO)"));
  return disk_car->description_txt;
}

static const char *file_win32_description_short(disk_t *disk_car)
{
  struct info_file_win32_struct *data=(struct info_file_win32_struct *)disk_car->data;
  char buffer_disk_size[100];
  size_to_unit(disk_car->disk_size, buffer_disk_size);
  if(disk_car->device[0]=='\\' && disk_car->device[1]=='\\' && disk_car->device[2]=='.' && disk_car->device[3]=='\\' && disk_car->device[5]==':')
  {
    if(disk_car->model==NULL)
      snprintf(disk_car->description_short_txt,
	  sizeof(disk_car->description_txt), "Drive %c: - %s%s",
	  disk_car->device[4], buffer_disk_size,
	  ((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?"":" (RO)"));
    else
      snprintf(disk_car->description_short_txt,
	  sizeof(disk_car->description_txt), "Drive %c: - %s%s - %s",
	  disk_car->device[4], buffer_disk_size,
	  ((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?"":" (RO)"),
	  disk_car->model);
  }
  else
  {
    if(disk_car->model==NULL)
      snprintf(disk_car->description_short_txt,
	sizeof(disk_car->description_txt), "Disk %s - %s%s",
	disk_car->device, buffer_disk_size,
	((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?"":" (RO)"));
    else
      snprintf(disk_car->description_short_txt,
	sizeof(disk_car->description_txt), "Disk %s - %s%s - %s",
	disk_car->device, buffer_disk_size,
	((data->mode&FILE_WRITE_DATA)==FILE_WRITE_DATA?"":" (RO)"),
	disk_car->model);
  }
  return disk_car->description_short_txt;
}

static void file_win32_clean(disk_t *disk)
{
  if(disk->data!=NULL)
  {
    struct info_file_win32_struct *data=(struct info_file_win32_struct *)disk->data;
    CloseHandle(data->handle);
  }
  generic_clean(disk);
}

static unsigned int file_win32_compute_sector_size(HANDLE handle)
{
  char *buffer=(char *)MALLOC(4096);
  unsigned int sector_size;
  for(sector_size=512;sector_size<=4096;sector_size*=2)
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
  return 0;
}

static int file_win32_pread_aux(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset)
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
    log_error("file_win32_pread(%d,%u,buffer,%lu(%u/%u/%u)) seek err %s\n", (int)fd,
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
  if(ret!=(signed)count)
  {
    if(ret>0 || offset<disk_car->disk_size)
    {
      log_error("file_win32_pread(%d,%u,buffer,%lu(%u/%u/%u)) read err: ", (int)fd,
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
    if(ret>0)
      memset((char*)buf+ret,0,count-ret);
  }
  return ret;
}

static int file_win32_pread(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset)
{
  return align_pread(&file_win32_pread_aux, disk_car, buf, count, offset);
}

static int file_win32_pwrite_aux(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset)
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
    log_error("file_win32_pwrite(%d,%u,buffer,%lu(%u/%u/%u)) seek err %s\n", (int)fd,
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
  if(ret!=(signed)count)
  {
    log_error("file_win32_pwrite(%u,%u,buffer,%lu(%u/%u/%u)) write err\n", (int)fd,
        (unsigned)(count/disk_car->sector_size), (long unsigned)(offset/disk_car->sector_size),
        offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset));
  }
  return ret;
}

static int file_win32_pwrite(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset)
{
  return align_pwrite(&file_win32_pread_aux, &file_win32_pwrite_aux, disk_car, buf, count, offset);
}

static int file_win32_nopwrite(disk_t *disk_car, const void *buf, const unsigned int count,  const uint64_t offset)
{
  const struct info_file_win32_struct *data=(const struct info_file_win32_struct *)disk_car->data;
  log_warning("file_win32_nopwrite(%d,%u,buffer,%lu(%u/%u/%u)) write refused\n", (unsigned int)data->handle,
      (unsigned)(count/disk_car->sector_size),(long unsigned)(offset/disk_car->sector_size),
      offset2cylinder(disk_car,offset),offset2head(disk_car,offset),offset2sector(disk_car,offset));
  return -1;
}

static int file_win32_sync(disk_t *disk_car)
{
  const struct info_file_win32_struct *data=(const struct info_file_win32_struct *)disk_car->data;
  if(FlushFileBuffers(data->handle)==0)
  {
    errno=EINVAL;
    return -1;
  }
  errno=0;
  return 0;
}
#endif
