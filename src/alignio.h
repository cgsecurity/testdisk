/*

    File: alignio.h

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
static int align_pread(int (*fnct_pread)(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset),
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
    int res;
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
    res=fnct_pread(disk_car, disk_car->rbuffer, count_new, offset_new/disk_car->sector_size*disk_car->sector_size);
    memcpy(buf,(char*)disk_car->rbuffer+(offset_new%disk_car->sector_size),count);
    return (res < (signed)count ?  res : (signed)count );
  }
  return fnct_pread(disk_car, buf, count, offset_new);
}

static int align_pwrite(int (*fnct_pread)(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset),
    int (*fnct_pwrite)(disk_t *disk_car, const void *buf, const unsigned int count, const uint64_t offset),
    disk_t *disk_car, const void*buf, const unsigned int count, const uint64_t offset)
{
  const uint64_t offset_new=offset+disk_car->offset;
  const unsigned int count_new=((offset_new%disk_car->sector_size)+count+disk_car->sector_size-1)/disk_car->sector_size*disk_car->sector_size;
  if(count!=count_new ||
      ((disk_car->access_mode&TESTDISK_O_DIRECT)!=0 &&
       (((size_t)(buf) & (disk_car->sector_size-1))!=0))
    )
  {
    int tmp;
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
    if(fnct_pread(disk_car, disk_car->wbuffer, count_new, offset_new/disk_car->sector_size*disk_car->sector_size)<0)
    {
      log_error("read failed but try to write anyway");
      memset(disk_car->wbuffer,0, disk_car->wbuffer_size);
    }
    memcpy((char*)disk_car->wbuffer+(offset_new%disk_car->sector_size),buf,count);
    tmp=fnct_pwrite(disk_car, disk_car->wbuffer, count_new, offset_new/disk_car->sector_size*disk_car->sector_size);
    return (tmp < (signed)count ? tmp : (signed)count);
  }
  return fnct_pwrite(disk_car, buf, count, offset_new);
}

