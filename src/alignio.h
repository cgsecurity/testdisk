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

/*@
  @ requires \valid_function(fnct_pread);
  @ requires \valid(disk_car);
  @ requires disk_car->sector_size > 0;
  @ requires disk_car->offset < 0x8000000000000000;
  @ requires 0 < count < 0x8000000000000000;
  @ requires offset < 0x8000000000000000;
  @ requires \valid((char *)buf + (0 .. count -1));
  @ requires disk_car->rbuffer == \null || (\freeable(disk_car->rbuffer) && disk_car->rbuffer_size > 0);
  @ ensures  disk_car->rbuffer == \null || (\freeable(disk_car->rbuffer) && disk_car->rbuffer_size > 0);
  @*/
static int align_pread(int (*fnct_pread)(disk_t *disk_car, void *buf, const unsigned int count, const uint64_t offset),
           disk_t *disk_car, void*buf, const unsigned int count, const uint64_t offset)
{
  const uint64_t offset_new=offset+disk_car->offset;
  const unsigned int count_new=((offset_new%disk_car->sector_size)+count+disk_car->sector_size-1)/disk_car->sector_size*disk_car->sector_size;
  /*@ assert count_new >= count; */
  /*@ assert count_new >= disk_car->sector_size; */
  /*@ assert count_new > 0; */
  if(count!=count_new ||
      ((disk_car->access_mode&TESTDISK_O_DIRECT)!=0 &&
       (((size_t)(buf) & (disk_car->sector_size-1))!=0) &&
       (buf!=disk_car->rbuffer || disk_car->rbuffer_size<count_new))
    )
  {
    int res;
    if(disk_car->rbuffer_size < count_new)
    {
      free(disk_car->rbuffer);
      disk_car->rbuffer=NULL;
    }
    if(disk_car->rbuffer==NULL)
    {
      disk_car->rbuffer_size=128*512;
      /*@ loop assigns disk_car->rbuffer_size; */
      while(disk_car->rbuffer_size < count_new)
      {
	disk_car->rbuffer_size*=2;
      }
      /*@ assert disk_car->rbuffer_size >= count_new; */
      disk_car->rbuffer=(char*)MALLOC(disk_car->rbuffer_size);
    }
    /*@ assert \freeable(disk_car->rbuffer); */
    res=fnct_pread(disk_car, disk_car->rbuffer, count_new, offset_new/disk_car->sector_size*disk_car->sector_size);
    memcpy(buf,(char*)disk_car->rbuffer+(offset_new%disk_car->sector_size),count);
    /*@ assert \freeable(disk_car->rbuffer) && disk_car->rbuffer_size > 0; */
    return (res < (signed)count ?  res : (signed)count );
  }
  return fnct_pread(disk_car, buf, count, offset_new);
}

/*@
  @ requires \valid_function(fnct_pread);
  @ requires \valid_function(fnct_pwrite);
  @ requires \valid(disk_car);
  @ requires disk_car->sector_size > 0;
  @ requires disk_car->offset < 0x8000000000000000;
  @ requires 0 < count < 0x8000000000000000;
  @ requires offset < 0x8000000000000000;
  @ requires \valid_read((char *)buf + (0 .. count -1));
  @ requires disk_car->wbuffer == \null || \freeable(disk_car->wbuffer);
  @ ensures  disk_car->wbuffer == \null || \freeable(disk_car->wbuffer);
  @*/
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
    if(disk_car->wbuffer_size < count_new)
    {
      free(disk_car->wbuffer);
      disk_car->wbuffer=NULL;
    }
    if(disk_car->wbuffer==NULL)
    {
      disk_car->wbuffer_size=128*512;
      /*@ loop assigns disk_car->wbuffer_size; */
      while(disk_car->wbuffer_size < count_new)
      {
	disk_car->wbuffer_size*=2;
      }
      /*@ assert disk_car->wbuffer_size >= count_new; */
      disk_car->wbuffer=(char*)MALLOC(disk_car->wbuffer_size);
    }
    /*@ assert \freeable(disk_car->wbuffer); */
    if(fnct_pread(disk_car, disk_car->wbuffer, count_new, offset_new/disk_car->sector_size*disk_car->sector_size)<0)
    {
      log_error("read failed but trying to write anyway");
      memset(disk_car->wbuffer,0, disk_car->wbuffer_size);
    }
    memcpy((char*)disk_car->wbuffer+(offset_new%disk_car->sector_size),buf,count);
    tmp=fnct_pwrite(disk_car, disk_car->wbuffer, count_new, offset_new/disk_car->sector_size*disk_car->sector_size);
    /*@ assert \freeable(disk_car->wbuffer) && disk_car->wbuffer_size > 0; */
    return (tmp < (signed)count ? tmp : (signed)count);
  }
  return fnct_pwrite(disk_car, buf, count, offset_new);
}
