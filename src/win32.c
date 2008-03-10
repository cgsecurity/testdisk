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
#ifdef HAVE_W32API_DDK_NTDDDISK_H
#include <w32api/ddk/ntdddisk.h>
#endif
#include "fnctdsk.h"
#include "log.h"
#include "win32.h"

void file_win32_disk_get_info(HANDLE handle, disk_t *dev, const int verbose)
{
#ifdef IOCTL_STORAGE_QUERY_PROPERTY
  DWORD               cbBytesReturned = 0;
  STORAGE_PROPERTY_QUERY query;
  char buffer [10240];
  memset((void *) & query, 0, sizeof (query));
  query.PropertyId = StorageDeviceProperty;
  query.QueryType = PropertyStandardQuery;
  memset(&buffer, 0, sizeof (buffer));

  if ( DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY,
	&query,
	sizeof (query),
	&buffer,
	sizeof (buffer),
	&cbBytesReturned, NULL) )
  {         
    const STORAGE_DEVICE_DESCRIPTOR * descrip = (const STORAGE_DEVICE_DESCRIPTOR *) & buffer;
    const unsigned int offsetVendor=descrip->VendorIdOffset;
    const unsigned int offsetProduct=descrip->ProductIdOffset;
    unsigned int lenVendor=0;
    unsigned int lenProduct=0;
    if(verbose>0)
    {
      log_info("IOCTL_STORAGE_QUERY_PROPERTY:\n");
      dump_log(&buffer, cbBytesReturned);
    }
    if(offsetVendor>0)
    {
      for(lenVendor=0; offsetVendor+lenVendor < sizeof(buffer) &&
	  offsetVendor+lenVendor < cbBytesReturned &&
	  buffer[offsetVendor+lenVendor] != '\0';
	  lenVendor++);
    }
    if(offsetProduct>0)
    {
      for(lenProduct=0; offsetProduct+lenProduct < sizeof(buffer) &&
	  offsetProduct+lenProduct < cbBytesReturned &&
	  buffer[offsetProduct+lenProduct] != '\0';
	  lenProduct++);
    }

    if(lenVendor+lenProduct>0)
    {
      int i;
      dev->model = (char*) MALLOC(lenVendor+1+lenProduct+1);
      dev->model[0]='\0';
      if(lenVendor>0)
      {
	memcpy(dev->model, &buffer[offsetVendor], lenVendor);
	dev->model[lenVendor]='\0';
	for(i=lenVendor-1;i>=0 && dev->model[i]==' ';i--);
	if(i>=0)
	  dev->model[++i]=' ';
	dev->model[++i]='\0';
      }
      if(lenProduct>0)
      {
	strncat(dev->model, &buffer[offsetProduct],lenProduct);
	for(i=strlen(dev->model)-1;i>=0 && dev->model[i]==' ';i--);
	dev->model[++i]='\0';
      }
      if(strlen(dev->model)>0)
	return ;
      free(dev->model);
      dev->model=NULL;
    }
  }
#endif
}
#endif
