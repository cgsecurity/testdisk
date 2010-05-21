/*

    File: hidden.c

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
#include "types.h"
#include "common.h"
#include "log.h"
#include "hidden.h"

int is_hpa_or_dco(const disk_t *disk)
{
  int res=0;
  if(disk->user_max > 0 && disk->user_max < disk->native_max+1)
  {
    log_warning("%s: Host Protected Area (HPA) present.\n", disk->device);
    res=1;
  }
  if((disk->native_max > 0 && disk->user_max < disk->native_max+1 && disk->native_max < disk->dco) ||
      (disk->user_max > 0 && disk->user_max < disk->dco+1))
  {
    log_warning("%s: Device Configuration Overlay (DCO) present.\n", disk->device);
    res=1;
  }
  if(res>0)
    log_flush();
  return res;
}
