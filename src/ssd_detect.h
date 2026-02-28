/*

    File: ssd_detect.h

    Copyright (C) 2024 TestDisk Contributors

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
#ifndef _SSD_DETECT_H
#define _SSD_DETECT_H
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  DEVICE_TYPE_UNKNOWN = 0,
  DEVICE_TYPE_HDD,
  DEVICE_TYPE_SSD,
  DEVICE_TYPE_NVME,
  DEVICE_TYPE_EMMC,
  DEVICE_TYPE_USB
} device_type_t;

typedef struct {
  device_type_t type;
  char model[128];
  char serial[64];
  char firmware[32];
  unsigned int block_size;      /* physical block size */
  unsigned int logical_block;   /* logical block size */
  int trim_supported;           /* 1 if TRIM/DISCARD supported */
  int rotational;               /* 0=SSD, 1=HDD, -1=unknown */
} device_info_t;

/*@
  @ requires valid_read_string(device_path);
  @ requires \valid(info);
  @*/
int detect_device_type(const char *device_path, device_info_t *info);

/*@
  @ assigns \nothing;
  @*/
const char *device_type_name(device_type_t type);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif /* _SSD_DETECT_H */
