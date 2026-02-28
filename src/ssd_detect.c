/*

    File: ssd_detect.c

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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#include "ssd_detect.h"

/*
 * sysfs_read_uint: read a single unsigned integer from a sysfs file.
 * Returns 1 on success, 0 on failure (file absent or unreadable).
 */
#ifdef __linux__
static int sysfs_read_uint(const char *path, unsigned int *val)
{
	FILE *f;
	f = fopen(path, "r");
	if(f == NULL)
		return 0;
	if(fscanf(f, "%u", val) != 1)
	{
		fclose(f);
		return 0;
	}
	fclose(f);
	return 1;
}

/*
 * sysfs_read_uint64: read a uint64 from a sysfs file.
 * Returns 1 on success, 0 on failure.
 */
static int sysfs_read_uint64(const char *path, unsigned long long *val)
{
	FILE *f;
	f = fopen(path, "r");
	if(f == NULL)
		return 0;
	if(fscanf(f, "%llu", val) != 1)
	{
		fclose(f);
		return 0;
	}
	fclose(f);
	return 1;
}

/*
 * sysfs_read_str: read a string from a sysfs file, strip trailing whitespace.
 * Returns 1 on success, 0 on failure.
 */
static int sysfs_read_str(const char *path, char *buf, unsigned int bufsize)
{
	FILE *f;
	size_t len;
	f = fopen(path, "r");
	if(f == NULL)
		return 0;
	if(fgets(buf, (int)bufsize, f) == NULL)
	{
		fclose(f);
		buf[0] = '\0';
		return 0;
	}
	fclose(f);
	/* Strip trailing newline / whitespace */
	len = strlen(buf);
	while(len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' || buf[len-1] == ' '))
	{
		buf[--len] = '\0';
	}
	return 1;
}

/*
 * devname_from_path: extract bare device name from /dev/sdX or /dev/nvmeX etc.
 * e.g. "/dev/sda" -> "sda", "/dev/nvme0n1" -> "nvme0n1"
 * Result written into out_buf (at most bufsize bytes, null-terminated).
 */
static void devname_from_path(const char *device_path, char *out_buf, unsigned int bufsize)
{
	const char *p;
	/* Advance past last '/' */
	p = strrchr(device_path, '/');
	if(p != NULL)
		p++;
	else
		p = device_path;
	strncpy(out_buf, p, bufsize - 1);
	out_buf[bufsize - 1] = '\0';
}

/*
 * strip_partition_suffix: for a device name like "sda1" strip the numeric
 * partition suffix to get the block device base "sda".  NVMe partitions look
 * like "nvme0n1p1" – strip everything from 'p' onward when the name already
 * contains digits before the 'p'.
 * Modifies devname in-place.
 */
static void strip_partition_suffix(char *devname)
{
	size_t len;
	size_t i;
	len = strlen(devname);
	if(len == 0)
		return;
	/* NVMe: strip trailing "pN" partition suffix (e.g. nvme0n1p2 -> nvme0n1) */
	if(strncmp(devname, "nvme", 4) == 0)
	{
		for(i = len; i > 0; i--)
		{
			if(devname[i-1] == 'p' && i > 1)
			{
				devname[i-1] = '\0';
				return;
			}
		}
		return;
	}
	/* Generic: strip trailing digits (partition numbers) */
	i = len;
	while(i > 0 && devname[i-1] >= '0' && devname[i-1] <= '9')
		i--;
	/* Keep at least one character */
	if(i > 0 && i < len)
		devname[i] = '\0';
}
#endif /* __linux__ */

/*
 * detect_device_type: populate device_info_t for the given device path.
 * On non-Linux platforms, returns -1 with type=DEVICE_TYPE_UNKNOWN.
 * On Linux, reads sysfs attributes; missing attributes are silently skipped.
 */
int detect_device_type(const char *device_path, device_info_t *info)
{
	if(info == NULL || device_path == NULL)
		return -1;

	/* Zero-initialise the structure */
	memset(info, 0, sizeof(*info));
	info->type = DEVICE_TYPE_UNKNOWN;
	info->rotational = -1; /* unknown until read */

#ifdef __linux__
	{
		char devname[64];
		char sysfs_base[256];
		char sysfs_path[320];
		unsigned int rotational_val = 0;
		unsigned int phys_block = 0;
		unsigned int log_block = 0;
		unsigned long long discard_max = 0;

		devname_from_path(device_path, devname, sizeof(devname));
		strip_partition_suffix(devname);

		snprintf(sysfs_base, sizeof(sysfs_base),
			"/sys/block/%s", devname);

		/* --- rotational flag (/sys/block/DEV/queue/rotational) --- */
		snprintf(sysfs_path, sizeof(sysfs_path),
			"%s/queue/rotational", sysfs_base);
		if(sysfs_read_uint(sysfs_path, &rotational_val))
		{
			info->rotational = (int)rotational_val;
		}

		/* --- model string (/sys/block/DEV/device/model) --- */
		snprintf(sysfs_path, sizeof(sysfs_path),
			"%s/device/model", sysfs_base);
		sysfs_read_str(sysfs_path, info->model, sizeof(info->model));

		/* --- serial number (/sys/block/DEV/device/serial) --- */
		snprintf(sysfs_path, sizeof(sysfs_path),
			"%s/device/serial", sysfs_base);
		sysfs_read_str(sysfs_path, info->serial, sizeof(info->serial));

		/* --- firmware revision (/sys/block/DEV/device/firmware_rev) --- */
		snprintf(sysfs_path, sizeof(sysfs_path),
			"%s/device/firmware_rev", sysfs_base);
		sysfs_read_str(sysfs_path, info->firmware, sizeof(info->firmware));

		/* --- physical block size --- */
		snprintf(sysfs_path, sizeof(sysfs_path),
			"%s/queue/physical_block_size", sysfs_base);
		if(sysfs_read_uint(sysfs_path, &phys_block))
			info->block_size = phys_block;

		/* --- logical block size --- */
		snprintf(sysfs_path, sizeof(sysfs_path),
			"%s/queue/logical_block_size", sysfs_base);
		if(sysfs_read_uint(sysfs_path, &log_block))
			info->logical_block = log_block;

		/* --- TRIM support (discard_max_bytes > 0) --- */
		snprintf(sysfs_path, sizeof(sysfs_path),
			"%s/queue/discard_max_bytes", sysfs_base);
		if(sysfs_read_uint64(sysfs_path, &discard_max))
			info->trim_supported = (discard_max > 0) ? 1 : 0;

		/*
		 * Classify device type using name pattern and sysfs attributes.
		 * Priority: NVMe name -> eMMC name -> rotational flag -> USB heuristic.
		 */
		if(strncmp(devname, "nvme", 4) == 0)
		{
			info->type = DEVICE_TYPE_NVME;
		}
		else if(strncmp(devname, "mmcblk", 6) == 0)
		{
			info->type = DEVICE_TYPE_EMMC;
		}
		else if(info->rotational == 0)
		{
			info->type = DEVICE_TYPE_SSD;
		}
		else if(info->rotational == 1)
		{
			/* Could still be a USB HDD; check removable flag */
			char removable_path[320];
			unsigned int removable = 0;
			snprintf(removable_path, sizeof(removable_path),
				"%s/removable", sysfs_base);
			if(sysfs_read_uint(removable_path, &removable) && removable)
				info->type = DEVICE_TYPE_USB;
			else
				info->type = DEVICE_TYPE_HDD;
		}
		/* If rotational is -1, type remains DEVICE_TYPE_UNKNOWN */
	}
	return 0;
#else
	/* Non-Linux stub: return DEVICE_TYPE_UNKNOWN gracefully */
	(void)device_path;
	return -1;
#endif /* __linux__ */
}

/*
 * device_type_name: human-readable label for a device_type_t value.
 */
const char *device_type_name(device_type_t type)
{
	switch(type)
	{
		case DEVICE_TYPE_HDD:     return "HDD";
		case DEVICE_TYPE_SSD:     return "SSD";
		case DEVICE_TYPE_NVME:    return "NVMe";
		case DEVICE_TYPE_EMMC:    return "eMMC";
		case DEVICE_TYPE_USB:     return "USB";
		case DEVICE_TYPE_UNKNOWN:
		default:                  return "Unknown";
	}
}
