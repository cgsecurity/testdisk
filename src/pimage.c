/* PhotoRec image filtering adapters, licensed under GPL v2 or later. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "photorec.h"
#include "image_filter.h"
#include "pimage.h"

struct image_disk_reader
{
  disk_t *disk;
  uint64_t start;
  const unsigned char *buffer;
  unsigned int buffer_size;
};

static int image_read_disk(void *opaque, const uint64_t offset,
    unsigned char *buffer, const unsigned int count)
{
  struct image_disk_reader *reader=(struct image_disk_reader *)opaque;
  if(offset <= reader->buffer_size && count <= reader->buffer_size-offset)
  {
    memcpy(buffer, reader->buffer+offset, count);
    return 1;
  }
  return reader->disk->pread(reader->disk, buffer, count, reader->start+offset)==(int)count;
}

static int image_read_file(void *opaque, const uint64_t offset,
    unsigned char *buffer, const unsigned int count)
{
  FILE *handle=(FILE *)opaque;
  return my_fseek(handle, offset, SEEK_SET)==0 && fread(buffer, 1, count, handle)==count;
}

int photorec_image_prepare(file_recovery_t *file_recovery,
    const struct ph_param *params, const struct ph_options *options,
    const alloc_data_t *list_search_space, const unsigned char *buffer,
    const unsigned int buffer_size)
{
  struct image_limits limits;
  struct image_disk_reader reader;
  const struct td_list_head *tmp;
  uint64_t available=0;
  uint64_t disk_size=params->disk->disk_real_size;
  if(!image_filter_supported(file_recovery->extension))
    return 0;
  file_recovery->image_min_width=limits.width=options->image_min_width;
  file_recovery->image_min_height=limits.height=options->image_min_height;
  file_recovery->image_min_pixels=limits.pixels=options->image_min_pixels;
  file_recovery->image_min_bytes=limits.bytes=options->image_min_bytes;
  if(limits.width==0 && limits.height==0 && limits.pixels==0 && limits.bytes==0)
    return 0;
  /* Brute-force reconstruction can reorder source fragments. Its recovered
   * stream is authoritative; never preflight it as a contiguous image. */
  if(params->status==STATUS_EXT2_ON_BF || params->status==STATUS_EXT2_OFF_BF)
    return 0;
  if(params->disk->disk_size < disk_size)
    disk_size=params->disk->disk_size;
  if(file_recovery->location.start >= disk_size)
    return 0;
  /* Stop at the current search extent. A hole can contain another file's
   * valid metadata, which must not decide this image's dimensions or EOF. */
  td_list_for_each(tmp, &list_search_space->list)
  {
    const alloc_data_t *extent=td_list_entry_const(tmp, const alloc_data_t, list);
    if(extent->start <= file_recovery->location.start &&
        file_recovery->location.start <= extent->end)
    {
      available=(extent->end < disk_size-1 ? extent->end : disk_size-1)
        - file_recovery->location.start + 1;
      break;
    }
  }
  /* An ext2 indirect block can occur after the first twelve data blocks.
   * Leave metadata beyond that point to the reconstructed-stream check. */
  if((params->status==STATUS_EXT2_ON || params->status==STATUS_EXT2_ON_SAVE_EVERYTHING) &&
      available > (uint64_t)12*params->blocksize)
    available=(uint64_t)12*params->blocksize;
  reader.disk=params->disk;
  reader.start=file_recovery->location.start;
  reader.buffer=buffer;
  reader.buffer_size=buffer_size;
  return image_filter_probe(file_recovery->extension, &limits,
      image_read_disk, &reader, available)<0;
}

int photorec_image_reject(const file_recovery_t *file_recovery)
{
  struct image_limits limits;
  if(!image_filter_supported(file_recovery->extension))
    return 0;
  if(file_recovery->file_size < file_recovery->image_min_bytes)
    return 1;
  limits.width=file_recovery->image_min_width;
  limits.height=file_recovery->image_min_height;
  limits.pixels=file_recovery->image_min_pixels;
  limits.bytes=0; /* The native check has already established the final size. */
  if(limits.width==0 && limits.height==0 && limits.pixels==0)
    return 0;
  return image_filter_probe(file_recovery->extension, &limits,
      image_read_file, file_recovery->handle, file_recovery->file_size)<0;
}
