/* Image metadata probes for PhotoRec, licensed under GPL v2 or later. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <string.h>
#include "types.h"
#include "image_filter.h"

/* Bounded extra work even when a damaged image advertises enormous lengths.
 * Long APP/EXIF segments are skipped, not buffered or searched for thumbnails. */
#define IMAGE_PROBE_BUDGET (16U * 1024U * 1024U)
#define IMAGE_PROBE_MARKERS 65536U

struct image_reader
{
  image_read_t read_data;
  void *opaque;
  uint64_t available;
  uint64_t offset;
  unsigned int count;
  unsigned int read_bytes;
  unsigned char buffer[4096];
};

static int image_read(struct image_reader *reader, const uint64_t offset,
    unsigned char *buffer, const unsigned int count)
{
  unsigned int n;
  if(offset > reader->available || count > reader->available - offset ||
      count > sizeof(reader->buffer))
    return 0;
  if(offset >= reader->offset && offset - reader->offset <= reader->count &&
      count <= reader->count - (offset - reader->offset))
  {
    memcpy(buffer, reader->buffer + (offset - reader->offset), count);
    return 1;
  }
  n=(reader->available - offset < sizeof(reader->buffer) ?
      (unsigned int)(reader->available - offset) : sizeof(reader->buffer));
  if(n > IMAGE_PROBE_BUDGET - reader->read_bytes ||
      reader->read_data(reader->opaque, offset, reader->buffer, n)==0)
    return 0;
  reader->read_bytes+=n;
  reader->offset=offset;
  reader->count=n;
  memcpy(buffer, reader->buffer, count);
  return 1;
}

static uint64_t image_be32(const unsigned char *p)
{
  return ((uint64_t)p[0]<<24) | ((uint64_t)p[1]<<16) |
    ((uint64_t)p[2]<<8) | p[3];
}

static int image_dimensions(const struct image_limits *limits,
    const uint64_t width, const uint64_t height)
{
  if(width==0 || height==0)
    return 0;
  /* Both formats store at most 32-bit dimensions, so the product fits. */
  if(width < limits->width || height < limits->height ||
      width * height < limits->pixels)
    return -1;
  return 1;
}

static uint32_t image_crc(const unsigned char *p, const unsigned int size)
{
  uint32_t crc=0xffffffffU;
  unsigned int i;
  for(i=0; i<size; i++)
  {
    unsigned int j;
    crc^=p[i];
    for(j=0; j<8; j++)
      crc=(crc>>1) ^ ((crc & 1U)!=0 ? 0xedb88320U : 0);
  }
  return crc ^ 0xffffffffU;
}

static int image_probe_png(struct image_reader *reader,
    const struct image_limits *limits)
{
  unsigned char header[33];
  uint64_t offset=33;
  unsigned int chunks=0;
  int have_data=0;
  int dimensions;
  if(image_read(reader, 0, header, sizeof(header))==0 ||
      memcmp(header, "\x89PNG\r\n\x1a\n", 8)!=0 ||
      image_be32(header+8)!=13 || memcmp(header+12, "IHDR", 4)!=0 ||
      image_crc(header+12, 17)!=image_be32(header+29))
    return 0;
  dimensions=image_dimensions(limits, image_be32(header+16), image_be32(header+20));
  if(dimensions<=0 || limits->bytes==0)
    return dimensions;
  while(chunks++ < IMAGE_PROBE_MARKERS)
  {
    unsigned char chunk[8];
    uint64_t length;
    if(offset>=limits->bytes)
      return 1;
    if(image_read(reader, offset, chunk, sizeof(chunk))==0)
      return 0;
    length=image_be32(chunk);
    if(length>0x7fffffffU || reader->available-offset < 12 ||
        length > reader->available-offset-12)
      return 0;
    if(memcmp(chunk+4, "IDAT", 4)==0)
      have_data=1;
    else if(memcmp(chunk+4, "IEND", 4)==0)
    {
      unsigned char crc[4];
      if(length!=0 || !have_data ||
          image_read(reader, offset+8, crc, sizeof(crc))==0 ||
          image_be32(crc)!=image_crc(chunk+4, 4))
        return 0;
      return (offset+12 < limits->bytes ? -1 : 1);
    }
    else if(memcmp(chunk+4, "IHDR", 4)==0)
      return 0;
    offset+=length+12;
  }
  return 0;
}

static int image_jpeg_sof(const unsigned int marker)
{
  return marker>=0xc0 && marker<=0xcf && marker!=0xc4 &&
    marker!=0xc8 && marker!=0xcc;
}

static int image_probe_jpg(struct image_reader *reader,
    const struct image_limits *limits)
{
  unsigned char data[8];
  uint64_t offset=2;
  uint64_t width=0;
  uint64_t height=0;
  unsigned int markers=0;
  int entropy=0;
  int have_scan=0;
  int multi_picture=0;
  if(image_read(reader, 0, data, 2)==0 || data[0]!=0xff || data[1]!=0xd8)
    return 0;
  while(markers < IMAGE_PROBE_MARKERS)
  {
    unsigned int marker;
    unsigned int length;
    int dimensions=image_dimensions(limits, width, height);
    if(dimensions<0)
      return -1;
    if(dimensions>0 && (limits->bytes==0 || offset>=limits->bytes))
      return 1;
    if(image_read(reader, offset, data, 1)==0)
      return 0;
    if(data[0]!=0xff)
    {
      if(!entropy)
        return 0;
      offset++;
      continue;
    }
    do
    {
      offset++;
      if(image_read(reader, offset, data, 1)==0)
        return 0;
    } while(data[0]==0xff);
    marker=data[0];
    offset++;
    if(entropy && (marker==0 || (marker>=0xd0 && marker<=0xd7)))
      continue;
    markers++;
    if(marker==0xd9)
    {
      if(!have_scan || dimensions==0 || multi_picture)
        return 0;
      return (offset < limits->bytes ? -1 : 1);
    }
    if(marker==0 || marker==0xd8 || (marker>=0xd0 && marker<=0xd7))
      return 0;
    if(marker==0x01)
      continue;
    if(image_read(reader, offset, data, 2)==0)
      return 0;
    length=((unsigned int)data[0]<<8) | data[1];
    if(length<2 || length > reader->available-offset)
      return 0;
    if(image_jpeg_sof(marker))
    {
      if(length<8 || image_read(reader, offset, data, 8)==0 ||
          data[7]==0 || length!=8U+3U*data[7])
        return 0;
      height=((unsigned int)data[3]<<8) | data[4];
      width=((unsigned int)data[5]<<8) | data[6];
    }
    else if(marker==0xdc && length==4 && height==0 && have_scan)
    {
      if(image_read(reader, offset+2, data, 2)==0)
        return 0;
      height=((unsigned int)data[0]<<8) | data[1];
    }
    else if(marker==0xe2 && length>=6)
    {
      if(image_read(reader, offset+2, data, 4)==0)
        return 0;
      if(memcmp(data, "MPF\0", 4)==0)
        multi_picture=1;
    }
    if(marker==0xda)
    {
      if(width==0 || length<6)
        return 0;
      entropy=1;
      have_scan=1;
    }
    else if(marker!=0xdc)
      entropy=0;
    offset+=length;
  }
  return 0;
}

/* Adding another image format requires only a metadata probe and this table;
 * the recovery, option and session code is independent of the image format. */
static const struct
{
  const char *extension;
  int (*probe)(struct image_reader *, const struct image_limits *);
} image_probes[]={
  {"jpg", image_probe_jpg},
  {"png", image_probe_png},
  {NULL, NULL}
};

int image_filter_supported(const char *extension)
{
  unsigned int i;
  if(extension==NULL)
    return 0;
  for(i=0; image_probes[i].extension!=NULL; i++)
    if(strcmp(extension, image_probes[i].extension)==0)
      return 1;
  return 0;
}

int image_filter_probe(const char *extension, const struct image_limits *limits,
    image_read_t read_data, void *opaque, const uint64_t available)
{
  unsigned int i;
  if(extension==NULL)
    return 0;
  for(i=0; image_probes[i].extension!=NULL; i++)
  {
    if(strcmp(extension, image_probes[i].extension)==0)
    {
      struct image_reader reader;
      memset(&reader, 0, sizeof(reader));
      reader.read_data=read_data;
      reader.opaque=opaque;
      reader.available=available;
      return image_probes[i].probe(&reader, limits);
    }
  }
  return 0;
}
