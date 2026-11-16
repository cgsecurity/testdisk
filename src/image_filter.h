/* Image metadata probes for PhotoRec, licensed under GPL v2 or later. */
#ifndef _IMAGE_FILTER_H
#define _IMAGE_FILTER_H
#ifdef __cplusplus
extern "C" {
#endif

struct image_limits
{
  uint64_t width;
  uint64_t height;
  uint64_t pixels;
  uint64_t bytes;
};

/* The reader must return 1 only after reading all count bytes. Offsets are
 * relative to the beginning of the image. Neither probe writes any data. */
typedef int (*image_read_t)(void *opaque, uint64_t offset,
    unsigned char *buffer, unsigned int count);

/* -1: a known minimum is not met; 0: metadata incomplete/unsupported;
 *  1: the inspected metadata meets the minima. This is not a file validator.
 * Budget exhaustion and short reads return unknown, never a rejection. */
int image_filter_probe(const char *extension, const struct image_limits *limits,
    image_read_t read_data, void *opaque, uint64_t available);
int image_filter_supported(const char *extension);

#ifdef __cplusplus
}
#endif
#endif
