/* PhotoRec image filtering adapters, licensed under GPL v2 or later. */
#ifndef _PIMAGE_H
#define _PIMAGE_H
#ifdef __cplusplus
extern "C" {
#endif
/* Save the selected minima and reject only definitively small source images.
 * Call after finishing the preceding file, but before creating this file. */
int photorec_image_prepare(file_recovery_t *file_recovery,
    const struct ph_param *params, const struct ph_options *options,
    const alloc_data_t *list_search_space, const unsigned char *buffer,
    unsigned int buffer_size);
/* Recheck the recovered stream, after the native checker has trimmed it. */
int photorec_image_reject(const file_recovery_t *file_recovery);
#ifdef __cplusplus
}
#endif
#endif
