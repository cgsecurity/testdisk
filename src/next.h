#ifdef __cplusplus
extern "C" {
#endif

void search_location_init(const disk_t *disk_car, const unsigned int location_boundary, const int fast_mode);
uint64_t search_location_update(const uint64_t location);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
