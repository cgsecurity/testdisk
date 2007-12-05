void hd_update_geometry(disk_t *disk_car, const int allow_partial_last_cylinder, const int verbose);
void hd_update_all_geometry(const list_disk_t * list_disk, const int allow_partial_last_cylinder, const int verbose);
list_disk_t *hd_parse(list_disk_t *list_disk, const int verbose, const arch_fnct_t *arch, const int testdisk_mode);
disk_t *file_test_availability(const char *device, const int verbose, const arch_fnct_t *arch, const int testdisk_mode);
#if defined(__CYGWIN__) || defined(__MINGW32__)
disk_t *file_test_availability_win32(const char *device, const int verbose, const arch_fnct_t *arch, const int testdisk_mode);
#endif
void autoset_unit(disk_t *disk_car);
