#if defined(__CYGWIN__) || defined(__MINGW32__)
void file_win32_disk_get_info(HANDLE handle, disk_t *dev, const int verbose);
#endif

