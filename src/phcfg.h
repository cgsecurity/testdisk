#ifdef __cplusplus
extern "C" {
#endif

void reset_list_file_enable(file_enable_t *files_enable);
int file_options_save(const file_enable_t *files_enable);
int file_options_load(file_enable_t *files_enable);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
