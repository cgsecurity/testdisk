/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _TD_JSON_H
#define _TD_JSON_H

int td_json_open(const char *filename);
void td_json_search(const disk_t *disk, const list_part_t *partitions, const int deeper, const int aborted);
int td_json_close(void);

#endif
