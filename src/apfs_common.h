#ifndef _APFS_COMMON_H
#define _APFS_COMMON_H
#ifdef __cplusplus
extern "C"
{
#endif
#define MAX_CKSUM_SIZE 8
#define NX_EPH_INFO_COUNT 4
#define NX_EPH_INFO_VERSION_1 1
#define NX_EPH_MIN_BLOCK_COUNT 8
#define NX_MAGIC 'BSXN'
#define NX_MAX_FILE_SYSTEM_EPH_STRUCTS 4
#define NX_MAX_FILE_SYSTEMS 100
#define NX_MAXIMUM_BLOCK_SIZE 65536
#define NX_MINIMUM_BLOCK_SIZE 4096
#define NX_TX_MIN_CHECKPOINT_COUNT 4

  typedef enum {
    NX_CNTR_OBJ_CKSUM_SET
      = 0,
    NX_CNTR_OBJ_CKSUM_FAIL = 1,
    NX_NUM_COUNTERS = 32
  } nx_counter_id_t;

  typedef uint64_t oid_t;
  typedef uint64_t xid_t;

  struct obj_phys {
    uint8_t o_cksum[MAX_CKSUM_SIZE];
    oid_t o_oid;
    xid_t o_xid;
    uint32_t o_type;
    uint32_t o_subtype;
  } __attribute__((gcc_struct, __packed__));

  typedef struct obj_phys obj_phys_t;
#if HAVE_PADDR_T == 0
  typedef int64_t paddr_t;
#endif

  struct prange {
    paddr_t pr_start_paddr;
    uint64_t pr_block_count;
  } __attribute__((gcc_struct, __packed__));
  typedef struct prange prange_t;

  typedef unsigned char apfs_uuid_t[16];

  struct nx_superblock {
    obj_phys_t nx_o;
    uint32_t nx_magic;
    uint32_t nx_block_size;
    uint64_t nx_block_count;
    uint64_t nx_features;
    uint64_t nx_readonly_compatible_features;
    uint64_t nx_incompatible_features;
    apfs_uuid_t nx_uuid;
    oid_t nx_next_oid;
    xid_t nx_next_xid;
    uint32_t nx_xp_desc_blocks;
    uint32_t nx_xp_data_blocks;
    paddr_t nx_xp_desc_base;
    paddr_t nx_xp_data_base;
    uint32_t nx_xp_desc_next;
    uint32_t nx_xp_data_next;
    uint32_t nx_xp_desc_index;
    uint32_t nx_xp_desc_len;
    uint32_t nx_xp_data_index;
    uint32_t nx_xp_data_len;
    oid_t nx_spaceman_oid;
    oid_t nx_omap_oid;
    oid_t nx_reaper_oid;
    uint32_t nx_test_type;
    uint32_t nx_max_file_systems;
    oid_t nx_fs_oid[NX_MAX_FILE_SYSTEMS];
    uint64_t nx_counters[NX_NUM_COUNTERS];
    prange_t nx_blocked_out_prange;
    oid_t nx_evict_mapping_tree_oid;
    uint64_t nx_flags;
    paddr_t nx_efi_jumpstart;
    apfs_uuid_t nx_fusion_uuid;
    prange_t nx_keylocker;
    uint64_t nx_ephemeral_info[NX_EPH_INFO_COUNT];
    oid_t nx_test_oid;
    oid_t nx_fusion_mt_oid;
    oid_t nx_fusion_wbc_oid;
    prange_t nx_fusion_wbc;
    uint64_t nx_newest_mounted_version;
    prange_t nx_mkb_locker;
  };
typedef struct nx_superblock nx_superblock_t;

//#define APFS_SUPERBLOCK_SIZE (sizeof(nx_superblock_t))
#define APFS_SUPERBLOCK_SIZE 4096
/*@
  @ requires \valid_read(sb);
  @ requires partition==\null || (\valid_read(partition) && valid_partition(partition));
  @ requires \separated(sb, partition);
  @ assigns  \nothing;
  @ */
int test_APFS(const nx_superblock_t *sb, const partition_t *partition);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
