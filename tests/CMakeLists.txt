# tests/CMakeLists.txt — unit test build configuration using cmocka
# Mirrors test file structure from phase-06 plan.

cmake_minimum_required(VERSION 3.16)

# ── cmocka detection ─────────────────────────────────────────────────────────
find_package(cmocka QUIET)
if(NOT cmocka_FOUND)
    find_library(CMOCKA_LIB cmocka)
    find_path(CMOCKA_INCLUDE_DIR cmocka.h)
    if(CMOCKA_LIB AND CMOCKA_INCLUDE_DIR)
        set(cmocka_FOUND TRUE)
        # Wrap into imported target for uniform usage below
        add_library(cmocka::cmocka UNKNOWN IMPORTED)
        set_target_properties(cmocka::cmocka PROPERTIES
            IMPORTED_LOCATION "${CMOCKA_LIB}"
            INTERFACE_INCLUDE_DIRECTORIES "${CMOCKA_INCLUDE_DIR}"
        )
    endif()
endif()

if(NOT cmocka_FOUND)
    message(WARNING
        "cmocka not found — unit tests will not be built.\n"
        "Install with: sudo apt-get install libcmocka-dev  (Debian/Ubuntu)\n"
        "              brew install cmocka                  (macOS)"
    )
    return()
endif()

enable_testing()

# ── Source directories ────────────────────────────────────────────────────────
set(SRC "${CMAKE_SOURCE_DIR}/src")
set(BIN_DIR "${CMAKE_BINARY_DIR}")  # config.h lives here

# ── Common compile setup for every test target ────────────────────────────────
function(add_testdisk_test target)
    # Remaining args are source files
    add_executable(${target} ${ARGN})
    target_compile_definitions(${target} PRIVATE HAVE_CONFIG_H _GNU_SOURCE)
    target_include_directories(${target} PRIVATE
        "${BIN_DIR}"    # generated config.h
        "${SRC}"
    )
    target_compile_options(${target} PRIVATE
        -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
    )
    target_link_libraries(${target} PRIVATE cmocka::cmocka)
    add_test(NAME ${target} COMMAND ${target})
endfunction()

# ── Utility function tests ────────────────────────────────────────────────────

# CRC calculation
add_testdisk_test(test_crc
    test_crc.c
    ${SRC}/crc.c
    ${SRC}/log.c
)

# Unicode conversion utilities
add_testdisk_test(test_unicode
    test_unicode.c
    ${SRC}/unicode.c
    ${SRC}/common.c
    ${SRC}/log.c
)

# common.c utility functions
add_testdisk_test(test_common
    test_common.c
    ${SRC}/common.c
    ${SRC}/log.c
)

# ── File signature framework tests ───────────────────────────────────────────

# filegen core — signature registration and dispatch
add_testdisk_test(test_filegen
    test_filegen.c
    ${SRC}/filegen.c
    ${SRC}/common.c
    ${SRC}/log.c
    ${SRC}/setdate.c
)

# JPEG signature handler
add_testdisk_test(test_file_jpg
    test_file_jpg.c
    ${SRC}/file_jpg.c
    ${SRC}/file_tiff.c
    ${SRC}/file_tiff_be.c
    ${SRC}/file_tiff_le.c
    ${SRC}/filegen.c
    ${SRC}/common.c
    ${SRC}/log.c
    ${SRC}/setdate.c
    ${SRC}/suspend_no.c
)
if(HAVE_LIBJPEG AND JPEG_LIBRARIES)
    target_link_libraries(test_file_jpg PRIVATE ${JPEG_LIBRARIES})
    target_include_directories(test_file_jpg PRIVATE ${JPEG_INCLUDE_DIRS})
endif()

# PNG signature handler
add_testdisk_test(test_file_png
    test_file_png.c
    ${SRC}/file_png.c
    ${SRC}/filegen.c
    ${SRC}/common.c
    ${SRC}/log.c
    ${SRC}/setdate.c
    ${SRC}/suspend_no.c
)
if(HAVE_LIBZ AND ZLIB_LIBRARIES)
    target_link_libraries(test_file_png PRIVATE ${ZLIB_LIBRARIES})
endif()

# ── Filesystem handler tests ──────────────────────────────────────────────────
# These test superblock parsing logic using in-memory fake disk images.

# FAT filesystem handler
add_testdisk_test(test_fat
    test_fat.c
    ${SRC}/fat.c
    ${SRC}/fat_common.c
    ${SRC}/fat_dir.c
    ${SRC}/ext2_common.c
    ${SRC}/common.c
    ${SRC}/log.c
    ${SRC}/log_part.c
    ${SRC}/misc.c
    ${SRC}/setdate.c
)

# NTFS filesystem handler
add_testdisk_test(test_ntfs
    test_ntfs.c
    ${SRC}/ntfs.c
    ${SRC}/ntfs_utl.c
    ${SRC}/common.c
    ${SRC}/log.c
    ${SRC}/log_part.c
    ${SRC}/misc.c
    ${SRC}/setdate.c
)
if(HAVE_LIBNTFS3G AND NTFS3G_LIB)
    target_link_libraries(test_ntfs PRIVATE ${NTFS3G_LIB})
endif()

# ext2/3/4 filesystem handler
add_testdisk_test(test_ext2
    test_ext2.c
    ${SRC}/ext2.c
    ${SRC}/ext2_common.c
    ${SRC}/ext2_dir.c
    ${SRC}/common.c
    ${SRC}/log.c
    ${SRC}/log_part.c
    ${SRC}/misc.c
    ${SRC}/setdate.c
)
if(HAVE_LIBEXT2FS AND EXT2FS_LIB)
    target_link_libraries(test_ext2 PRIVATE ${EXT2FS_LIB})
endif()
if(HAVE_LIBCOMM_ERR AND COM_ERR_LIB)
    target_link_libraries(test_ext2 PRIVATE ${COM_ERR_LIB})
endif()
