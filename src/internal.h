#ifndef KEYSHARP_PERMISSIONS_INTERNAL_H
#define KEYSHARP_PERMISSIONS_INTERNAL_H

#include "keysharp_permissions/permissions.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

bool ksp_internal_write_all(int descriptor, const void *data, size_t length);
bool ksp_internal_read_all(int descriptor, void *data, size_t length);
int ksp_internal_make_parent_directories(const char *path, mode_t mode,
                                         uid_t owner_uid);
int ksp_internal_fsync_directory(const char *directory);
bool ksp_internal_cancelled(ksp_cancel_fn cancelled, void *user_data);

#endif
