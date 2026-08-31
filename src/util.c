#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool ksp_internal_write_all(int descriptor, const void *data, size_t length)
{
    const unsigned char *cursor = data;

    while (length != 0u) {
        ssize_t written = write(descriptor, cursor, length);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return false;
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return true;
}

bool ksp_internal_read_all(int descriptor, void *data, size_t length)
{
    unsigned char *cursor = data;

    while (length != 0u) {
        ssize_t count = read(descriptor, cursor, length);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return false;
        cursor += (size_t)count;
        length -= (size_t)count;
    }
    return true;
}

static int verify_parent_directory(const char *path, uid_t owner_uid)
{
    struct stat info;

    if (lstat(path, &info) != 0 || !S_ISDIR(info.st_mode)
        || (info.st_uid != 0 && info.st_uid != owner_uid)
        || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

int ksp_internal_make_parent_directories(const char *path, mode_t mode,
                                         uid_t owner_uid)
{
    char copy[KSP_PATH_CAPACITY];
    size_t length;

    if (path == NULL || path[0] != '/'
        || (length = strlen(path)) == 0u || length >= sizeof(copy)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(copy, path, length + 1u);
    for (char *cursor = copy + 1; *cursor != '\0'; cursor++) {
        struct stat info;
        bool created = false;

        if (*cursor != '/')
            continue;
        *cursor = '\0';
        if (lstat(copy, &info) != 0) {
            if (errno != ENOENT || mkdir(copy, mode) != 0)
                goto error;
            created = true;
            if (chmod(copy, mode) != 0)
                goto error;
        }
        if (verify_parent_directory(copy, owner_uid) != 0)
            goto error;
        *cursor = '/';
        continue;

error:
        if (created)
            (void)rmdir(copy);
        *cursor = '/';
        return -1;
    }
    return 0;
}

int ksp_internal_fsync_directory(const char *directory)
{
    int descriptor;
    int result;
    int saved_errno;

    do {
        descriptor = open(directory,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0)
        return -1;
    do {
        result = fsync(descriptor);
    } while (result != 0 && errno == EINTR);
    saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    return result;
}

bool ksp_internal_cancelled(ksp_cancel_fn cancelled, void *user_data)
{
    return cancelled != NULL && cancelled(user_data);
}
