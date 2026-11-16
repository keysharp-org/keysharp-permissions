#include "keysharp_permissions/permissions.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define KSP_IDENTITY_KIND_PATH "path"
#define KSP_IDENTITY_KIND_SHA256 "sha256"

typedef struct ksp_sha256 {
    EVP_MD_CTX *context;
} ksp_sha256;

static int sha256_begin(ksp_sha256 *hash)
{
    if (hash == NULL) {
        errno = EINVAL;
        return -1;
    }
    hash->context = EVP_MD_CTX_new();
    if (hash->context == NULL) {
        errno = ENOMEM;
        return -1;
    }
    if (EVP_DigestInit_ex(hash->context, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(hash->context);
        hash->context = NULL;
        errno = EIO;
        return -1;
    }
    return 0;
}

static void sha256_end(ksp_sha256 *hash)
{
    int saved_errno = errno;

    if (hash != NULL) {
        EVP_MD_CTX_free(hash->context);
        hash->context = NULL;
    }
    errno = saved_errno;
}

static int sha256_update(ksp_sha256 *hash, const void *data, size_t length)
{
    if (hash == NULL || hash->context == NULL
        || (data == NULL && length != 0u)) {
        errno = EINVAL;
        return -1;
    }
    if (EVP_DigestUpdate(hash->context, data, length) != 1) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int sha256_finish(ksp_sha256 *hash,
                         char output[KSP_HASH_HEX_LENGTH + 1u])
{
    static const char digits[] = "0123456789abcdef";
    unsigned char digest[32];
    unsigned int length = 0u;

    if (hash == NULL || hash->context == NULL || output == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (EVP_DigestFinal_ex(hash->context, digest, &length) != 1
        || length != sizeof(digest)) {
        errno = EIO;
        return -1;
    }
    for (size_t index = 0u; index < sizeof(digest); index++) {
        output[index * 2u] = digits[digest[index] >> 4u];
        output[(index * 2u) + 1u] = digits[digest[index] & 0x0fu];
    }
    output[KSP_HASH_HEX_LENGTH] = '\0';
    return 0;
}

static int hash_identity(const char *kind, const void *identity,
                         size_t identity_length,
                         char output[KSP_HASH_HEX_LENGTH + 1u])
{
    static const unsigned char separator = 0u;
    ksp_sha256 hash;
    int result = -1;

    if (kind == NULL || kind[0] == '\0' || identity == NULL
        || identity_length == 0u || output == NULL
        || sha256_begin(&hash) != 0)
        return -1;
    if (sha256_update(&hash, KSP_IDENTITY_DOMAIN,
                      sizeof(KSP_IDENTITY_DOMAIN) - 1u) == 0
        && sha256_update(&hash, &separator, sizeof(separator)) == 0
        && sha256_update(&hash, kind, strlen(kind)) == 0
        && sha256_update(&hash, &separator, sizeof(separator)) == 0
        && sha256_update(&hash, identity, identity_length) == 0)
        result = sha256_finish(&hash, output);
    sha256_end(&hash);
    return result;
}

int ksp_identity_hash_path(const char *absolute_path,
                           char hash[KSP_HASH_HEX_LENGTH + 1u])
{
    size_t length;

    if (absolute_path == NULL || absolute_path[0] != '/'
        || (length = strlen(absolute_path)) == 0u
        || length >= KSP_PATH_CAPACITY || hash == NULL) {
        errno = EINVAL;
        return -1;
    }
    return hash_identity(KSP_IDENTITY_KIND_PATH, absolute_path, length, hash);
}

int ksp_identity_hash_content(
    const char executable_sha256[KSP_HASH_HEX_LENGTH + 1u],
    char hash[KSP_HASH_HEX_LENGTH + 1u])
{
    if (!ksp_hash_is_canonical(executable_sha256) || hash == NULL) {
        errno = EINVAL;
        return -1;
    }
    return hash_identity(KSP_IDENTITY_KIND_SHA256, executable_sha256,
                         KSP_HASH_HEX_LENGTH, hash);
}

static int hash_file(int descriptor,
                     char output[KSP_HASH_HEX_LENGTH + 1u])
{
    unsigned char buffer[8192];
    ksp_sha256 hash;
    int result = -1;

    while (lseek(descriptor, 0, SEEK_SET) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (sha256_begin(&hash) != 0)
        return -1;
    for (;;) {
        ssize_t count = read(descriptor, buffer, sizeof(buffer));

        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            break;
        if (count == 0) {
            result = sha256_finish(&hash, output);
            break;
        }
        if (sha256_update(&hash, buffer, (size_t)count) != 0)
            break;
    }
    sha256_end(&hash);
    return result;
}

static bool root_owned_and_protected(const struct stat *info)
{
    return info->st_uid == 0 && (info->st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool executable_path_is_protected(int descriptor,
                                         const char *absolute_path)
{
    char path[KSP_PATH_CAPACITY];
    struct stat executable;
    struct stat current;
    size_t length;

    if (descriptor < 0 || absolute_path == NULL || absolute_path[0] != '/'
        || (length = strlen(absolute_path)) == 0u || length >= sizeof(path)
        || fstat(descriptor, &executable) != 0
        || !S_ISREG(executable.st_mode)
        || !root_owned_and_protected(&executable)
        || lstat("/", &current) != 0 || !S_ISDIR(current.st_mode)
        || !root_owned_and_protected(&current))
        return false;
    memcpy(path, absolute_path, length + 1u);
    for (char *cursor = path + 1;; cursor++) {
        char saved;
        bool final;
        int status;
        bool valid;

        if (*cursor != '/' && *cursor != '\0')
            continue;
        saved = *cursor;
        *cursor = '\0';
        final = saved == '\0';
        status = final ? stat(path, &current) : lstat(path, &current);
        valid = status == 0 && root_owned_and_protected(&current)
            && (final
                ? S_ISREG(current.st_mode)
                    && current.st_dev == executable.st_dev
                    && current.st_ino == executable.st_ino
                : S_ISDIR(current.st_mode));
        *cursor = saved;
        if (!valid)
            return false;
        if (final)
            return true;
    }
}

static int read_proc_file(const char *path, char *buffer, size_t capacity,
                          size_t *length)
{
    size_t used = 0u;
    int descriptor;

    do {
        descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0)
        return -1;
    for (;;) {
        ssize_t count;

        if (used + 1u >= capacity) {
            close(descriptor);
            errno = EOVERFLOW;
            return -1;
        }
        count = read(descriptor, buffer + used, capacity - used - 1u);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            int saved_errno = errno;
            close(descriptor);
            errno = saved_errno;
            return -1;
        }
        if (count == 0)
            break;
        used += (size_t)count;
    }
    close(descriptor);
    buffer[used] = '\0';
    *length = used;
    return 0;
}

int ksp_process_start_time(pid_t pid, uint64_t *start_time)
{
    char path[64];
    char buffer[4096];
    char *cursor;
    char *end;
    unsigned long long value;
    size_t length;

    if (start_time != NULL)
        *start_time = 0u;
    if (pid <= 0 || start_time == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) <= 0
        || read_proc_file(path, buffer, sizeof(buffer), &length) != 0
        || length == 0u) {
        return -1;
    }
    cursor = strrchr(buffer, ')');
    if (cursor == NULL || cursor[1] != ' ') {
        errno = EPROTO;
        return -1;
    }
    cursor += 2;
    for (unsigned int field = 3u; field < 22u; field++) {
        cursor = strchr(cursor, ' ');
        if (cursor == NULL) {
            errno = EPROTO;
            return -1;
        }
        cursor++;
    }
    errno = 0;
    value = strtoull(cursor, &end, 10);
    if (errno != 0 || end == cursor || (*end != ' ' && *end != '\n')
        || value == 0u) {
        errno = EPROTO;
        return -1;
    }
    *start_time = (uint64_t)value;
    return 0;
}

static int process_owner(pid_t pid, uid_t *owner)
{
    char path[64];
    struct stat info;

    if (snprintf(path, sizeof(path), "/proc/%ld", (long)pid) <= 0
        || stat(path, &info) != 0)
        return -1;
    *owner = info.st_uid;
    return 0;
}

static int read_executable_path(pid_t pid, char *path, size_t capacity)
{
    char proc_path[64];
    ssize_t length;

    if (snprintf(proc_path, sizeof(proc_path), "/proc/%ld/exe", (long)pid)
        <= 0)
        return -1;
    do {
        length = readlink(proc_path, path, capacity - 1u);
    } while (length < 0 && errno == EINTR);
    if (length <= 0 || (size_t)length >= capacity - 1u) {
        if (length >= 0)
            errno = EOVERFLOW;
        return -1;
    }
    path[(size_t)length] = '\0';
    return 0;
}

static void capture_fingerprint(ksp_identity *identity, const struct stat *info)
{
    identity->executable_device = (uint64_t)info->st_dev;
    identity->executable_inode = (uint64_t)info->st_ino;
    identity->executable_size = (int64_t)info->st_size;
    identity->executable_mtime_seconds = (int64_t)info->st_mtim.tv_sec;
    identity->executable_mtime_nanoseconds = info->st_mtim.tv_nsec;
    identity->executable_ctime_seconds = (int64_t)info->st_ctim.tv_sec;
    identity->executable_ctime_nanoseconds = info->st_ctim.tv_nsec;
}

static bool fingerprint_matches(const ksp_identity *identity,
                                 const struct stat *info)
{
    return identity->executable_inode != 0u && S_ISREG(info->st_mode)
        && identity->executable_device == (uint64_t)info->st_dev
        && identity->executable_inode == (uint64_t)info->st_ino
        && identity->executable_size == (int64_t)info->st_size
        && identity->executable_mtime_seconds == (int64_t)info->st_mtim.tv_sec
        && identity->executable_mtime_nanoseconds == info->st_mtim.tv_nsec
        && identity->executable_ctime_seconds == (int64_t)info->st_ctim.tv_sec
        && identity->executable_ctime_nanoseconds == info->st_ctim.tv_nsec;
}

int ksp_identity_identify(pid_t pid, uid_t expected_uid,
                          uint64_t expected_start_time,
                          ksp_identity *identity)
{
    char proc_path[64];
    char executable_sha256[KSP_HASH_HEX_LENGTH + 1u];
    struct stat executable_info;
    struct stat current_executable_info;
    uint64_t current_start_time;
    uid_t current_owner;
    int descriptor = -1;
    int result = -1;

    if (identity != NULL)
        memset(identity, 0, sizeof(*identity));
    if (pid <= 0 || expected_uid == KSP_UID_ANY
        || expected_start_time == 0u || identity == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (process_owner(pid, &current_owner) != 0
        || current_owner != expected_uid
        || ksp_process_start_time(pid, &current_start_time) != 0
        || current_start_time != expected_start_time) {
        errno = ESRCH;
        return -1;
    }
    if (snprintf(proc_path, sizeof(proc_path), "/proc/%ld/exe", (long)pid)
        <= 0)
        return -1;
    do {
        descriptor = open(proc_path, O_RDONLY | O_CLOEXEC);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0 || fstat(descriptor, &executable_info) != 0
        || !S_ISREG(executable_info.st_mode)
        || read_executable_path(pid, identity->executable,
                                sizeof(identity->executable)) != 0)
        goto done;
    if (executable_path_is_protected(descriptor, identity->executable)) {
        if (ksp_identity_hash_path(identity->executable, identity->hash) != 0)
            goto done;
    } else if (hash_file(descriptor, executable_sha256) != 0
               || ksp_identity_hash_content(executable_sha256,
                                            identity->hash) != 0) {
        goto done;
    }
    if (process_owner(pid, &current_owner) != 0
        || current_owner != expected_uid
        || ksp_process_start_time(pid, &current_start_time) != 0
        || current_start_time != expected_start_time
        || stat(proc_path, &current_executable_info) != 0
        || current_executable_info.st_dev != executable_info.st_dev
        || current_executable_info.st_ino != executable_info.st_ino) {
        errno = ESRCH;
        goto done;
    }
    /* Cached revalidation trusts this fingerprint, so it must describe the
     * bytes that were hashed rather than a file written during hashing. */
    capture_fingerprint(identity, &executable_info);
    if (!fingerprint_matches(identity, &current_executable_info)) {
        errno = ESTALE;
        goto done;
    }
    identity->uid = expected_uid;
    identity->pid = pid;
    identity->start_time = expected_start_time;
    result = 0;

done:
    if (descriptor >= 0) {
        int saved_errno = errno;
        close(descriptor);
        errno = saved_errno;
    }
    if (result != 0)
        memset(identity, 0, sizeof(*identity));
    return result;
}

int ksp_identity_capture(pid_t pid, uid_t expected_uid,
                         ksp_identity *identity)
{
    uint64_t start_time;

    if (ksp_process_start_time(pid, &start_time) != 0)
        return -1;
    return ksp_identity_identify(pid, expected_uid, start_time, identity);
}

int ksp_identity_revalidate(const ksp_identity *expected,
                            ksp_identity *verified)
{
    ksp_identity local;

    if (expected == NULL || expected->pid <= 0 || expected->start_time == 0u
        || !ksp_hash_is_canonical(expected->hash)) {
        errno = EINVAL;
        return -1;
    }
    if (ksp_identity_identify(expected->pid, expected->uid,
                              expected->start_time, &local) != 0)
        return -1;
    if (strcmp(local.hash, expected->hash) != 0) {
        errno = ESTALE;
        return -1;
    }
    if (verified != NULL)
        *verified = local;
    return 0;
}

int ksp_identity_revalidate_cached(const ksp_identity *expected,
                                   ksp_identity *verified)
{
    char path[64];
    char executable[KSP_PATH_CAPACITY];
    struct stat info;
    uint64_t start_time;
    uid_t owner;

    if (expected == NULL || expected->pid <= 0 || expected->start_time == 0u
        || !ksp_hash_is_canonical(expected->hash)) {
        errno = EINVAL;
        return -1;
    }
    if (process_owner(expected->pid, &owner) != 0 || owner != expected->uid
        || ksp_process_start_time(expected->pid, &start_time) != 0
        || start_time != expected->start_time
        || snprintf(path, sizeof(path), "/proc/%ld/exe", (long)expected->pid) <= 0
        || stat(path, &info) != 0
        || read_executable_path(expected->pid, executable,
                                 sizeof(executable)) != 0) {
        errno = ESRCH;
        return -1;
    }
    if (!fingerprint_matches(expected, &info)
        || strcmp(expected->executable, executable) != 0)
        return ksp_identity_revalidate(expected, verified);
    if (process_owner(expected->pid, &owner) != 0 || owner != expected->uid
        || ksp_process_start_time(expected->pid, &start_time) != 0
        || start_time != expected->start_time || stat(path, &info) != 0
        || !fingerprint_matches(expected, &info)) {
        errno = ESTALE;
        return -1;
    }
    if (verified != NULL)
        *verified = *expected;
    return 0;
}
