#include "keysharp_permissions/permissions.h"

#include "internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define KSP_MARKER_PREFIX "grant-"
#define KSP_MARKER_SUFFIX ".grant"
#define KSP_MAX_CONFIGURED_RECORDS 8192u
#define KSP_RECORD_CAPACITY (KSP_PATH_CAPACITY + 256u)
#define KSP_MARKER_NAME_CAPACITY 160u

struct ksp_store {
    char *persistent_directory;
    char *runtime_directory;
    uid_t owner_uid;
    uint32_t read_scopes;
    uint32_t write_scopes;
    size_t max_records;
};

typedef struct ksp_marker_target {
    char name[KSP_MARKER_NAME_CAPACITY];
} ksp_marker_target;

static bool valid_directory_path(const char *path)
{
    size_t length;

    if (path == NULL || path[0] != '/'
        || (length = strlen(path)) <= 1u
        || length >= KSP_PATH_CAPACITY - 160u
        || path[length - 1u] == '/')
        return false;
    for (size_t index = 0u; index < length; index++) {
        unsigned char value = (unsigned char)path[index];

        if (value < 0x20u || value == 0x7fu
            || (value == (unsigned char)'/' && index + 1u < length
                && path[index + 1u] == '/'))
            return false;
    }
    return strstr(path, "/./") == NULL && strstr(path, "/../") == NULL
        && strcmp(path + length - 2u, "/.") != 0
        && (length < 3u || strcmp(path + length - 3u, "/..") != 0);
}

static bool valid_read_scopes(const ksp_store *store, uint32_t scopes)
{
    return store != NULL && scopes != 0u
        && (scopes & ~store->read_scopes) == 0u;
}

static bool valid_write_scopes(const ksp_store *store, uint32_t scopes)
{
    return store != NULL && scopes != 0u
        && (scopes & ~store->write_scopes) == 0u;
}

static int checked_snprintf(char *destination, size_t capacity,
                            const char *format, ...)
{
    va_list arguments;
    int length;

    va_start(arguments, format);
    length = vsnprintf(destination, capacity, format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= capacity) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int set_mode_and_verify(int descriptor, uid_t owner_uid, mode_t mode)
{
    struct stat info;

    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_uid != owner_uid) {
        errno = EACCES;
        return -1;
    }
    if ((info.st_mode & 07777) != mode) {
        if (geteuid() != owner_uid || fchmod(descriptor, mode) != 0
            || fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)
            || info.st_uid != owner_uid
            || (info.st_mode & 07777) != mode) {
            errno = EACCES;
            return -1;
        }
    }
    return 0;
}

static int verify_directory(const char *path, uid_t owner_uid, mode_t mode)
{
    struct stat info;

    if (lstat(path, &info) != 0 || !S_ISDIR(info.st_mode)
        || info.st_uid != owner_uid) {
        errno = EACCES;
        return -1;
    }
    if ((info.st_mode & 07777) != mode) {
        if (geteuid() != owner_uid || chmod(path, mode) != 0
            || lstat(path, &info) != 0 || !S_ISDIR(info.st_mode)
            || info.st_uid != owner_uid
            || (info.st_mode & 07777) != mode) {
            errno = EACCES;
            return -1;
        }
    }
    return 0;
}

static int prepare_directory(const char *path, uid_t owner_uid, mode_t mode)
{
    char child[KSP_PATH_CAPACITY];

    if (checked_snprintf(child, sizeof(child), "%s/x", path) != 0
        || ksp_internal_make_parent_directories(child, mode, owner_uid) != 0)
        return -1;
    return verify_directory(path, owner_uid, mode);
}

void ksp_store_config_init(ksp_store_config *config,
                           uint32_t write_scopes)
{
    if (config == NULL)
        return;
    memset(config, 0, sizeof(*config));
    config->persistent_directory = KSP_STORE_DIRECTORY;
    config->runtime_directory = KSP_RUNTIME_DIRECTORY;
    config->owner_uid = 0;
    config->read_scopes = write_scopes;
    config->write_scopes = write_scopes;
    config->max_records = KSP_DEFAULT_MAX_RECORDS;
}

int ksp_store_create(ksp_store **output, const ksp_store_config *config)
{
    ksp_store *store;

    if (output == NULL) {
        errno = EINVAL;
        return -1;
    }
    *output = NULL;
    if (config == NULL
        || !valid_directory_path(config->persistent_directory)
        || !valid_directory_path(config->runtime_directory)
        || strcmp(config->persistent_directory,
                  config->runtime_directory) == 0
        || config->owner_uid == KSP_UID_ANY
        || config->read_scopes == 0u
        || (config->read_scopes & ~KSP_SCOPE_ALL) != 0u
        || config->write_scopes == 0u
        || (config->write_scopes & ~KSP_SCOPE_ALL) != 0u
        || (config->write_scopes & ~config->read_scopes) != 0u
        || config->max_records == 0u
        || config->max_records > KSP_MAX_CONFIGURED_RECORDS) {
        errno = EINVAL;
        return -1;
    }
    store = calloc(1u, sizeof(*store));
    if (store == NULL)
        return -1;
    store->persistent_directory = strdup(config->persistent_directory);
    store->runtime_directory = strdup(config->runtime_directory);
    if (store->persistent_directory == NULL
        || store->runtime_directory == NULL) {
        ksp_store_destroy(store);
        return -1;
    }
    store->owner_uid = config->owner_uid;
    store->read_scopes = config->read_scopes;
    store->write_scopes = config->write_scopes;
    store->max_records = config->max_records;
    *output = store;
    return 0;
}

void ksp_store_destroy(ksp_store *store)
{
    if (store == NULL)
        return;
    free(store->persistent_directory);
    free(store->runtime_directory);
    free(store);
}

int ksp_store_prepare(ksp_store *store)
{
    if (store == NULL || geteuid() != store->owner_uid) {
        errno = EACCES;
        return -1;
    }
    if (prepare_directory(store->persistent_directory, store->owner_uid,
                          0700) != 0
        || prepare_directory(store->runtime_directory, store->owner_uid,
                             0755) != 0)
        return -1;
    return 0;
}

const char *ksp_store_persistent_directory(const ksp_store *store)
{
    return store == NULL ? NULL : store->persistent_directory;
}

const char *ksp_store_runtime_directory(const ksp_store *store)
{
    return store == NULL ? NULL : store->runtime_directory;
}

uint32_t ksp_store_read_scopes(const ksp_store *store)
{
    return store == NULL ? 0u : store->read_scopes;
}

uint32_t ksp_store_write_scopes(const ksp_store *store)
{
    return store == NULL ? 0u : store->write_scopes;
}

static int lock_file(const char *path, uid_t owner_uid, int operation)
{
    int descriptor;

    do {
        descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                          0600);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0)
        return -1;
    if (set_mode_and_verify(descriptor, owner_uid, 0600) != 0)
        goto error;
    while (flock(descriptor, operation) != 0) {
        if (errno != EINTR)
            goto error;
    }
    return descriptor;

error:
    {
        int saved_errno = errno;
        close(descriptor);
        errno = saved_errno;
    }
    return -1;
}

static void unlock_file(int descriptor)
{
    int saved_errno = errno;

    if (descriptor >= 0) {
        while (flock(descriptor, LOCK_UN) != 0 && errno == EINTR) {
        }
        close(descriptor);
    }
    errno = saved_errno;
}

static int lock_store(const ksp_store *store, int operation)
{
    char path[KSP_PATH_CAPACITY];

    if (store == NULL || geteuid() != store->owner_uid
        || prepare_directory(store->persistent_directory, store->owner_uid,
                             0700) != 0
        || checked_snprintf(path, sizeof(path), "%s/.lock",
                            store->persistent_directory) != 0)
        return -1;
    return lock_file(path, store->owner_uid, operation);
}

static int parse_decimal_uid(const char *text, size_t length, uid_t *uid)
{
    char buffer[64];
    char canonical[64];
    char *end;
    uintmax_t value;
    uid_t converted;

    if (text == NULL || uid == NULL || length == 0u
        || length >= sizeof(buffer)
        || (length > 1u && text[0] == '0'))
        return -1;
    for (size_t index = 0u; index < length; index++)
        if (text[index] < '0' || text[index] > '9')
            return -1;
    memcpy(buffer, text, length);
    buffer[length] = '\0';
    errno = 0;
    value = strtoumax(buffer, &end, 10);
    converted = (uid_t)value;
    if (errno != 0 || *end != '\0' || (uintmax_t)converted != value
        || converted == KSP_UID_ANY
        || snprintf(canonical, sizeof(canonical), "%ju", value) < 0
        || strcmp(canonical, buffer) != 0)
        return -1;
    *uid = converted;
    return 0;
}

static int parse_decimal_u64(const char *text, size_t length,
                             uint64_t *value)
{
    char buffer[64];
    char canonical[64];
    char *end;
    uintmax_t parsed;

    if (text == NULL || value == NULL || length == 0u
        || length >= sizeof(buffer)
        || (length > 1u && text[0] == '0'))
        return -1;
    for (size_t index = 0u; index < length; index++)
        if (text[index] < '0' || text[index] > '9')
            return -1;
    memcpy(buffer, text, length);
    buffer[length] = '\0';
    errno = 0;
    parsed = strtoumax(buffer, &end, 10);
    if (errno != 0 || *end != '\0' || parsed > UINT64_MAX
        || snprintf(canonical, sizeof(canonical), "%ju", parsed) < 0
        || strcmp(canonical, buffer) != 0)
        return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int parse_scope_hex(const char *text, uint32_t *scope)
{
    uint32_t value = 0u;

    if (text == NULL || scope == NULL)
        return -1;
    for (size_t index = 0u; index < 8u; index++) {
        unsigned char digit = (unsigned char)text[index];
        uint32_t nibble;

        if (digit >= (unsigned char)'0' && digit <= (unsigned char)'9')
            nibble = (uint32_t)(digit - (unsigned char)'0');
        else if (digit >= (unsigned char)'a' && digit <= (unsigned char)'f')
            nibble = (uint32_t)(digit - (unsigned char)'a') + 10u;
        else
            return -1;
        value = (value << 4u) | nibble;
    }
    if (value == 0u || (value & (value - 1u)) != 0u
        || (value & ~KSP_SCOPE_ALL) != 0u)
        return -1;
    *scope = value;
    return 0;
}

bool ksp_marker_parse_name(const char *name, uid_t *uid,
                           char app_hash[KSP_HASH_HEX_LENGTH + 1u],
                           uint32_t *scope)
{
    const size_t prefix_length = sizeof(KSP_MARKER_PREFIX) - 1u;
    const size_t suffix_length = sizeof(KSP_MARKER_SUFFIX) - 1u;
    const char *uid_end;
    const char *hash;
    const char *scope_text;
    size_t length;

    if (name == NULL || uid == NULL || app_hash == NULL || scope == NULL
        || strncmp(name, KSP_MARKER_PREFIX, prefix_length) != 0)
        return false;
    uid_end = strchr(name + prefix_length, '-');
    if (uid_end == NULL
        || parse_decimal_uid(name + prefix_length,
                             (size_t)(uid_end - name) - prefix_length,
                             uid) != 0)
        return false;
    hash = uid_end + 1;
    length = strlen(name);
    if (length != (size_t)(hash - name) + KSP_HASH_HEX_LENGTH + 1u + 8u
                      + suffix_length
        || hash[KSP_HASH_HEX_LENGTH] != '-'
        || strcmp(name + length - suffix_length, KSP_MARKER_SUFFIX) != 0)
        return false;
    for (size_t index = 0u; index < KSP_HASH_HEX_LENGTH; index++) {
        if (!((hash[index] >= '0' && hash[index] <= '9')
              || (hash[index] >= 'a' && hash[index] <= 'f')))
            return false;
    }
    scope_text = hash + KSP_HASH_HEX_LENGTH + 1u;
    if (parse_scope_hex(scope_text, scope) != 0)
        return false;
    memcpy(app_hash, hash, KSP_HASH_HEX_LENGTH);
    app_hash[KSP_HASH_HEX_LENGTH] = '\0';
    return true;
}

static int marker_path(const ksp_store *store, uid_t uid,
                       const char *app_hash, uint32_t scope,
                       char *path, size_t capacity)
{
    if (store == NULL || !ksp_hash_is_canonical(app_hash)
        || scope == 0u || (scope & (scope - 1u)) != 0u
        || (scope & ~KSP_SCOPE_ALL) != 0u) {
        errno = EINVAL;
        return -1;
    }
    return checked_snprintf(path, capacity, "%s/" KSP_MARKER_PREFIX
                            "%ju-%s-%08x" KSP_MARKER_SUFFIX,
                            store->persistent_directory, (uintmax_t)uid,
                            app_hash, scope);
}

static bool valid_display_path(const char *path, size_t length)
{
    if (path == NULL || length == 0u || length >= KSP_PATH_CAPACITY
        || path[0] != '/')
        return false;
    for (size_t index = 0u; index < length; index++) {
        unsigned char value = (unsigned char)path[index];
        if (value < 0x20u || value == 0x7fu)
            return false;
    }
    return true;
}

static int read_marker(const ksp_store *store, uid_t expected_uid,
                       const char *expected_hash, uint32_t expected_scope,
                       ksp_permission_entry *entry)
{
    char path[KSP_PATH_CAPACITY];
    char record[KSP_RECORD_CAPACITY];
    struct stat info;
    const char *cursor;
    const char *separator;
    const char *hash;
    const char *scope_text;
    const char *time_text;
    const char *executable;
    size_t hash_length;
    size_t scope_length;
    size_t time_length;
    size_t executable_length;
    uint64_t granted_at;
    uid_t uid;
    uint32_t scope;
    int descriptor;

    if (marker_path(store, expected_uid, expected_hash, expected_scope,
                    path, sizeof(path)) != 0)
        return -1;
    do {
        descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0)
        return errno == ENOENT ? 0 : -1;
    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_uid != store->owner_uid
        || (info.st_mode & 07777) != 0600 || info.st_size <= 0
        || (uintmax_t)info.st_size >= sizeof(record)
        || (uintmax_t)info.st_size
               < sizeof(KSP_MARKER_VERSION "\n") - 1u) {
        errno = EACCES;
        goto error;
    }
    if (!ksp_internal_read_all(descriptor, record, (size_t)info.st_size))
        goto error;
    if (memchr(record, '\0', (size_t)info.st_size) != NULL) {
        errno = EPROTO;
        goto error;
    }
    record[(size_t)info.st_size] = '\0';
    if (close(descriptor) != 0)
        return -1;
    descriptor = -1;
    if (memcmp(record, KSP_MARKER_VERSION "\n",
               sizeof(KSP_MARKER_VERSION "\n") - 1u) != 0) {
        errno = EPROTO;
        return -1;
    }
    cursor = record + sizeof(KSP_MARKER_VERSION "\n") - 1u;
    separator = strchr(cursor, '\t');
    if (separator == NULL
        || parse_decimal_uid(cursor, (size_t)(separator - cursor), &uid) != 0)
        goto malformed;
    hash = separator + 1;
    separator = strchr(hash, '\t');
    if (separator == NULL)
        goto malformed;
    hash_length = (size_t)(separator - hash);
    scope_text = separator + 1;
    separator = strchr(scope_text, '\t');
    if (separator == NULL)
        goto malformed;
    scope_length = (size_t)(separator - scope_text);
    time_text = separator + 1;
    separator = strchr(time_text, '\t');
    if (separator == NULL)
        goto malformed;
    time_length = (size_t)(separator - time_text);
    executable = separator + 1;
    executable_length = strlen(executable);
    if (hash_length != KSP_HASH_HEX_LENGTH || scope_length != 8u
        || executable_length < 2u
        || executable[executable_length - 1u] != '\n'
        || memchr(executable, '\n', executable_length - 1u) != NULL
        || parse_scope_hex(scope_text, &scope) != 0
        || parse_decimal_u64(time_text, time_length, &granted_at) != 0
        || !valid_display_path(executable, executable_length - 1u))
        goto malformed;
    executable_length--;
    if (uid != expected_uid || scope != expected_scope
        || memcmp(hash, expected_hash, KSP_HASH_HEX_LENGTH) != 0)
        goto malformed;
    if (entry != NULL) {
        memset(entry, 0, sizeof(*entry));
        entry->uid = uid;
        memcpy(entry->app_hash, hash, KSP_HASH_HEX_LENGTH);
        entry->app_hash[KSP_HASH_HEX_LENGTH] = '\0';
        memcpy(entry->executable, executable, executable_length);
        entry->executable[executable_length] = '\0';
        entry->scopes = scope;
        entry->granted_at_utc = granted_at;
    }
    return 1;

malformed:
    errno = EPROTO;
    return -1;

error:
    {
        int saved_errno = errno;
        close(descriptor);
        errno = saved_errno;
    }
    return -1;
}

static int sync_descriptor(int descriptor)
{
    int result;

    do {
        result = fsync(descriptor);
    } while (result != 0 && errno == EINTR);
    return result;
}

static int write_marker_locked(const ksp_store *store,
                               const ksp_identity *identity,
                               uint32_t scope)
{
    char final_path[KSP_PATH_CAPACITY];
    char temporary[KSP_PATH_CAPACITY];
    char display_path[KSP_PATH_CAPACITY];
    char record[KSP_RECORD_CAPACITY];
    struct stat info;
    time_t current_time;
    int descriptor = -1;
    int result = -1;
    int record_length;

    int existing = read_marker(store, identity->uid, identity->hash, scope,
                               NULL);
    if (existing != 0)
        return existing > 0 ? 0 : -1;
    if (marker_path(store, identity->uid, identity->hash, scope,
                    final_path, sizeof(final_path)) != 0
        || checked_snprintf(temporary, sizeof(temporary), "%s/.grant-%ju-XXXXXX",
                            store->persistent_directory,
                            (uintmax_t)identity->uid) != 0)
        return -1;
    ksp_sanitize_display_text(identity->executable, display_path,
                              sizeof(display_path));
    if (!valid_display_path(display_path, strlen(display_path))) {
        errno = EINVAL;
        return -1;
    }
    current_time = time(NULL);
    if (current_time < 0)
        return -1;
    record_length = snprintf(record, sizeof(record), KSP_MARKER_VERSION
                             "\n%ju\t%s\t%08x\t%ju\t%s\n",
                             (uintmax_t)identity->uid, identity->hash, scope,
                             (uintmax_t)current_time, display_path);
    if (record_length <= 0 || (size_t)record_length >= sizeof(record)) {
        errno = EOVERFLOW;
        return -1;
    }
    descriptor = mkstemp(temporary);
    if (descriptor < 0 || fchmod(descriptor, 0600) != 0
        || fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_uid != store->owner_uid
        || (info.st_mode & 07777) != 0600
        || !ksp_internal_write_all(descriptor, record, (size_t)record_length)
        || sync_descriptor(descriptor) != 0)
        goto done;
    if (close(descriptor) != 0) {
        descriptor = -1;
        goto done;
    }
    descriptor = -1;
    if (rename(temporary, final_path) != 0
        || ksp_internal_fsync_directory(store->persistent_directory) != 0)
        goto done;
    result = 0;

done:
    if (descriptor >= 0)
        close(descriptor);
    if (result != 0)
        (void)unlink(temporary);
    return result;
}

int ksp_store_generation_path(const ksp_store *store, uid_t uid,
                              char *path, size_t capacity)
{
    if (store == NULL || uid == KSP_UID_ANY || path == NULL
        || capacity == 0u) {
        errno = EINVAL;
        return -1;
    }
    return checked_snprintf(path, capacity, "%s/revoke-%ju.generation",
                            store->runtime_directory, (uintmax_t)uid);
}

int ksp_store_generation(const ksp_store *store, uid_t uid,
                         uint64_t *generation)
{
    char path[KSP_PATH_CAPACITY];
    struct stat info;
    uint64_t value;
    unsigned char trailing;
    ssize_t count;
    int descriptor;

    if (generation != NULL)
        *generation = 0u;
    if (store == NULL || uid == KSP_UID_ANY || generation == NULL
        || ksp_store_generation_path(store, uid, path, sizeof(path)) != 0) {
        errno = EINVAL;
        return -1;
    }
    do {
        descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0)
        return errno == ENOENT ? 0 : -1;
    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_uid != store->owner_uid
        || (info.st_mode & 07777) != 0644
        || !ksp_internal_read_all(descriptor, &value, sizeof(value)))
        goto malformed;
    do {
        count = read(descriptor, &trailing, sizeof(trailing));
    } while (count < 0 && errno == EINTR);
    if (count != 0)
        goto malformed;
    if (close(descriptor) != 0)
        return -1;
    *generation = value;
    return 0;

malformed:
    {
        int saved_errno = errno == 0 ? EPROTO : errno;
        close(descriptor);
        errno = saved_errno;
    }
    return -1;
}

static int bump_generation(const ksp_store *store, uid_t uid)
{
    char path[KSP_PATH_CAPACITY];
    char lock_path[KSP_PATH_CAPACITY];
    char temporary[KSP_PATH_CAPACITY];
    struct stat info;
    uint64_t generation;
    int lock = -1;
    int descriptor = -1;
    int result = -1;

    if (geteuid() != store->owner_uid
        || prepare_directory(store->runtime_directory, store->owner_uid,
                             0755) != 0
        || ksp_store_generation_path(store, uid, path, sizeof(path)) != 0
        || checked_snprintf(lock_path, sizeof(lock_path),
                            "%s/.revoke-%ju.lock", store->runtime_directory,
                            (uintmax_t)uid) != 0
        || checked_snprintf(temporary, sizeof(temporary),
                            "%s/.revoke-%ju-XXXXXX",
                            store->runtime_directory, (uintmax_t)uid) != 0)
        return -1;
    lock = lock_file(lock_path, store->owner_uid, LOCK_EX);
    if (lock < 0 || ksp_store_generation(store, uid, &generation) != 0)
        goto done;
    generation++;
    if (generation == 0u)
        generation = 1u;
    descriptor = mkstemp(temporary);
    if (descriptor < 0 || fchmod(descriptor, 0644) != 0
        || fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_uid != store->owner_uid
        || (info.st_mode & 07777) != 0644
        || !ksp_internal_write_all(descriptor, &generation,
                                   sizeof(generation))
        || sync_descriptor(descriptor) != 0)
        goto done;
    if (close(descriptor) != 0) {
        descriptor = -1;
        goto done;
    }
    descriptor = -1;
    if (rename(temporary, path) != 0
        || ksp_internal_fsync_directory(store->runtime_directory) != 0)
        goto done;
    result = 0;

done:
    if (descriptor >= 0)
        close(descriptor);
    if (result != 0)
        (void)unlink(temporary);
    unlock_file(lock);
    return result;
}

static int check_locked(const ksp_store *store, uid_t uid,
                        const char *app_hash, uint32_t scopes,
                        uint32_t *allowed)
{
    *allowed = 0u;
    for (uint32_t bit = 1u; bit <= KSP_SCOPE_CLIPBOARD_MONITORING;
         bit <<= 1u) {
        int found;

        if ((scopes & bit) == 0u)
            continue;
        found = read_marker(store, uid, app_hash, bit, NULL);
        if (found < 0) {
            *allowed = 0u;
            return -1;
        }
        if (found > 0)
            *allowed |= bit;
    }
    return 0;
}

int ksp_store_check(const ksp_store *store, uid_t uid, const char *app_hash,
                    uint32_t scopes, uint32_t *allowed)
{
    int lock;
    int result;

    if (allowed != NULL)
        *allowed = 0u;
    if (uid == KSP_UID_ANY || !valid_read_scopes(store, scopes)
        || !ksp_hash_is_canonical(app_hash)
        || allowed == NULL) {
        errno = EINVAL;
        return -1;
    }
    lock = lock_store(store, LOCK_SH);
    if (lock < 0)
        return -1;
    result = check_locked(store, uid, app_hash, scopes, allowed);
    unlock_file(lock);
    return result;
}

int ksp_store_check_at_generation(const ksp_store *store, uid_t uid,
                                  const char *app_hash, uint32_t scopes,
                                  uint32_t *allowed, uint64_t *generation)
{
    int lock;
    int result;

    if (allowed != NULL)
        *allowed = 0u;
    if (generation != NULL)
        *generation = 0u;
    if (uid == KSP_UID_ANY || !valid_read_scopes(store, scopes)
        || !ksp_hash_is_canonical(app_hash)
        || allowed == NULL || generation == NULL) {
        errno = EINVAL;
        return -1;
    }
    lock = lock_store(store, LOCK_SH);
    if (lock < 0)
        return -1;
    result = check_locked(store, uid, app_hash, scopes, allowed);
    if (result == 0)
        result = ksp_store_generation(store, uid, generation);
    unlock_file(lock);
    return result;
}

int ksp_store_grant_if_generation(ksp_store *store,
                                  const ksp_identity *identity,
                                  uint32_t scopes,
                                  uint64_t expected_generation)
{
    uint64_t generation;
    size_t executable_length;
    int lock;
    int result = -1;

    if (!valid_write_scopes(store, scopes) || identity == NULL
        || identity->uid == KSP_UID_ANY
        || identity->pid <= 0 || identity->start_time == 0u
        || !ksp_hash_is_canonical(identity->hash)
        || (executable_length = strnlen(identity->executable,
                                       sizeof(identity->executable))) == 0u
        || executable_length == sizeof(identity->executable)
        || identity->executable[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    lock = lock_store(store, LOCK_EX);
    if (lock < 0)
        return -1;
    if (ksp_store_generation(store, identity->uid, &generation) != 0)
        goto done;
    if (generation != expected_generation) {
        result = 1;
        goto done;
    }
    for (uint32_t bit = 1u; bit <= KSP_SCOPE_CLIPBOARD_MONITORING;
         bit <<= 1u) {
        if ((scopes & bit) != 0u
            && write_marker_locked(store, identity, bit) != 0)
            goto done;
    }
    result = 0;

done:
    unlock_file(lock);
    return result;
}

static int collect_uid_targets(const ksp_store *store, uid_t uid,
                               uint32_t scopes, ksp_marker_target **targets,
                               size_t *count)
{
    size_t capacity = 0u;
    size_t inspected = 0u;
    size_t target_limit = store->max_records * 8u;
    size_t inspection_limit = target_limit + 64u;
    ksp_marker_target *items = NULL;
    DIR *directory;
    int result = -1;

    *targets = NULL;
    *count = 0u;
    directory = opendir(store->persistent_directory);
    if (directory == NULL)
        return -1;
    for (;;) {
        struct dirent *item;
        char hash[KSP_HASH_HEX_LENGTH + 1u];
        uid_t marker_uid;
        uint32_t scope;

        errno = 0;
        item = readdir(directory);
        if (item == NULL) {
            if (errno != 0)
                goto done;
            break;
        }
        if (strcmp(item->d_name, ".") == 0
            || strcmp(item->d_name, "..") == 0)
            continue;
        if (++inspected > inspection_limit) {
            errno = EOVERFLOW;
            goto done;
        }
        if (!ksp_marker_parse_name(item->d_name, &marker_uid, hash, &scope)
            || marker_uid != uid || (scopes & scope) == 0u)
            continue;
        if (read_marker(store, marker_uid, hash, scope, NULL) <= 0)
            goto done;
        if (*count == target_limit) {
            errno = EOVERFLOW;
            goto done;
        }
        if (*count == capacity) {
            size_t expanded_capacity = capacity == 0u ? 16u : capacity * 2u;
            ksp_marker_target *expanded;

            if (expanded_capacity > target_limit)
                expanded_capacity = target_limit;
            expanded = realloc(items, expanded_capacity * sizeof(*items));
            if (expanded == NULL)
                goto done;
            items = expanded;
            capacity = expanded_capacity;
        }
        if (strlen(item->d_name) >= sizeof(items[*count].name)) {
            errno = EOVERFLOW;
            goto done;
        }
        strcpy(items[*count].name, item->d_name);
        (*count)++;
    }
    *targets = items;
    items = NULL;
    result = 0;

done:
    {
        int saved_errno = errno;
        closedir(directory);
        free(items);
        errno = saved_errno;
    }
    return result;
}

static int revoke_locked(ksp_store *store, uid_t uid, const char *app_hash,
                         uint32_t scopes)
{
    ksp_marker_target *targets = NULL;
    size_t count = 0u;
    int result = -1;

    if (app_hash == NULL
        && collect_uid_targets(store, uid, scopes, &targets, &count) != 0)
        return -1;
    if (bump_generation(store, uid) != 0)
        goto done;
    if (app_hash != NULL) {
        for (uint32_t bit = 1u; bit <= KSP_SCOPE_CLIPBOARD_MONITORING;
             bit <<= 1u) {
            char path[KSP_PATH_CAPACITY];

            if ((scopes & bit) == 0u)
                continue;
            if (marker_path(store, uid, app_hash, bit, path, sizeof(path)) != 0
                || (unlink(path) != 0 && errno != ENOENT))
                goto done;
        }
    } else {
        for (size_t index = 0u; index < count; index++) {
            char path[KSP_PATH_CAPACITY];

            if (checked_snprintf(path, sizeof(path), "%s/%s",
                                 store->persistent_directory,
                                 targets[index].name) != 0
                || (unlink(path) != 0 && errno != ENOENT))
                goto done;
        }
    }
    if (ksp_internal_fsync_directory(store->persistent_directory) != 0
        || bump_generation(store, uid) != 0)
        goto done;
    result = 0;

done:
    free(targets);
    return result;
}

int ksp_store_revoke(ksp_store *store, uid_t uid, const char *app_hash,
                     uint32_t scopes)
{
    int lock;
    int result;

    if (uid == KSP_UID_ANY || !valid_write_scopes(store, scopes)
        || !ksp_hash_is_canonical(app_hash)) {
        errno = EINVAL;
        return -1;
    }
    lock = lock_store(store, LOCK_EX);
    if (lock < 0)
        return -1;
    result = revoke_locked(store, uid, app_hash, scopes);
    unlock_file(lock);
    return result;
}

int ksp_store_revoke_uid(ksp_store *store, uid_t uid, uint32_t scopes)
{
    int lock;
    int result;

    if (uid == KSP_UID_ANY || !valid_write_scopes(store, scopes)) {
        errno = EINVAL;
        return -1;
    }
    lock = lock_store(store, LOCK_EX);
    if (lock < 0)
        return -1;
    result = revoke_locked(store, uid, NULL, scopes);
    unlock_file(lock);
    return result;
}

static int compare_entries(const void *left, const void *right)
{
    const ksp_permission_entry *first = left;
    const ksp_permission_entry *second = right;

    if (first->uid < second->uid)
        return -1;
    if (first->uid > second->uid)
        return 1;
    return strcmp(first->app_hash, second->app_hash);
}

int ksp_store_list(const ksp_store *store, uid_t uid_filter,
                   ksp_permission_entry **entries, size_t *count)
{
    size_t capacity = 0u;
    size_t inspected = 0u;
    size_t inspection_limit;
    ksp_permission_entry *records = NULL;
    DIR *directory = NULL;
    int lock;
    int result = -1;

    if (entries == NULL || count == NULL) {
        errno = EINVAL;
        return -1;
    }
    *entries = NULL;
    *count = 0u;
    if (store == NULL) {
        errno = EINVAL;
        return -1;
    }
    inspection_limit = store->max_records * 8u + 64u;
    lock = lock_store(store, LOCK_SH);
    if (lock < 0)
        return -1;
    directory = opendir(store->persistent_directory);
    if (directory == NULL)
        goto done;
    for (;;) {
        struct dirent *item;
        ksp_permission_entry marker;
        char hash[KSP_HASH_HEX_LENGTH + 1u];
        uid_t uid;
        uint32_t scope;
        size_t target;

        errno = 0;
        item = readdir(directory);
        if (item == NULL) {
            if (errno != 0)
                goto done;
            break;
        }
        if (strcmp(item->d_name, ".") == 0
            || strcmp(item->d_name, "..") == 0)
            continue;
        if (++inspected > inspection_limit) {
            errno = EOVERFLOW;
            goto done;
        }
        if (!ksp_marker_parse_name(item->d_name, &uid, hash, &scope)
            || (store->write_scopes & scope) == 0u
            || (uid_filter != KSP_UID_ANY && uid_filter != uid))
            continue;
        if (read_marker(store, uid, hash, scope, &marker) <= 0)
            goto done;
        for (target = 0u; target < *count; target++) {
            if (records[target].uid == uid
                && strcmp(records[target].app_hash, hash) == 0)
                break;
        }
        if (target == *count) {
            ksp_permission_entry *expanded;

            if (*count == store->max_records) {
                errno = EOVERFLOW;
                goto done;
            }
            if (*count == capacity) {
                size_t expanded_capacity = capacity == 0u ? 16u : capacity * 2u;

                if (expanded_capacity > store->max_records)
                    expanded_capacity = store->max_records;
                expanded = realloc(records,
                                   expanded_capacity * sizeof(*records));
                if (expanded == NULL)
                    goto done;
                records = expanded;
                capacity = expanded_capacity;
            }
            records[target] = marker;
            (*count)++;
        } else {
            records[target].scopes |= scope;
            if (marker.granted_at_utc > records[target].granted_at_utc
                || (marker.granted_at_utc == records[target].granted_at_utc
                    && strcmp(marker.executable,
                              records[target].executable) < 0)) {
                records[target].granted_at_utc = marker.granted_at_utc;
                strcpy(records[target].executable, marker.executable);
            }
        }
    }
    if (closedir(directory) != 0) {
        directory = NULL;
        goto done;
    }
    directory = NULL;
    if (*count > 1u)
        qsort(records, *count, sizeof(*records), compare_entries);
    *entries = records;
    records = NULL;
    result = 0;

done:
    {
        int saved_errno = errno;
        if (directory != NULL)
            closedir(directory);
        free(records);
        if (result != 0)
            *count = 0u;
        unlock_file(lock);
        errno = saved_errno;
    }
    return result;
}

void ksp_store_list_free(ksp_permission_entry *entries)
{
    free(entries);
}

int ksp_prompt_lock_acquire(const ksp_store *store, uid_t uid,
                            const char *app_hash, ksp_cancel_fn cancelled,
                            void *user_data)
{
    char path[KSP_PATH_CAPACITY];
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000L };
    int descriptor;

    if (store == NULL || uid == KSP_UID_ANY
        || !ksp_hash_is_canonical(app_hash)) {
        errno = EINVAL;
        return -1;
    }
    if (ksp_internal_cancelled(cancelled, user_data)) {
        errno = ECANCELED;
        return -1;
    }
    if (geteuid() != store->owner_uid
        || prepare_directory(store->runtime_directory, store->owner_uid,
                             0755) != 0
        || checked_snprintf(path, sizeof(path), "%s/.prompt-%ju-%s.lock",
                            store->runtime_directory, (uintmax_t)uid,
                            app_hash) != 0)
        return -1;
    do {
        descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                          0600);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0
        || set_mode_and_verify(descriptor, store->owner_uid, 0600) != 0)
        goto error;
    for (;;) {
        if (flock(descriptor, LOCK_EX | LOCK_NB) == 0)
            break;
        if (errno == EINTR)
            continue;
        if (errno != EWOULDBLOCK && errno != EAGAIN)
            goto error;
        if (ksp_internal_cancelled(cancelled, user_data)) {
            errno = ECANCELED;
            goto error;
        }
        struct timespec remaining = delay;
        while (nanosleep(&remaining, &remaining) != 0) {
            if (errno != EINTR)
                goto error;
            if (ksp_internal_cancelled(cancelled, user_data)) {
                errno = ECANCELED;
                goto error;
            }
        }
    }
    if (ksp_internal_cancelled(cancelled, user_data)) {
        errno = ECANCELED;
        unlock_file(descriptor);
        return -1;
    }
    return descriptor;

error:
    if (descriptor >= 0) {
        int saved_errno = errno;
        close(descriptor);
        errno = saved_errno;
    }
    return -1;
}

void ksp_prompt_lock_release(int descriptor)
{
    unlock_file(descriptor);
}
