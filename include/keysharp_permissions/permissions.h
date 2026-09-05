#ifndef KEYSHARP_PERMISSIONS_PERMISSIONS_H
#define KEYSHARP_PERMISSIONS_PERMISSIONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KSP_HASH_HEX_LENGTH 64u
#define KSP_PATH_CAPACITY 4096u
#define KSP_IDENTITY_DOMAIN "org.keysharp.app-identity-v1"
#define KSP_STORE_DIRECTORY "/var/lib/keysharp-permissions/v1"
#define KSP_RUNTIME_DIRECTORY "/run/keysharp-permissions"
#define KSP_MARKER_VERSION "keysharp-permission-v1"
#define KSP_UID_ANY ((uid_t)-1)
#define KSP_DEFAULT_MAX_RECORDS 4096u

typedef enum ksp_scope {
    KSP_SCOPE_INPUT_MONITORING = 0x00000001u,
    KSP_SCOPE_INPUT_CONTROL = 0x00000002u,
    KSP_SCOPE_WINDOW_MONITORING = 0x00000004u,
    KSP_SCOPE_WINDOW_CONTROL = 0x00000008u,
    KSP_SCOPE_SCREEN_CAPTURE = 0x00000010u,
    KSP_SCOPE_AUDIO_CAPTURE = 0x00000020u,
    KSP_SCOPE_CAMERA_CAPTURE = 0x00000040u,
    KSP_SCOPE_CLIPBOARD_MONITORING = 0x00000080u,
    KSP_SCOPE_ALL = 0x000000ffu,
} ksp_scope;

const char *ksp_scope_name(uint32_t scope);
const char *ksp_scope_display_name(uint32_t scope);
uint32_t ksp_scope_from_name(const char *name);
int ksp_scopes_format(uint32_t scopes, bool display_names,
                      char *destination, size_t capacity);
bool ksp_hash_is_canonical(const char *hash);

typedef struct ksp_identity {
    uid_t uid;
    pid_t pid;
    uint64_t start_time;
    char executable[KSP_PATH_CAPACITY];
    char hash[KSP_HASH_HEX_LENGTH + 1u];
    uint64_t executable_device;
    uint64_t executable_inode;
    int64_t executable_size;
    int64_t executable_mtime_seconds;
    int64_t executable_mtime_nanoseconds;
    int64_t executable_ctime_seconds;
    int64_t executable_ctime_nanoseconds;
} ksp_identity;

int ksp_process_start_time(pid_t pid, uint64_t *start_time);
int ksp_identity_identify(pid_t pid, uid_t expected_uid,
                          uint64_t expected_start_time,
                          ksp_identity *identity);
int ksp_identity_capture(pid_t pid, uid_t expected_uid,
                         ksp_identity *identity);
int ksp_identity_revalidate(const ksp_identity *expected,
                            ksp_identity *verified);
/* Reuses the captured digest only while process and executable metadata agree.
 * Interactive authorization still uses the complete revalidation above. */
int ksp_identity_revalidate_cached(const ksp_identity *expected,
                                   ksp_identity *verified);
int ksp_identity_hash_path(const char *absolute_path,
                           char hash[KSP_HASH_HEX_LENGTH + 1u]);
int ksp_identity_hash_content(
    const char executable_sha256[KSP_HASH_HEX_LENGTH + 1u],
    char hash[KSP_HASH_HEX_LENGTH + 1u]);

typedef struct ksp_store ksp_store;

typedef struct ksp_store_config {
    const char *persistent_directory;
    const char *runtime_directory;
    uid_t owner_uid;
    /* Checks may request read_scopes. Administration, listing, grants, and
     * revocation are restricted to write_scopes. */
    uint32_t read_scopes;
    uint32_t write_scopes;
    /* Caps both returned identities and directory traversal work. */
    size_t max_records;
} ksp_store_config;

typedef struct ksp_permission_entry {
    uid_t uid;
    char app_hash[KSP_HASH_HEX_LENGTH + 1u];
    char executable[KSP_PATH_CAPACITY];
    uint32_t scopes;
    uint64_t granted_at_utc;
} ksp_permission_entry;

typedef bool (*ksp_cancel_fn)(void *user_data);

void ksp_store_config_init(ksp_store_config *config,
                           uint32_t write_scopes);
int ksp_store_create(ksp_store **store, const ksp_store_config *config);
void ksp_store_destroy(ksp_store *store);
int ksp_store_prepare(ksp_store *store);
const char *ksp_store_persistent_directory(const ksp_store *store);
const char *ksp_store_runtime_directory(const ksp_store *store);
uint32_t ksp_store_read_scopes(const ksp_store *store);
uint32_t ksp_store_write_scopes(const ksp_store *store);

int ksp_store_check(const ksp_store *store, uid_t uid, const char *app_hash,
                    uint32_t scopes, uint32_t *allowed);
int ksp_store_check_at_generation(const ksp_store *store, uid_t uid,
                                  const char *app_hash, uint32_t scopes,
                                  uint32_t *allowed, uint64_t *generation);
int ksp_store_generation_path(const ksp_store *store, uid_t uid,
                              char *path, size_t capacity);
int ksp_store_generation(const ksp_store *store, uid_t uid,
                         uint64_t *generation);

/* Returns 1 if the expected generation changed, -1 on error, and 0 after
 * persisting the grant. */
int ksp_store_grant_if_generation(ksp_store *store,
                                  const ksp_identity *identity,
                                  uint32_t scopes,
                                  uint64_t expected_generation);
/* Checks cancellation after the store lock and before each marker commit.
 * Cancellation returns -1 with ECANCELED. Already committed scopes remain. */
int ksp_store_grant_if_generation_cancelled(ksp_store *store,
    const ksp_identity *identity, uint32_t scopes, uint64_t expected_generation,
    ksp_cancel_fn cancelled, void *user_data);
int ksp_store_revoke(ksp_store *store, uid_t uid, const char *app_hash,
                     uint32_t scopes);
int ksp_store_revoke_uid(ksp_store *store, uid_t uid, uint32_t scopes);

int ksp_store_list(const ksp_store *store, uid_t uid_filter,
                   ksp_permission_entry **entries, size_t *count);
void ksp_store_list_free(ksp_permission_entry *entries);

/* The returned descriptor owns an exclusive cross-authority prompt lock.
 * Closing it through ksp_prompt_lock_release releases the lock. */
int ksp_prompt_lock_acquire(const ksp_store *store, uid_t uid,
                            const char *app_hash, ksp_cancel_fn cancelled,
                            void *user_data);
void ksp_prompt_lock_release(int descriptor);

bool ksp_marker_parse_name(const char *name, uid_t *uid,
                           char app_hash[KSP_HASH_HEX_LENGTH + 1u],
                           uint32_t *scope);
void ksp_sanitize_display_text(const char *source, char *destination,
                               size_t capacity);

typedef enum ksp_polkit_result {
    KSP_POLKIT_DENIED = 0,
    KSP_POLKIT_GRANTED = 1,
    KSP_POLKIT_UNAVAILABLE = 2,
    KSP_POLKIT_CANCELLED = 3,
    KSP_POLKIT_IDENTITY_CHANGED = 4,
} ksp_polkit_result;

typedef struct ksp_polkit_config {
    const char *pkcheck_path;
    const char *action_id;
    const char *scope_detail_key;
    const char *scope_names_detail_key;
    uint32_t allowed_scopes;
    unsigned int timeout_seconds;
} ksp_polkit_config;

ksp_polkit_result ksp_polkit_authorize(
    const ksp_polkit_config *config,
    const ksp_identity *identity,
    uint32_t scopes,
    ksp_cancel_fn cancelled,
    void *user_data);
ksp_polkit_result ksp_polkit_result_from_exit(int exit_code);

#ifdef __cplusplus
}
#endif

#endif
