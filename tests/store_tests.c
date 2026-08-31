#include "test.h"

#include "keysharp_permissions/permissions.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct cancellation_state {
    unsigned int calls;
} cancellation_state;

static bool cancel_on_second_check(void *user_data)
{
    cancellation_state *state = user_data;
    state->calls++;
    return state->calls >= 2u;
}

static int remove_tree(const char *path)
{
    DIR *directory = opendir(path);

    if (directory == NULL)
        return errno == ENOENT ? 0 : -1;
    for (;;) {
        struct dirent *item = readdir(directory);
        char child[KSP_PATH_CAPACITY];
        struct stat info;
        int length;

        if (item == NULL)
            break;
        if (strcmp(item->d_name, ".") == 0
            || strcmp(item->d_name, "..") == 0)
            continue;
        length = snprintf(child, sizeof(child), "%s/%s", path, item->d_name);
        if (length <= 0 || (size_t)length >= sizeof(child)
            || lstat(child, &info) != 0) {
            closedir(directory);
            return -1;
        }
        if (S_ISDIR(info.st_mode)) {
            if (remove_tree(child) != 0) {
                closedir(directory);
                return -1;
            }
        } else if (unlink(child) != 0) {
            closedir(directory);
            return -1;
        }
    }
    if (closedir(directory) != 0)
        return -1;
    return rmdir(path);
}

static void make_identity(ksp_identity *identity, char hash_character,
                          const char *executable)
{
    memset(identity, 0, sizeof(*identity));
    identity->uid = getuid();
    identity->pid = getpid();
    identity->start_time = 1u;
    memset(identity->hash, hash_character, KSP_HASH_HEX_LENGTH);
    identity->hash[KSP_HASH_HEX_LENGTH] = '\0';
    snprintf(identity->executable, sizeof(identity->executable), "%s",
             executable);
}

static int verify_marker_header(const char *directory,
                                const ksp_identity *identity,
                                uint32_t scope)
{
    char path[KSP_PATH_CAPACITY];
    char buffer[128];
    int length;
    int descriptor;
    ssize_t count;

    length = snprintf(path, sizeof(path), "%s/grant-%ju-%s-%08x.grant",
                      directory, (uintmax_t)identity->uid, identity->hash,
                      scope);
    if (length <= 0 || (size_t)length >= sizeof(path))
        return -1;
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return -1;
    count = read(descriptor, buffer, sizeof(buffer) - 1u);
    close(descriptor);
    if (count <= 0)
        return -1;
    buffer[(size_t)count] = '\0';
    return strncmp(buffer, KSP_MARKER_VERSION "\n",
                   sizeof(KSP_MARKER_VERSION "\n") - 1u) == 0
        ? 0
        : -1;
}

static int write_malformed_marker(const char *directory,
                                  const ksp_identity *identity,
                                  uint32_t scope, char *path,
                                  size_t path_capacity)
{
    static const char malformed[] = "keysharp-permission-v1\nmalformed\n";
    int length = snprintf(path, path_capacity,
                          "%s/grant-%ju-%s-%08x.grant", directory,
                          (uintmax_t)identity->uid, identity->hash, scope);
    int descriptor;

    if (length <= 0 || (size_t)length >= path_capacity)
        return -1;
    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC
                            | O_NOFOLLOW,
                      0600);
    if (descriptor < 0
        || write(descriptor, malformed, sizeof(malformed) - 1u)
               != (ssize_t)(sizeof(malformed) - 1u)) {
        if (descriptor >= 0)
            close(descriptor);
        return -1;
    }
    return close(descriptor);
}

int ksp_test_store(void)
{
    const uint32_t input_scopes = KSP_SCOPE_INPUT_MONITORING
        | KSP_SCOPE_INPUT_CONTROL;
    const uint32_t desktop_scopes = KSP_SCOPE_WINDOW_MONITORING
        | KSP_SCOPE_WINDOW_CONTROL | KSP_SCOPE_SCREEN_CAPTURE
        | KSP_SCOPE_AUDIO_CAPTURE | KSP_SCOPE_CAMERA_CAPTURE
        | KSP_SCOPE_CLIPBOARD_MONITORING;
    char resolved_home[KSP_PATH_CAPACITY];
    char root[KSP_PATH_CAPACITY];
    char persistent[KSP_PATH_CAPACITY];
    char runtime[KSP_PATH_CAPACITY];
    char malformed_path[KSP_PATH_CAPACITY];
    const char *home = getenv("HOME");
    ksp_store_config input_config;
    ksp_store_config desktop_config;
    ksp_store_config bounded_config;
    ksp_store *input = NULL;
    ksp_store *desktop = NULL;
    ksp_store *bounded = NULL;
    ksp_permission_entry *entries = NULL;
    ksp_identity first;
    ksp_identity second;
    ksp_identity malformed;
    uint32_t allowed;
    uint64_t generation;
    size_t count;
    int prompt_lock;
    int status;
    pid_t child;

    CHECK(home != NULL && realpath(home, resolved_home) != NULL);
    CHECK(snprintf(root, sizeof(root), "%s/.ksp-test-XXXXXX", resolved_home)
          > 0);
    CHECK(mkdtemp(root) != NULL);
    CHECK(snprintf(persistent, sizeof(persistent), "%s/persistent", root) > 0);
    CHECK(snprintf(runtime, sizeof(runtime), "%s/runtime", root) > 0);

    ksp_store_config_init(&input_config, input_scopes);
    input_config.persistent_directory = persistent;
    input_config.runtime_directory = runtime;
    input_config.owner_uid = geteuid();
    input_config.max_records = 4u;
    desktop_config = input_config;
    desktop_config.write_scopes = desktop_scopes;
    desktop_config.read_scopes = desktop_scopes | KSP_SCOPE_INPUT_CONTROL;
    CHECK(ksp_store_create(&input, &input_config) == 0);
    CHECK(ksp_store_create(&desktop, &desktop_config) == 0);
    CHECK(ksp_store_prepare(input) == 0);
    CHECK(ksp_store_prepare(desktop) == 0);
    make_identity(&first, 'a', "/opt/apps/first");
    make_identity(&second, 'b', "/opt/apps/second");
    make_identity(&malformed, 'c', "/opt/apps/malformed");

    CHECK(ksp_store_generation(input, getuid(), &generation) == 0);
    CHECK(generation == 0u);
    CHECK(ksp_store_grant_if_generation(input, &first,
                                        KSP_SCOPE_INPUT_MONITORING,
                                        generation) == 0);
    CHECK(ksp_store_grant_if_generation(desktop, &first,
                                        KSP_SCOPE_SCREEN_CAPTURE,
                                        generation) == 0);
    CHECK(verify_marker_header(persistent, &first,
                               KSP_SCOPE_INPUT_MONITORING) == 0);
    CHECK(ksp_store_check(input, getuid(), first.hash, input_scopes,
                          &allowed) == 0);
    CHECK(allowed == KSP_SCOPE_INPUT_MONITORING);
    CHECK(ksp_store_check(desktop, getuid(), first.hash, desktop_scopes,
                          &allowed) == 0);
    CHECK(allowed == KSP_SCOPE_SCREEN_CAPTURE);

    CHECK(ksp_store_revoke(input, getuid(), first.hash,
                           KSP_SCOPE_INPUT_CONTROL) == 0);
    CHECK(ksp_store_generation(input, getuid(), &generation) == 0);
    CHECK(generation == 2u);
    CHECK(ksp_store_grant_if_generation(input, &first,
                                        KSP_SCOPE_INPUT_CONTROL, 0u) == 1);
    CHECK(ksp_store_grant_if_generation(input, &first,
                                        KSP_SCOPE_INPUT_CONTROL,
                                        generation) == 0);
    CHECK(ksp_store_check(desktop, getuid(), first.hash,
                          KSP_SCOPE_INPUT_CONTROL, &allowed) == 0);
    CHECK(allowed == KSP_SCOPE_INPUT_CONTROL);
    errno = 0;
    CHECK(ksp_store_revoke(desktop, getuid(), first.hash,
                           KSP_SCOPE_INPUT_CONTROL) != 0);
    CHECK(errno == EINVAL);
    CHECK(ksp_store_revoke(input, getuid(), first.hash,
                           KSP_SCOPE_INPUT_MONITORING) == 0);
    CHECK(ksp_store_generation(input, getuid(), &generation) == 0);
    CHECK(generation == 4u);
    CHECK(ksp_store_check(input, getuid(), first.hash, input_scopes,
                          &allowed) == 0);
    CHECK(allowed == KSP_SCOPE_INPUT_CONTROL);
    CHECK(ksp_store_check(desktop, getuid(), first.hash, desktop_scopes,
                          &allowed) == 0);
    CHECK(allowed == KSP_SCOPE_SCREEN_CAPTURE);
    CHECK(ksp_store_list(desktop, getuid(), &entries, &count) == 0);
    CHECK(count == 1u);
    CHECK(entries[0].scopes == KSP_SCOPE_SCREEN_CAPTURE);
    ksp_store_list_free(entries);
    entries = NULL;

    CHECK(ksp_store_grant_if_generation(input, &second,
                                        KSP_SCOPE_INPUT_MONITORING,
                                        generation) == 0);
    CHECK(ksp_store_list(input, getuid(), &entries, &count) == 0);
    CHECK(count == 2u);
    CHECK(strcmp(entries[0].app_hash, first.hash) == 0);
    CHECK(strcmp(entries[1].app_hash, second.hash) == 0);
    ksp_store_list_free(entries);
    entries = NULL;

    bounded_config = input_config;
    bounded_config.max_records = 1u;
    CHECK(ksp_store_create(&bounded, &bounded_config) == 0);
    errno = 0;
    CHECK(ksp_store_list(bounded, getuid(), &entries, &count) != 0);
    CHECK(errno == EOVERFLOW);

    prompt_lock = ksp_prompt_lock_acquire(input, getuid(), first.hash,
                                          NULL, NULL);
    CHECK(prompt_lock >= 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        cancellation_state cancellation = { 0 };
        int descriptor;

        close(prompt_lock);
        errno = 0;
        descriptor = ksp_prompt_lock_acquire(input, getuid(), first.hash,
                                             cancel_on_second_check,
                                             &cancellation);
        if (descriptor >= 0)
            ksp_prompt_lock_release(descriptor);
        _exit(descriptor < 0 && errno == ECANCELED ? 0 : 1);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    ksp_prompt_lock_release(prompt_lock);

    CHECK(ksp_store_revoke_uid(input, getuid(), input_scopes) == 0);
    CHECK(ksp_store_check(input, getuid(), first.hash, input_scopes,
                          &allowed) == 0);
    CHECK(allowed == 0u);
    CHECK(ksp_store_check(input, getuid(), second.hash, input_scopes,
                          &allowed) == 0);
    CHECK(allowed == 0u);
    CHECK(ksp_store_check(desktop, getuid(), first.hash, desktop_scopes,
                          &allowed) == 0);
    CHECK(allowed == KSP_SCOPE_SCREEN_CAPTURE);
    CHECK(ksp_store_generation(input, getuid(), &generation) == 0);
    CHECK(generation == 6u);

    CHECK(write_malformed_marker(persistent, &malformed,
                                 KSP_SCOPE_INPUT_MONITORING,
                                 malformed_path, sizeof(malformed_path)) == 0);
    allowed = UINT32_MAX;
    CHECK(ksp_store_check(input, getuid(), malformed.hash,
                          KSP_SCOPE_INPUT_MONITORING, &allowed) != 0);
    CHECK(allowed == 0u);
    CHECK(unlink(malformed_path) == 0);

    ksp_store_destroy(bounded);
    ksp_store_destroy(desktop);
    ksp_store_destroy(input);
    CHECK(remove_tree(root) == 0);
    return 0;
}
