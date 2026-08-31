#include "keysharp_permissions/permissions.h"

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define KSP_POLKIT_MAX_TIMEOUT_SECONDS 3600u

static bool valid_identifier(const char *value)
{
    size_t length;

    if (value == NULL || (length = strlen(value)) == 0u || length > 255u)
        return false;
    for (size_t index = 0u; index < length; index++) {
        unsigned char character = (unsigned char)value[index];

        if (!((character >= (unsigned char)'a'
               && character <= (unsigned char)'z')
              || (character >= (unsigned char)'A'
                  && character <= (unsigned char)'Z')
              || (character >= (unsigned char)'0'
                  && character <= (unsigned char)'9')
              || character == (unsigned char)'.'
              || character == (unsigned char)'_'
              || character == (unsigned char)'-'))
            return false;
    }
    return true;
}

static bool valid_config(const ksp_polkit_config *config, uint32_t scopes)
{
    return config != NULL && config->pkcheck_path != NULL
        && config->pkcheck_path[0] == '/'
        && strlen(config->pkcheck_path) < KSP_PATH_CAPACITY
        && valid_identifier(config->action_id)
        && valid_identifier(config->scope_detail_key)
        && valid_identifier(config->scope_names_detail_key)
        && config->allowed_scopes != 0u
        && (config->allowed_scopes & ~KSP_SCOPE_ALL) == 0u
        && scopes != 0u && (scopes & ~config->allowed_scopes) == 0u
        && config->timeout_seconds != 0u
        && config->timeout_seconds <= KSP_POLKIT_MAX_TIMEOUT_SECONDS;
}

static bool deadline_reached(const struct timespec *deadline)
{
    struct timespec current;

    if (clock_gettime(CLOCK_MONOTONIC, &current) != 0)
        return true;
    return current.tv_sec > deadline->tv_sec
        || (current.tv_sec == deadline->tv_sec
            && current.tv_nsec >= deadline->tv_nsec);
}

static void terminate_child(pid_t child)
{
    int status;

    if (child <= 0)
        return;
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
}

static int configure_spawn(posix_spawn_file_actions_t *actions,
                           posix_spawnattr_t *attributes)
{
    sigset_t mask;
    sigset_t defaults;
    short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
    int error;

    error = posix_spawn_file_actions_init(actions);
    if (error != 0)
        return error;
    error = posix_spawn_file_actions_addopen(actions, STDIN_FILENO,
                                             "/dev/null", O_RDONLY, 0);
    if (error == 0)
        error = posix_spawn_file_actions_addopen(actions, STDOUT_FILENO,
                                                 "/dev/null", O_WRONLY, 0);
    if (error == 0)
        error = posix_spawn_file_actions_addopen(actions, STDERR_FILENO,
                                                 "/dev/null", O_WRONLY, 0);
    if (error != 0) {
        posix_spawn_file_actions_destroy(actions);
        return error;
    }
    error = posix_spawnattr_init(attributes);
    if (error != 0) {
        posix_spawn_file_actions_destroy(actions);
        return error;
    }
    sigemptyset(&mask);
    sigemptyset(&defaults);
    sigaddset(&defaults, SIGHUP);
    sigaddset(&defaults, SIGINT);
    sigaddset(&defaults, SIGPIPE);
    sigaddset(&defaults, SIGTERM);
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    flags = (short)(flags | POSIX_SPAWN_CLOEXEC_DEFAULT);
#endif
    error = posix_spawnattr_setsigmask(attributes, &mask);
    if (error == 0)
        error = posix_spawnattr_setsigdefault(attributes, &defaults);
    if (error == 0)
        error = posix_spawnattr_setflags(attributes, flags);
    if (error != 0) {
        posix_spawnattr_destroy(attributes);
        posix_spawn_file_actions_destroy(actions);
    }
    return error;
}

ksp_polkit_result ksp_polkit_result_from_exit(int exit_code)
{
    if (exit_code == 0)
        return KSP_POLKIT_GRANTED;
    if (exit_code == 1 || exit_code == 3)
        return KSP_POLKIT_DENIED;
    return KSP_POLKIT_UNAVAILABLE;
}

ksp_polkit_result ksp_polkit_authorize(
    const ksp_polkit_config *config,
    const ksp_identity *identity,
    uint32_t scopes,
    ksp_cancel_fn cancelled,
    void *user_data)
{
    char subject[128];
    char scope_names[256];
    char display_names[256];
    char display_path[KSP_PATH_CAPACITY];
    char prompt[KSP_PATH_CAPACITY + 384u];
    char *const environment[] = {
        (char *)"PATH=/usr/bin:/bin",
        (char *)"LANG=C.UTF-8",
        (char *)"LC_ALL=C.UTF-8",
        NULL,
    };
    char *arguments[24];
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    struct timespec deadline;
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000L };
    ksp_identity verified;
    size_t argument = 0u;
    pid_t child = -1;
    int error;
    int status = 0;
    int subject_length;
    int prompt_length;

    if (!valid_config(config, scopes) || identity == NULL
        || identity->pid <= 0 || identity->start_time == 0u
        || !ksp_hash_is_canonical(identity->hash)
        || identity->executable[0] != '/')
        return KSP_POLKIT_UNAVAILABLE;
    if (ksp_internal_cancelled(cancelled, user_data))
        return KSP_POLKIT_CANCELLED;
    if (ksp_identity_revalidate(identity, &verified) != 0)
        return KSP_POLKIT_IDENTITY_CHANGED;
    if (ksp_scopes_format(scopes, false, scope_names,
                          sizeof(scope_names)) != 0
        || ksp_scopes_format(scopes, true, display_names,
                             sizeof(display_names)) != 0)
        return KSP_POLKIT_UNAVAILABLE;
    ksp_sanitize_display_text(verified.executable, display_path,
                              sizeof(display_path));
    subject_length = snprintf(subject, sizeof(subject), "%ld,%" PRIu64 ",%ju",
                              (long)verified.pid, verified.start_time,
                              (uintmax_t)verified.uid);
    prompt_length = snprintf(prompt, sizeof(prompt),
                             "Authentication is required to permanently grant %s to %s",
                             display_names, display_path);
    if (subject_length <= 0 || (size_t)subject_length >= sizeof(subject)
        || prompt_length <= 0 || (size_t)prompt_length >= sizeof(prompt))
        return KSP_POLKIT_UNAVAILABLE;

    arguments[argument++] = (char *)config->pkcheck_path;
    arguments[argument++] = (char *)"--action-id";
    arguments[argument++] = (char *)config->action_id;
    arguments[argument++] = (char *)"--process";
    arguments[argument++] = subject;
    arguments[argument++] = (char *)"--allow-user-interaction";
    arguments[argument++] = (char *)"--detail";
    arguments[argument++] = (char *)"app.path";
    arguments[argument++] = display_path;
    arguments[argument++] = (char *)"--detail";
    arguments[argument++] = (char *)config->scope_detail_key;
    arguments[argument++] = scope_names;
    arguments[argument++] = (char *)"--detail";
    arguments[argument++] = (char *)config->scope_names_detail_key;
    arguments[argument++] = display_names;
    arguments[argument++] = (char *)"--detail";
    arguments[argument++] = (char *)"polkit.message";
    arguments[argument++] = prompt;
    arguments[argument] = NULL;

    error = configure_spawn(&actions, &attributes);
    if (error != 0)
        return KSP_POLKIT_UNAVAILABLE;
    error = posix_spawn(&child, config->pkcheck_path, &actions, &attributes,
                        arguments, environment);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    if (error != 0)
        return KSP_POLKIT_UNAVAILABLE;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
        terminate_child(child);
        return KSP_POLKIT_UNAVAILABLE;
    }
    deadline.tv_sec += (time_t)config->timeout_seconds;
    for (;;) {
        pid_t waited = waitpid(child, &status, WNOHANG);

        if (waited == child)
            break;
        if (waited < 0 && errno != EINTR) {
            terminate_child(child);
            return KSP_POLKIT_UNAVAILABLE;
        }
        if (ksp_internal_cancelled(cancelled, user_data)) {
            terminate_child(child);
            return KSP_POLKIT_CANCELLED;
        }
        if (deadline_reached(&deadline)) {
            terminate_child(child);
            return KSP_POLKIT_UNAVAILABLE;
        }
        struct timespec remaining = delay;
        while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR) {
            if (ksp_internal_cancelled(cancelled, user_data)) {
                terminate_child(child);
                return KSP_POLKIT_CANCELLED;
            }
        }
    }
    if (!WIFEXITED(status))
        return KSP_POLKIT_UNAVAILABLE;
    ksp_polkit_result result = ksp_polkit_result_from_exit(WEXITSTATUS(status));
    if (result != KSP_POLKIT_GRANTED)
        return result;
    return ksp_identity_revalidate(&verified, NULL) == 0
        ? KSP_POLKIT_GRANTED
        : KSP_POLKIT_IDENTITY_CHANGED;
}
