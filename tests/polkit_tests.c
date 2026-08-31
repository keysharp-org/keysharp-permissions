#include "test.h"

#include "keysharp_permissions/permissions.h"

#include <stdbool.h>
#include <string.h>
#include <unistd.h>

static bool cancel_immediately(void *user_data)
{
    (void)user_data;
    return true;
}

int ksp_test_polkit(void)
{
    char executable[KSP_PATH_CAPACITY];
    ksp_identity identity;
    ksp_polkit_config config = {
        .pkcheck_path = executable,
        .action_id = "org.test.grant",
        .scope_detail_key = "test.scopes",
        .scope_names_detail_key = "test.scope-names",
        .allowed_scopes = KSP_SCOPE_INPUT_MONITORING
            | KSP_SCOPE_INPUT_CONTROL,
        .timeout_seconds = 2u,
    };
    ssize_t length;

    length = readlink("/proc/self/exe", executable, sizeof(executable) - 1u);
    CHECK(length > 0 && (size_t)length < sizeof(executable) - 1u);
    executable[(size_t)length] = '\0';
    CHECK(ksp_identity_capture(getpid(), getuid(), &identity) == 0);
    CHECK(ksp_polkit_result_from_exit(0) == KSP_POLKIT_GRANTED);
    CHECK(ksp_polkit_result_from_exit(1) == KSP_POLKIT_DENIED);
    CHECK(ksp_polkit_result_from_exit(3) == KSP_POLKIT_DENIED);
    CHECK(ksp_polkit_result_from_exit(127) == KSP_POLKIT_UNAVAILABLE);
    CHECK(ksp_polkit_authorize(&config, &identity,
                               KSP_SCOPE_INPUT_MONITORING
                                   | KSP_SCOPE_INPUT_CONTROL,
                               NULL, NULL) == KSP_POLKIT_GRANTED);
    config.action_id = "org.test.deny";
    CHECK(ksp_polkit_authorize(&config, &identity,
                               KSP_SCOPE_INPUT_MONITORING
                                   | KSP_SCOPE_INPUT_CONTROL,
                               NULL, NULL) == KSP_POLKIT_DENIED);
    CHECK(ksp_polkit_authorize(&config, &identity,
                               KSP_SCOPE_INPUT_MONITORING
                                   | KSP_SCOPE_INPUT_CONTROL,
                               cancel_immediately, NULL)
          == KSP_POLKIT_CANCELLED);
    CHECK(ksp_polkit_authorize(&config, &identity,
                               KSP_SCOPE_SCREEN_CAPTURE, NULL, NULL)
          == KSP_POLKIT_UNAVAILABLE);
    return 0;
}
