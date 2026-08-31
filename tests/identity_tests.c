#include "test.h"

#include "keysharp_permissions/permissions.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>

int ksp_test_identity(void)
{
    static const char zero_digest[] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    static const char expected_path_hash[] =
        "4109d2117781adb1d57931e66ffad58fa3f88a0a6bb7584714f8699225933e1b";
    static const char expected_content_hash[] =
        "73cd7ab5e10d259a782b6e021af8326514447477af0358481ee31fc5fee7d434";
    char hash[KSP_HASH_HEX_LENGTH + 1u];
    ksp_identity identity;
    ksp_identity verified;
    uint64_t start_time;

    CHECK(ksp_identity_hash_path("/usr/bin/example-client", hash) == 0);
    CHECK(strcmp(hash, expected_path_hash) == 0);
    CHECK(ksp_identity_hash_content(zero_digest, hash) == 0);
    CHECK(strcmp(hash, expected_content_hash) == 0);
    CHECK(ksp_process_start_time(getpid(), &start_time) == 0);
    CHECK(start_time != 0u);
    CHECK(ksp_identity_identify(getpid(), getuid(), start_time, &identity) == 0);
    CHECK(identity.uid == getuid());
    CHECK(identity.pid == getpid());
    CHECK(identity.start_time == start_time);
    CHECK(identity.executable[0] == '/');
    CHECK(ksp_hash_is_canonical(identity.hash));
    CHECK(ksp_identity_revalidate(&identity, &verified) == 0);
    CHECK(strcmp(identity.hash, verified.hash) == 0);
    CHECK(ksp_identity_identify(getpid(), getuid(), start_time + 1u,
                                &verified) != 0);
    return 0;
}
