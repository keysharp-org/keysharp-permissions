#include "test.h"

#include "keysharp_permissions/permissions.h"

#include <inttypes.h>
#include <string.h>

int ksp_test_scopes(void)
{
    static const char lower_hash[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const char valid_marker[] =
        "grant-1000-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-00000001.grant";
    char formatted[256];
    char hash[KSP_HASH_HEX_LENGTH + 1u];
    char changed[sizeof(valid_marker)];
    uid_t uid;
    uint32_t scope;

    CHECK(KSP_SCOPE_INPUT_MONITORING == 0x01u);
    CHECK(KSP_SCOPE_INPUT_CONTROL == 0x02u);
    CHECK(KSP_SCOPE_WINDOW_MONITORING == 0x04u);
    CHECK(KSP_SCOPE_WINDOW_CONTROL == 0x08u);
    CHECK(KSP_SCOPE_SCREEN_CAPTURE == 0x10u);
    CHECK(KSP_SCOPE_AUDIO_CAPTURE == 0x20u);
    CHECK(KSP_SCOPE_CAMERA_CAPTURE == 0x40u);
    CHECK(KSP_SCOPE_CLIPBOARD_MONITORING == 0x80u);
    CHECK(KSP_SCOPE_ALL == 0xffu);
    CHECK(strcmp(ksp_scope_name(KSP_SCOPE_SCREEN_CAPTURE),
                 "screen-capture") == 0);
    CHECK(strcmp(ksp_scope_display_name(KSP_SCOPE_SCREEN_CAPTURE),
                 "Screen Capture") == 0);
    CHECK(ksp_scope_from_name("screen-capture") == KSP_SCOPE_SCREEN_CAPTURE);
    CHECK(ksp_scope_from_name("ScreenCapture") == 0u);
    CHECK(ksp_scope_from_name("block-input") == 0u);
    CHECK(ksp_scope_name(0x100u) == NULL);
    CHECK(ksp_scopes_format(KSP_SCOPE_INPUT_MONITORING
                                | KSP_SCOPE_INPUT_CONTROL,
                            false, formatted, sizeof(formatted)) == 0);
    CHECK(strcmp(formatted, "input-monitoring,input-control") == 0);
    CHECK(ksp_scopes_format(KSP_SCOPE_INPUT_MONITORING
                                | KSP_SCOPE_INPUT_CONTROL,
                            true, formatted, sizeof(formatted)) == 0);
    CHECK(strcmp(formatted, "Input Monitoring, Input Control") == 0);
    CHECK(ksp_hash_is_canonical(lower_hash));
    strcpy(hash, lower_hash);
    hash[4] = 'A';
    CHECK(!ksp_hash_is_canonical(hash));
    CHECK(ksp_marker_parse_name(valid_marker, &uid, hash, &scope));
    CHECK((uintmax_t)uid == 1000u);
    CHECK(strcmp(hash, lower_hash) == 0);
    CHECK(scope == KSP_SCOPE_INPUT_MONITORING);
    strcpy(changed, valid_marker);
    changed[6] = '0';
    CHECK(!ksp_marker_parse_name(changed, &uid, hash, &scope));
    strcpy(changed, valid_marker);
    changed[sizeof("grant-1000-") - 1u] = 'A';
    CHECK(!ksp_marker_parse_name(changed, &uid, hash, &scope));
    strcpy(changed, valid_marker);
    memcpy(strstr(changed, "00000001.grant"), "00000100", 8u);
    CHECK(!ksp_marker_parse_name(changed, &uid, hash, &scope));
    return 0;
}
