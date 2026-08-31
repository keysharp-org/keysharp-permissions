#include "keysharp_permissions/permissions.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

typedef struct ksp_scope_record {
    uint32_t scope;
    const char *name;
    const char *display_name;
} ksp_scope_record;

static const ksp_scope_record scope_records[] = {
    { KSP_SCOPE_INPUT_MONITORING, "input-monitoring", "Input Monitoring" },
    { KSP_SCOPE_INPUT_CONTROL, "input-control", "Input Control" },
    { KSP_SCOPE_WINDOW_MONITORING, "window-monitoring", "Window Monitoring" },
    { KSP_SCOPE_WINDOW_CONTROL, "window-control", "Window Control" },
    { KSP_SCOPE_SCREEN_CAPTURE, "screen-capture", "Screen Capture" },
    { KSP_SCOPE_AUDIO_CAPTURE, "audio-capture", "Audio Capture" },
    { KSP_SCOPE_CAMERA_CAPTURE, "camera-capture", "Camera Capture" },
    { KSP_SCOPE_CLIPBOARD_MONITORING, "clipboard-monitoring",
      "Clipboard Monitoring" },
};

static const ksp_scope_record *find_scope(uint32_t scope)
{
    for (size_t index = 0u;
         index < sizeof(scope_records) / sizeof(scope_records[0]); index++) {
        if (scope_records[index].scope == scope)
            return &scope_records[index];
    }
    return NULL;
}

const char *ksp_scope_name(uint32_t scope)
{
    const ksp_scope_record *record = find_scope(scope);
    return record == NULL ? NULL : record->name;
}

const char *ksp_scope_display_name(uint32_t scope)
{
    const ksp_scope_record *record = find_scope(scope);
    return record == NULL ? NULL : record->display_name;
}

uint32_t ksp_scope_from_name(const char *name)
{
    if (name == NULL)
        return 0u;
    for (size_t index = 0u;
         index < sizeof(scope_records) / sizeof(scope_records[0]); index++) {
        if (strcmp(scope_records[index].name, name) == 0)
            return scope_records[index].scope;
    }
    return 0u;
}

int ksp_scopes_format(uint32_t scopes, bool display_names,
                      char *destination, size_t capacity)
{
    size_t used = 0u;

    if (destination == NULL || capacity == 0u || scopes == 0u
        || (scopes & ~KSP_SCOPE_ALL) != 0u) {
        errno = EINVAL;
        return -1;
    }
    destination[0] = '\0';
    for (size_t index = 0u;
         index < sizeof(scope_records) / sizeof(scope_records[0]); index++) {
        const char *name;
        int written;

        if ((scopes & scope_records[index].scope) == 0u)
            continue;
        name = display_names ? scope_records[index].display_name
                             : scope_records[index].name;
        written = snprintf(destination + used, capacity - used, "%s%s",
                           used == 0u ? "" : (display_names ? ", " : ","),
                           name);
        if (written < 0 || (size_t)written >= capacity - used) {
            destination[0] = '\0';
            errno = ENOSPC;
            return -1;
        }
        used += (size_t)written;
    }
    return 0;
}

bool ksp_hash_is_canonical(const char *hash)
{
    if (hash == NULL || strlen(hash) != KSP_HASH_HEX_LENGTH)
        return false;
    for (size_t index = 0u; index < KSP_HASH_HEX_LENGTH; index++) {
        if (!((hash[index] >= '0' && hash[index] <= '9')
              || (hash[index] >= 'a' && hash[index] <= 'f')))
            return false;
    }
    return true;
}

void ksp_sanitize_display_text(const char *source, char *destination,
                               size_t capacity)
{
    size_t index = 0u;

    if (destination == NULL || capacity == 0u)
        return;
    if (source != NULL) {
        while (source[index] != '\0' && index + 1u < capacity) {
            unsigned char value = (unsigned char)source[index];
            destination[index] = value < 0x20u || value == 0x7fu
                ? '?'
                : (char)value;
            index++;
        }
    }
    destination[index] = '\0';
}
