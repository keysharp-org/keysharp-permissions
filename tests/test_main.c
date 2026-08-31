#include "test.h"

#include <stdbool.h>
#include <string.h>

static bool has_argument(int argc, char **argv, const char *value)
{
    for (int index = 1; index < argc; index++)
        if (strcmp(argv[index], value) == 0)
            return true;
    return false;
}

static int pkcheck_stub(int argc, char **argv)
{
    if (argc < 3 || strcmp(argv[1], "--action-id") != 0
        || !has_argument(argc, argv, "--process")
        || !has_argument(argc, argv, "--allow-user-interaction")
        || !has_argument(argc, argv, "app.path")
        || !has_argument(argc, argv, "test.scopes")
        || !has_argument(argc, argv, "test.scope-names")
        || !has_argument(argc, argv, "input-monitoring,input-control")
        || !has_argument(argc, argv, "Input Monitoring, Input Control")
        || !has_argument(argc, argv, "polkit.message"))
        return 2;
    return strcmp(argv[2], "org.test.deny") == 0 ? 1 : 0;
}

int main(int argc, char **argv)
{
    int failures = 0;

    if (argc > 1 && strcmp(argv[1], "--action-id") == 0)
        return pkcheck_stub(argc, argv);
    failures += ksp_test_scopes();
    failures += ksp_test_identity();
    failures += ksp_test_store();
    failures += ksp_test_polkit();
    if (failures != 0) {
        fprintf(stderr, "%d test group(s) failed\n", failures);
        return 1;
    }
    puts("keysharp-permissions tests passed");
    return 0;
}
