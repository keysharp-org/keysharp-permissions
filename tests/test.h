#ifndef KEYSHARP_PERMISSIONS_TEST_H
#define KEYSHARP_PERMISSIONS_TEST_H

#include <stdio.h>

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, \
                    #expression);                                             \
            return 1;                                                         \
        }                                                                     \
    } while (0)

int ksp_test_scopes(void);
int ksp_test_identity(void);
int ksp_test_store(void);
int ksp_test_polkit(void);

#endif
