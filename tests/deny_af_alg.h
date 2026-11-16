#ifndef KEYSHARP_PERMISSIONS_TEST_DENY_AF_ALG_H
#define KEYSHARP_PERMISSIONS_TEST_DENY_AF_ALG_H

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int ksp_test_deny_af_alg(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_ALG, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EAFNOSUPPORT),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    int descriptor;

    /* Restrict only this test process and its children, never the host kernel. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0)
        return -1;
    descriptor = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (descriptor >= 0) {
        close(descriptor);
        errno = EIO;
        return -1;
    }
    return errno == EAFNOSUPPORT ? 0 : -1;
}

#endif
