#ifndef INJECTDEMO_TOOLS_H
#define INJECTDEMO_TOOLS_H

#include <stdio.h>
#include <unistd.h>
#include <cctype>
#include <dlfcn.h>
#include <sys/mman.h>

#include "logger.h"
#include "tracer.h"

#if defined(__arm__)
    #define LIBC_PATH "/system/lib/libc.so"
#elif defined(__aarch64__)
    #define LIBC_PATH "/system/lib64/libc.so"
#endif

namespace Inject {
    pid_t getPidWithProcessName(const char* process_name);
    const char* getProcessNameWithPid(const pid_t pid);
    void *get_remote_address(pid_t pid, void* local);
    void *find_space_by_mmap(Tracer *tracer, size_t size);
    void *load(Tracer *tracer, const char *library);
}

#endif //INJECTDEMO_TOOLS_H
