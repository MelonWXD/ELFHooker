#include "tools.h"

bool find_module_info_by_address(pid_t pid, void *addr, char* module, void **start, void **end) {
    char buffer[1024];
    if (pid <= 0) {
        snprintf(buffer, 1024, "/proc/self/maps");
    } else {
        snprintf(buffer, 1024, "/proc/%d/maps", pid);
    }

    unsigned long module_start;
    unsigned long module_end;
    int module_name_pos;
    FILE *mapsFile = fopen(buffer, "r");
    if (NULL != mapsFile) {
        while(fgets(buffer, 1024, mapsFile)) {
            // 7ad995c000-7ad9a18000 r-xp 00000000 103:09 1623                          /system/lib64/libc.so
            if (sscanf(buffer, "%lx-%lx %*4s %*x %*x:%*x %*d%n", &module_start, &module_end, &module_name_pos) != 2) {
                LOGE("failed to parse %s", buffer);
                continue;
            }

            if ((unsigned long)addr>module_start && (unsigned long)addr<module_end) {
                fclose(mapsFile);
                while(isspace(buffer[module_name_pos])) {
                    module_name_pos++;
                }
                strcpy(module, &buffer[module_name_pos]);
                *start = (void *)module_start;
                *end = (void *)module_end;
                return true;
            }
        }
    }
    fclose(mapsFile);
    LOGE("failed to find %p module in process (%d)", addr, pid);
    return false;
}

bool find_module_info_by_name(pid_t pid, const char* module_name, void **start, void **end) {
    char buffer[1024];
    if (pid <= 0) {
        snprintf(buffer, 1024, "/proc/self/maps");
    } else {
        snprintf(buffer, 1024, "/proc/%d/maps", pid);
    }

    unsigned long module_start;
    unsigned long module_end;
    int module_name_pos;
    FILE *mapsFile = fopen(buffer, "r");
    if (NULL != mapsFile) {
        while(fgets(buffer, 1024, mapsFile)) {
            // 7ad995c000-7ad9a18000 r-xp 00000000 103:09 1623                          /system/lib64/libc.so
            if (sscanf(buffer, "%lx-%lx %*4s %*x %*x:%*x %*d%n", &module_start, &module_end, &module_name_pos) != 2) {
                LOGE("failed to parse %s", buffer);
                continue;
            }

            while(isspace(buffer[module_name_pos])) {
                module_name_pos++;
            }
            // LOGD("%s: start %p, end: %p", &buffer[module_name_pos], (void *)module_start, (void *)module_end);
            if (0 == strncmp(&buffer[module_name_pos], module_name, strlen(module_name))) {
                *start = (void *)module_start;
                *end = (void *)module_end;
                fclose(mapsFile);
                return true;
            }
        }
    }
    fclose(mapsFile);
    LOGE("failed to find module %s (%d)", module_name, pid);
    return false;
}

void* get_method_address(const char *library, const char *method) {
    void *handler = dlopen(library, RTLD_LAZY | RTLD_LOCAL);
    if (NULL == handler) {
        LOGE("failed to dlopen %s", library);
        return NULL;
    }
    void *ret = dlsym(handler, method);
    dlclose(handler);
    return ret;
}

pid_t Inject::getPidWithProcessName(const char *process_name) {
    DIR* proc = opendir("/proc");
    if (NULL == proc) {
        LOGE("failed to open /proc dir");
        return 0;
    }

    int error;
    int ret = 0;
    int id;
    char buffer[256];
    FILE *cmdlineFile;
    dirent *curr = NULL;
    while(NULL != (curr=readdir(proc))) {
        if (DT_DIR != curr->d_type) {
            continue;
        }

        id = atoi(curr->d_name);
        if (id > 0) {
            snprintf(buffer, 256, "/proc/%d/cmdline", id);
            cmdlineFile = fopen(buffer, "r");
            if (NULL != cmdlineFile) {
                fgets(buffer, 256, cmdlineFile);
                error = ferror(cmdlineFile);
                fclose(cmdlineFile);
                if (0==error && 0==strcmp(buffer, process_name)) {
                    ret = id;
                    break;
                }
            }
        }
    }
    closedir(proc);
    return ret;
}

const char* Inject::getProcessNameWithPid(const pid_t pid) {
    char *ret = NULL;
    char buffer[256];
    snprintf(buffer, 256, "/proc/%d/cmdline", pid);
    FILE *cmdlineFile = fopen(buffer, "r");
    if (NULL != cmdlineFile) {
        fgets(buffer, 256, cmdlineFile);
        if (0 == ferror(cmdlineFile)) {
            ret = strdup(buffer);
        }
        fclose(cmdlineFile);
    }
    return ret;
}

void* Inject::get_remote_address(pid_t pid, void *local) {
    char buffer[256];
    void *local_start;
    void *local_end;
    void *remote_start;
    void *remote_end;

    if (!find_module_info_by_address(-1, local, buffer, &local_start, &local_end)) {
        return NULL;
    }

    LOGD("%p: module is %s", local, buffer);

    if (!find_module_info_by_name(pid, buffer, &remote_start, &remote_end)) {
        return NULL;
    }

    return (void *)((unsigned long)local + (unsigned long)remote_start - (unsigned long)local_start);
}

void* Inject::find_space_by_mmap(Tracer *tracer, size_t size) {
    arch_regs regs;
    if (!tracer->traceGetRegs(&regs)) {
        return NULL;
    }

    void *local_mmap = get_method_address(LIBC_PATH, "mmap");
    if(NULL == local_mmap) {
        LOGE("failed to get local address of mmap");
        return NULL;
    }
    void *remote_mmap = get_remote_address(tracer->traceePid(), local_mmap);
    if (NULL == remote_mmap) {
        LOGE("failed to parse remote mmap address");
        return NULL;
    }
    LOGD("mmap: local %p, remote %p", local_mmap, remote_mmap);

    t_long params[6];
    params[0] = 0;
    params[1] = (long)size;
    params[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    params[3] = MAP_ANONYMOUS | MAP_PRIVATE;
    params[4] = 0;
    params[5] = 0;

    if (!tracer->traceCall(remote_mmap, params, 6, &regs)) {
        return NULL;
    }

    if (!tracer->traceGetRegs(&regs)) {
        return NULL;
    }

    return 0 == regs.pc ? (void *)regs.r0 : NULL;
}

void* Inject::load(Tracer *tracer, const char *library) {
    arch_regs regs;
    if (!tracer->traceGetRegs(&regs)) {
        return NULL;
    }

    void *remote_dlopen = get_remote_address(tracer->traceePid(), (void *)dlopen);
    if (NULL == remote_dlopen) {
        LOGE("failed to parse remote dlopen address");
        return NULL;
    }
    LOGD("dlopen: local %p, remote %p", dlopen, remote_dlopen);

    size_t length = strlen(library) + 1;
    void *buffer = find_space_by_mmap(tracer, length);
    if (NULL == buffer) {
        LOGE("failed to find a buffer(%zu) with mmap", length);
        return NULL;
    }
    LOGD("mmap: buffer %p, length: %zu", buffer, length);

    if (length != tracer->traceWrite((uint8_t *) buffer, (uint8_t *) library, length)) {
        LOGE("failed to traceWrite library name into process %d", tracer->traceePid());
        return NULL;
    }

//    char temp[length];
//    if (length != tracer->traceRead((uint8_t *)buffer, (uint8_t *)temp, length)) {
//        LOGE("failed to traceRead from process %d", tracer->traceePid());
//    } else {
//        LOGD("read result: %s", temp);
//    }

    t_long params[2];
    params[0] = (t_long)buffer;
    params[1] = RTLD_NOW | RTLD_GLOBAL;
    if (!tracer->traceCall(remote_dlopen, params, 2, &regs)) {
        return NULL;
    }

    if (!tracer->traceGetRegs(&regs)) {
        return NULL;
    }
    #if defined(__arm__)
        LOGD("dlopen: r0 %08lx pc %08lx", regs.r0, regs.pc);
    #elif defined(__aarch64__)
        LOGD("dlopen: r0 %016llx pc %016llx", regs.r0, regs.pc);
    #endif

    return 0 == regs.pc ? (void *)regs.r0 : NULL;
}
