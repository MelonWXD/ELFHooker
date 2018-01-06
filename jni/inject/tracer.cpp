#include "tracer.h"
#include "tools.h"

using namespace::Inject;

Tracer::Tracer(pid_t pid) : pid(pid) {
    if (pid > 0) {
        processName = getProcessNameWithPid(pid);
        LOGD("pid: %d, process name: %s", pid, NULL!=processName ? processName : "unknown");
    }
}

Tracer::Tracer(const char *process_name) {
    if (NULL==process_name || 0==strlen(process_name)) {
        LOGE("process name is NULL");
        return;
    }

    pid = getPidWithProcessName(process_name);
    if (0 == pid) {
        LOGE("failed to get pid of process %s", process_name);
        return;
    }
    processName = strdup(process_name);
    LOGD("pid: %d, process name: %s", pid, NULL!=processName ? processName : "unknown");
}

pid_t Tracer::traceePid() {
    return pid;
}

const char* Tracer::traceeProcessName() {
    return NULL!=processName ? processName : "unknown";
}

bool Tracer::traceAttach() {
    if (pid<=0 || -1==ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
        LOGE("failed to traceAttach (%d)", pid);
        return false;
    }
    waitpid(pid, NULL, WUNTRACED);

    return true;
}

bool Tracer::traceDetach() {
    if (pid > 0) {
        if (-1 != ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
            return true;
        }
    }
    LOGE("failed to traceDetach (%d)", pid);
    return false;
}

bool Tracer::traceGetRegs(arch_regs *regs) {
    if (pid > 0) {
        #if defined(__arm__)
            if (-1 != ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
                return true;
            }
        #elif defined(__aarch64__)
            struct iovec data;
            data.iov_base = regs;
            data.iov_len = sizeof(arch_regs);
            if (-1 != ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &data)) {
                return true;
            }
        #endif
    }
    LOGE("failed to PTRACE_GETREGS (%d)", pid);
    return false;
}

bool Tracer::traceSetRegs(arch_regs *regs) {
    if (pid > 0) {
        #if defined(__arm__)
            if (-1 != ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
                return true;
            }
        #elif defined(__aarch64__)
            struct iovec data;
            data.iov_base = regs;
            data.iov_len = sizeof(arch_regs);
            if (-1 != ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &data)) {
                return true;
            }
        #endif
    }
    LOGE("failed to PTRACE_SETREGS (%d)", pid);
    return false;
}

long Tracer::traceWrite(uint8_t *dest, uint8_t *src, size_t size) {
    if (pid > 0) {
        uint8_t step = sizeof(t_long);
        size_t i = size / step;
        uint8_t j = (uint8_t)(size % step);
        t_union_long_char u;

        for (size_t k=0; k<i; k++) {
            memcpy(u.chars, src, step);
            if (-1 == ptrace(PTRACE_POKETEXT, pid, dest, u.val)) {
                LOGE("failed to PTRACE_POKETEXT (%d)", pid);
                return -1;
            }
            src += step;
            dest += step;
        }

        if (j > 0) {
            errno = 0;
            u.val = (t_long)ptrace(PTRACE_PEEKTEXT, pid, dest, NULL);
            if (-1==u.val && 0!=errno) {
                LOGE("failed to PTRACE_PEEKTEXT (%d): errno %d", pid, errno);
                return -1;
            }

            for (uint8_t k=0; k<j; k++) {
                u.chars[k] = *src++;
            }
            if (-1 == ptrace(PTRACE_POKETEXT, pid, dest, u.val)) {
                LOGE("failed to PTRACE_POKETEXT (%d)", pid);
                return -1;
            }
        }
        return size;
    }
    return 0;
}

long Tracer::traceRead(uint8_t *src, uint8_t *buffer, size_t size) {
    if (pid > 0) {
        uint8_t step = sizeof(t_long);
        size_t i = size / step;
        uint8_t j = (uint8_t)(size % step);
        t_union_long_char u;

        errno = 0;
        for (uint32_t k=0; k<i; k++) {
            u.val = (t_long)ptrace(PTRACE_PEEKTEXT, pid, src, NULL);
            if (-1==u.val && 0!=errno) {
                LOGE("failed to PTRACE_PEEKTEXT (%d): errno %d", pid, errno);
                return -1;
            }
            memcpy(buffer, u.chars, step);
            buffer += step;
            src += step;
        }

        if (j > 0) {
            u.val = (t_long)ptrace(PTRACE_PEEKTEXT, pid, src, NULL);
            if (-1==u.val && 0!=errno) {
                LOGE("failed to PTRACE_PEEKTEXT (%d): errno %d", pid, errno);
                return -1;
            }
            memcpy(buffer, u.chars, j);
        }
        return size;
    }
    return 0;
}

bool Tracer::traceContinue() {
    if (pid > 0) {
        if (-1 != ptrace(PTRACE_CONT, pid, NULL, NULL)) {
            return true;
        }
    }
    LOGE("failed to PTRACE_CONT (%d)", pid);
    return false;
}

bool Tracer::traceCall(void *addr, t_long *params, uint8_t num_params, arch_regs *regs) {
    if (pid > 0) {
        for (uint8_t i=0; i<num_params && i<MAX_PARAMETER_REGISTER; i++) {
            regs->uregs[i] = params[i];
        }

        if (num_params > MAX_PARAMETER_REGISTER) {
            size_t size = (num_params-MAX_PARAMETER_REGISTER)*sizeof(t_long);
            regs->sp -= size;
            traceWrite((uint8_t *) regs->sp, (uint8_t *) &params[MAX_PARAMETER_REGISTER], size);
        }

        regs->pc = (t_long)addr;
        if (regs->pc & 0x1) {
            // thumb
            regs->pc &= ~1u;
            regs->cpsr |= CPSR_T_MASK;
        } else {
            // arm
            regs->cpsr &= ~CPSR_T_MASK;
        }
        regs->lr = 0;

        if (traceSetRegs(regs) && traceContinue()) {
            int stat = 0;
            waitpid(pid, &stat, WUNTRACED);
            while (stat != 0xb7f) {
                if (!traceContinue()) {
                    LOGE("failed to traceCall (%d)", pid);
                    return false;
                }
                waitpid(pid, &stat, WUNTRACED);
            }
            return true;
        }
    }
    LOGE("failed to traceCall (%d)", pid);
    return false;
}
