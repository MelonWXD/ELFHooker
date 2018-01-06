#ifndef INJECTDEMO_TRACER_H
#define INJECTDEMO_TRACER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <elf.h>

#include "def.h"
#include "logger.h"

typedef union {
    t_long val;
    char chars[sizeof(t_long)];
} t_union_long_char;

class Tracer {
public:
    Tracer(pid_t pid);
    Tracer(const char* process_name);
    pid_t traceePid();
    const char* traceeProcessName();
    bool traceAttach();
    bool traceDetach();
    bool traceGetRegs(arch_regs *regs);
    bool traceSetRegs(arch_regs *regs);
    long traceWrite(uint8_t *dest, uint8_t *src, size_t size);
    long traceRead(uint8_t *src, uint8_t *buffer, size_t size);
    bool traceContinue();
    bool traceCall(void *addr, t_long *params, uint8_t num_params, arch_regs *regs);

private:
    pid_t pid = 0;
    const char* processName = NULL;
};


#endif //INJECTDEMO_TRACER_H
