#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "tracer.h"
#include "tools.h"

#define USAGE "usage: %s -p PID |(-P process_name) -l library_name\n"

using namespace::Inject;

int main(int argc, char* argv[]) {
    int ret = 0;
    int opt;
    pid_t pid = 0;
    const char* process_name = NULL;
    const char* library_name = NULL;
    arch_regs regs;

    while(-1 != (opt=getopt(argc, argv, "p:P:l:h"))) {
        switch(opt) {
            case 'p':
                pid = atoi(optarg);
                break;
            case 'P':
                process_name = optarg;
                break;
            case 'l':
                library_name = optarg;
                break;
            case 'h':
            default:
                fprintf(stdout, USAGE, argv[0]);
                exit(-1);
        }
    }

    if ((0==pid && NULL==process_name) || NULL==library_name) {
        fprintf(stdout, USAGE, argv[0]);
        exit(-1);
    }

    if (-1 == access(library_name, R_OK|X_OK)) {
        fprintf(stdout, "%s must chmod rx\n", library_name);
        exit(-1);
    }

    Tracer *tracer;
    if (pid > 0) {
        Tracer real(pid);
        tracer = &real;
    } else {
        Tracer real(process_name);
        tracer = &real;
    }
    if (!tracer->traceAttach()) {
        fprintf(stdout, "failed to traceAttach\n");
        exit(-1);
    }

    if (!tracer->traceGetRegs(&regs)) {
        ret = -1;
        goto DETACH;
    }

    if (NULL == load(tracer, library_name)) {
        fprintf(stdout, "failed to load %s\n", library_name);
    } else {
        fprintf(stdout, "load %s success\n", library_name);
        fprintf(stdout, "inject success\n");
    }

    if (!tracer->traceSetRegs(&regs)) {
        ret = -1;
        goto DETACH;
    }
DETACH:
    tracer->traceDetach();
    return ret;
}
