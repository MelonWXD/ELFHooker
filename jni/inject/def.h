#ifndef INJECTDEMO_DEF_H
#define INJECTDEMO_DEF_H

#include <sys/ptrace.h>

#define CPSR_T_MASK		( 1u << 5 )

#if defined(__arm__)
    typedef long t_long;
    typedef struct pt_regs arch_regs;

    #define MAX_PARAMETER_REGISTER 4

    #define cpsr ARM_cpsr
    #define pc ARM_pc
    #define lr ARM_lr
    #define sp ARM_sp
    #define r0 ARM_r0
#elif defined(__aarch64__)
    typedef __u64 t_long;
    typedef struct user_pt_regs arch_regs;

    #define MAX_PARAMETER_REGISTER 8

    #define uregs regs
    #define cpsr pstate
    #define lr regs[30]
    #define r0 regs[0]
#endif

#endif //INJECTDEMO_DEF_H
