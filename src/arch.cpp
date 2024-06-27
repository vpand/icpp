/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "arch.h"
#include <cstdlib>
#include <cstring>

#define __ASM__ __asm__ __volatile__
#define __NAKED__ __attribute__((naked))

namespace icpp {

ArchType host_arch() {
#if __arm64__ || __aarch64__
  return AArch64;
#elif __x86_64__ || __x64__
  return X86_64;
#else
#error Unsupported host architecture.
#endif
}

#define switch_stack_strsize "0x1000"

#define save_gpr_a64()                                                         \
  __ASM__("stp  x0, x1, [sp, #0x0]");                                          \
  __ASM__("stp  x2, x3, [sp, #0x10]");                                         \
  __ASM__("stp  x4, x5, [sp, #0x20]");                                         \
  __ASM__("stp  x6, x7, [sp, #0x30]");                                         \
  __ASM__("stp  x8, x9, [sp, #0x40]");                                         \
  __ASM__("stp  x10, x11, [sp, #0x50]");                                       \
  __ASM__("stp  x12, x13, [sp, #0x60]");                                       \
  __ASM__("stp  x14, x15, [sp, #0x70]");                                       \
  __ASM__("stp  x16, x17, [sp, #0x80]");                                       \
  __ASM__("stp  x18, x19, [sp, #0x90]");                                       \
  __ASM__("stp  x20, x21, [sp, #0xa0]");                                       \
  __ASM__("stp  x22, x23, [sp, #0xb0]");                                       \
  __ASM__("stp  x24, x25, [sp, #0xc0]");                                       \
  __ASM__("stp  x26, x27, [sp, #0xd0]");                                       \
  __ASM__("stp  x28, x29, [sp, #0xe0]");                                       \
  __ASM__("stp  x30, x17, [sp, #0xf0]");

// other usage need save real x31(sp) to context
#define save_gpr_real_a64()                                                    \
  __ASM__("stp  x0, x1, [sp, #0x0]");                                          \
  __ASM__("stp  x2, x3, [sp, #0x10]");                                         \
  __ASM__("stp  x4, x5, [sp, #0x20]");                                         \
  __ASM__("stp  x6, x7, [sp, #0x30]");                                         \
  __ASM__("stp  x8, x9, [sp, #0x40]");                                         \
  __ASM__("stp  x10, x11, [sp, #0x50]");                                       \
  __ASM__("stp  x12, x13, [sp, #0x60]");                                       \
  __ASM__("stp  x14, x15, [sp, #0x70]");                                       \
  __ASM__("stp  x16, x17, [sp, #0x80]");                                       \
  __ASM__("stp  x18, x19, [sp, #0x90]");                                       \
  __ASM__("stp  x20, x21, [sp, #0xa0]");                                       \
  __ASM__("stp  x22, x23, [sp, #0xb0]");                                       \
  __ASM__("stp  x24, x25, [sp, #0xc0]");                                       \
  __ASM__("stp  x26, x27, [sp, #0xd0]");                                       \
  __ASM__("stp  x28, x29, [sp, #0xe0]");                                       \
  __ASM__("mov  x17, sp");                                                     \
  __ASM__("stp  x30, x17, [sp, #0xf0]");

#define save_neon_a64()                                                        \
  __ASM__("stp  q0, q1, [sp, #0x100]");                                        \
  __ASM__("stp  q2, q3, [sp, #0x120]");                                        \
  __ASM__("stp  q4, q5, [sp, #0x140]");                                        \
  __ASM__("stp  q6, q7, [sp, #0x160]");                                        \
  __ASM__("stp  q8, q9, [sp, #0x180]");                                        \
  __ASM__("stp  q10, q11, [sp, #0x1a0]");                                      \
  __ASM__("stp  q12, q13, [sp, #0x1c0]");                                      \
  __ASM__("stp  q14, q15, [sp, #0x1e0]");                                      \
  __ASM__("stp  q16, q17, [sp, #0x200]");                                      \
  __ASM__("stp  q18, q19, [sp, #0x220]");                                      \
  __ASM__("stp  q20, q21, [sp, #0x240]");                                      \
  __ASM__("stp  q22, q23, [sp, #0x260]");                                      \
  __ASM__("stp  q24, q25, [sp, #0x280]");                                      \
  __ASM__("stp  q26, q27, [sp, #0x2a0]");                                      \
  __ASM__("stp  q28, q29, [sp, #0x2c0]");                                      \
  __ASM__("stp  q30, q31, [sp, #0x2e0]");

#define load_gpr_a64()                                                         \
  __ASM__("ldp  x0, x1, [sp, #0x0]");                                          \
  __ASM__("ldp  x2, x3, [sp, #0x10]");                                         \
  __ASM__("ldp  x4, x5, [sp, #0x20]");                                         \
  __ASM__("ldp  x6, x7, [sp, #0x30]");                                         \
  __ASM__("ldp  x8, x9, [sp, #0x40]");                                         \
  __ASM__("ldp  x10, x11, [sp, #0x50]");                                       \
  __ASM__("ldp  x12, x13, [sp, #0x60]");                                       \
  __ASM__("ldp  x14, x15, [sp, #0x70]");                                       \
  __ASM__("ldp  x16, x17, [sp, #0x80]");                                       \
  __ASM__("ldp  x18, x19, [sp, #0x90]");                                       \
  __ASM__("ldp  x20, x21, [sp, #0xa0]");                                       \
  __ASM__("ldp  x22, x23, [sp, #0xb0]");                                       \
  __ASM__("ldp  x24, x25, [sp, #0xc0]");                                       \
  __ASM__("ldp  x26, x27, [sp, #0xd0]");                                       \
  __ASM__("ldp  x28, x29, [sp, #0xe0]");                                       \
  __ASM__("ldp  x30, x17, [sp, #0xf0]");

#define load_neon_a64()                                                        \
  __ASM__("ldp  q0, q1, [sp, #0x100]");                                        \
  __ASM__("ldp  q2, q3, [sp, #0x120]");                                        \
  __ASM__("ldp  q4, q5, [sp, #0x140]");                                        \
  __ASM__("ldp  q6, q7, [sp, #0x160]");                                        \
  __ASM__("ldp  q8, q9, [sp, #0x180]");                                        \
  __ASM__("ldp  q10, q11, [sp, #0x1a0]");                                      \
  __ASM__("ldp  q12, q13, [sp, #0x1c0]");                                      \
  __ASM__("ldp  q14, q15, [sp, #0x1e0]");                                      \
  __ASM__("ldp  q16, q17, [sp, #0x200]");                                      \
  __ASM__("ldp  q18, q19, [sp, #0x220]");                                      \
  __ASM__("ldp  q20, q21, [sp, #0x240]");                                      \
  __ASM__("ldp  q22, q23, [sp, #0x260]");                                      \
  __ASM__("ldp  q24, q25, [sp, #0x280]");                                      \
  __ASM__("ldp  q26, q27, [sp, #0x2a0]");                                      \
  __ASM__("ldp  q28, q29, [sp, #0x2c0]");                                      \
  __ASM__("ldp  q30, q31, [sp, #0x2e0]");

#define save_gpr(reg)                                                          \
  __ASM__("movq %rax, 0x000(" #reg ")");                                       \
  __ASM__("movq %rbx, 0x008(" #reg ")");                                       \
  __ASM__("movq %rcx, 0x010(" #reg ")");                                       \
  __ASM__("movq %rdx, 0x018(" #reg ")");                                       \
  __ASM__("movq %rbp, 0x020(" #reg ")");                                       \
  __ASM__("movq %rsi, 0x028(" #reg ")");                                       \
  __ASM__("movq %rdi, 0x030(" #reg ")");                                       \
  __ASM__("movq %r8 , 0x038(" #reg ")");                                       \
  __ASM__("movq %r9 , 0x040(" #reg ")");                                       \
  __ASM__("movq %r10, 0x048(" #reg ")");                                       \
  __ASM__("movq %r11, 0x050(" #reg ")");                                       \
  __ASM__("movq %r12, 0x058(" #reg ")");                                       \
  __ASM__("movq %r13, 0x060(" #reg ")");                                       \
  __ASM__("movq %r14, 0x068(" #reg ")");                                       \
  __ASM__("movq %r15, 0x070(" #reg ")");

#define load_gpr(reg)                                                          \
  __ASM__("movq 0x000(" #reg "), %rax");                                       \
  __ASM__("movq 0x008(" #reg "), %rbx");                                       \
  __ASM__("movq 0x010(" #reg "), %rcx");                                       \
  __ASM__("movq 0x018(" #reg "), %rdx");                                       \
  __ASM__("movq 0x020(" #reg "), %rbp");                                       \
  __ASM__("movq 0x028(" #reg "), %rsi");                                       \
  __ASM__("movq 0x030(" #reg "), %rdi");                                       \
  __ASM__("movq 0x038(" #reg "), %r8 ");                                       \
  __ASM__("movq 0x040(" #reg "), %r9 ");                                       \
  __ASM__("movq 0x048(" #reg "), %r10");                                       \
  __ASM__("movq 0x050(" #reg "), %r11");                                       \
  __ASM__("movq 0x058(" #reg "), %r12");                                       \
  __ASM__("movq 0x060(" #reg "), %r13");                                       \
  __ASM__("movq 0x068(" #reg "), %r14");                                       \
  __ASM__("movq 0x070(" #reg "), %r15");

#define load_gpr_r11()                                                         \
  __ASM__("movq 0x000(%r11), %rax");                                           \
  __ASM__("movq 0x008(%r11), %rbx");                                           \
  __ASM__("movq 0x010(%r11), %rcx");                                           \
  __ASM__("movq 0x018(%r11), %rdx");                                           \
  __ASM__("movq 0x020(%r11), %rbp");                                           \
  __ASM__("movq 0x028(%r11), %rsi");                                           \
  __ASM__("movq 0x030(%r11), %rdi");                                           \
  __ASM__("movq 0x038(%r11), %r8 ");                                           \
  __ASM__("movq 0x040(%r11), %r9 ");                                           \
  __ASM__("movq 0x048(%r11), %r10");                                           \
  __ASM__("movq 0x058(%r11), %r12");                                           \
  __ASM__("movq 0x060(%r11), %r13");                                           \
  __ASM__("movq 0x068(%r11), %r14");                                           \
  __ASM__("movq 0x070(%r11), %r15");

#define save_xmm_after_gpr(reg)                                                \
  __ASM__("movdqu %xmm0 , 0x078(" #reg ")");                                   \
  __ASM__("movdqu %xmm1 , 0x088(" #reg ")");                                   \
  __ASM__("movdqu %xmm2 , 0x098(" #reg ")");                                   \
  __ASM__("movdqu %xmm3 , 0x0A8(" #reg ")");                                   \
  __ASM__("movdqu %xmm4 , 0x0B8(" #reg ")");                                   \
  __ASM__("movdqu %xmm5 , 0x0C8(" #reg ")");                                   \
  __ASM__("movdqu %xmm6 , 0x0D8(" #reg ")");                                   \
  __ASM__("movdqu %xmm7 , 0x0E8(" #reg ")");                                   \
  __ASM__("movdqu %xmm8 , 0x0F8(" #reg ")");                                   \
  __ASM__("movdqu %xmm9 , 0x108(" #reg ")");                                   \
  __ASM__("movdqu %xmm10, 0x118(" #reg ")");                                   \
  __ASM__("movdqu %xmm11, 0x128(" #reg ")");                                   \
  __ASM__("movdqu %xmm12, 0x138(" #reg ")");                                   \
  __ASM__("movdqu %xmm13, 0x148(" #reg ")");                                   \
  __ASM__("movdqu %xmm14, 0x158(" #reg ")");                                   \
  __ASM__("movdqu %xmm15, 0x168(" #reg ")");

#define load_xmm_after_gpr(reg)                                                \
  __ASM__("movdqu 0x078(" #reg "), %xmm0");                                    \
  __ASM__("movdqu 0x088(" #reg "), %xmm1");                                    \
  __ASM__("movdqu 0x098(" #reg "), %xmm2");                                    \
  __ASM__("movdqu 0x0A8(" #reg "), %xmm3");                                    \
  __ASM__("movdqu 0x0B8(" #reg "), %xmm4");                                    \
  __ASM__("movdqu 0x0C8(" #reg "), %xmm5");                                    \
  __ASM__("movdqu 0x0D8(" #reg "), %xmm6");                                    \
  __ASM__("movdqu 0x0E8(" #reg "), %xmm7");                                    \
  __ASM__("movdqu 0x0F8(" #reg "), %xmm8");                                    \
  __ASM__("movdqu 0x108(" #reg "), %xmm9");                                    \
  __ASM__("movdqu 0x118(" #reg "), %xmm10");                                   \
  __ASM__("movdqu 0x128(" #reg "), %xmm11");                                   \
  __ASM__("movdqu 0x138(" #reg "), %xmm12");                                   \
  __ASM__("movdqu 0x148(" #reg "), %xmm13");                                   \
  __ASM__("movdqu 0x158(" #reg "), %xmm14");                                   \
  __ASM__("movdqu 0x168(" #reg "), %xmm15");

// symbol used by assembly code
extern "C" {

const void *load_call_context_arm64(ContextA64 *ctx, void *func, char *buff) {
  auto regptr = reinterpret_cast<ContextA64 *>(buff);

  std::memcpy(regptr->r, ctx->r, sizeof(regptr->r));
  std::memcpy(regptr->v, ctx->v, sizeof(regptr->v));
  return func;
}

void save_call_context_arm64(ContextA64 *ctx, char *buff) {
  auto regptr = reinterpret_cast<ContextA64 *>(buff);

  std::memcpy(ctx->r, regptr->r, sizeof(regptr->r) - 2 * 8 /* ignore lr,sp */);
  std::memcpy(ctx->v, regptr->v, sizeof(regptr->v));
}

uint64_t pickup_sp_arm64(ContextA64 *ctx) { return ctx->r[A64_SP]; }

uint64_t pickup_rsp(ContextX64 *context) { return context->rsp; }

void load_vmp_stack(char *tmpsp, const char *vmsp) {
  constexpr size_t size = 0x1000;
  memcpy(tmpsp, vmsp, size);
}

} // end of extern "C"

void __NAKED__ host_call_asm(void *ctx, const void *func) {
#if __arm64__ || __aarch64__
  __ASM__("sub sp, sp, #0x400");
  save_gpr_a64(); /*save orig host context*/
  save_neon_a64();

  /*currently x0 is ctx, x1 is func*/
  __ASM__("sub sp, sp, #0x400");
  __ASM__("mov x2, sp");
  __ASM__("str x0, [sp, #0x3f0]"); /*save ctx*/
#if __APPLE__
  __ASM__("bl _load_call_context_arm64"); /*load exec context to buffer*/
#else
  __ASM__("bl load_call_context_arm64");
#endif
  __ASM__("str x0, [sp, #0x3f8]"); /*save the callee*/

  __ASM__("ldr x0, [sp, #0x3f0]"); /*load ctx*/
#if __APPLE__
  __ASM__("bl _pickup_sp_arm64");
#else
  __ASM__("bl pickup_sp_arm64");
#endif
  __ASM__("mov x1, x0");
  __ASM__("mov x2, #" switch_stack_strsize);
  __ASM__("sub sp, sp, x2"); // alloc 4kb space
  __ASM__("mov x0, sp");
#if __APPLE__
  __ASM__("bl _load_vmp_stack"); /*copy interp sp to host*/
#else
  __ASM__("bl load_vmp_stack");
#endif
  __ASM__("add sp, sp, #" switch_stack_strsize);

  load_gpr_a64(); /*load exec context to host*/
  load_neon_a64();

  __ASM__("ldr x17, [sp, #0x3f8]");              /*get the exec insn*/
  __ASM__("mov x29, sp");                        /*save current sp*/
  __ASM__("sub sp, sp, #" switch_stack_strsize); /*let sp be our temp stack*/
  __ASM__("blr x17");                            /*exec the insn*/

  __ASM__("mov x30, x29");                       /*save call-before sp*/
  __ASM__("add sp, sp, #" switch_stack_strsize); /*restore current sp*/
  save_gpr_a64();                                /*save exec context to buffer*/
  save_neon_a64();

  __ASM__("ldr x0, [sp, #0x3f0]"); /*load ctx*/
  __ASM__("mov x1, sp");
  __ASM__("sub sp, sp, #" switch_stack_strsize); /*let sp be our temp stack*/
#if __APPLE__
  __ASM__("bl _save_call_context_arm64"); /*save interp context to global
                                     context context*/
#else
  __ASM__("bl save_call_context_arm64");
#endif
  __ASM__("add sp, sp, #" switch_stack_strsize);
  __ASM__("add sp, sp, #0x400");

  load_gpr_a64(); /*restore orig host context*/
  load_neon_a64();

  __ASM__("add sp, sp, #0x400");
  __ASM__("ret");
#elif __x86_64__ || __x64__
  /*
   save host context
   load vm context
   call target
   save vm context
   load host context
   */
  __ASM__("subq $768, %rsp"); // gpr+xmm+st+rflags=8*16+16*16+10*8+8=472==>768
  save_gpr(% rsp);
  save_xmm_after_gpr(% rsp);
  // save rflags/float-stack
  __ASM__("fnsave 0x280(%rsp)");
  __ASM__("frstor 0x280(%rsp)");

  // convert Win64 ABI to System-V ABI
#ifdef _WIN32
  __ASM__("movq %rcx, %rdi");
#endif

  // currently, rdi=context
  __ASM__("pushq %rdi"); // save context
#if __APPLE__
  __ASM__("call _pickup_rsp");
#else
#ifdef _WIN32
  __ASM__("movq %rdi, %rcx");
  __ASM__("movq %rsi, %rdx");
#endif
  __ASM__("call pickup_rsp");
#endif
  __ASM__("popq %r11");          // load context
  __ASM__("pushq %r11");         // save context
  __ASM__("movq %rax, %rsi");    // arg1=vm stack
  __ASM__("movq $0x1000, %rdx"); // arg2=size
  __ASM__("subq %rdx, %rsp");    // alloc 4kb space
  __ASM__("movq %rsp, %rdi");    // arg0=host stack
  __ASM__("pushq %r11");         // save context
#if __APPLE__
  __ASM__("callq _load_vmp_stack"); /*copy interp sp to host*/
#else
#ifdef _WIN32
  __ASM__("movq %rdx, %r8");
  __ASM__("movq %rcx, %r9");
  __ASM__("movq %rdi, %rcx");
  __ASM__("movq %rsi, %rdx");
#endif
  __ASM__("callq load_vmp_stack");
#endif
  __ASM__("popq %r11"); // load context
  load_gpr_r11();
  load_xmm_after_gpr(% r11);
  __ASM__("frstor 0x280(%r11)");     // load float stack
  __ASM__("movq %rsp, -0x10(%r11)"); // save stack before call
  __ASM__("callq *-0x8(%r11)");      // call the target
  __ASM__("addq $0x1000, %rsp");     // free stack 4kb
  __ASM__("popq %r11");              // load context
  __ASM__("movq %rsp, -0x18(%r11)"); // save stack after call
  save_gpr(% r11);
  save_xmm_after_gpr(% r11);
  __ASM__("fnsave 0x280(%r11)");

  load_gpr(% rsp);
  load_xmm_after_gpr(% rsp);
  __ASM__("addq $768, %rsp");
  __ASM__("retq");
#else
#error Unsupported host architecture.
#endif
}

void host_call(void *ctx, const void *func) {
#if __arm64__ || __aarch64__
  host_call_asm(ctx, func);
#else
  struct ContextCallX64 {
    uint64_t sp_after;  // stack after call
    uint64_t sp_before; // stack before call
    const void *target;
    ContextX64 context;
  };

  ContextCallX64 callctx;
  callctx.sp_after = 0;
  callctx.sp_before = 0;
  callctx.target = func;
  callctx.context = *reinterpret_cast<ContextX64 *>(ctx);
  host_call_asm(&callctx.context, func);
  std::memcpy(ctx, &callctx.context, sizeof(callctx.context));

  // process retn xx situation
  callctx.sp_before +=
      0x1000 + sizeof(void *); // 0x1000 temp stack + ptrsz context
  context->rsp.q += (callctx.sp_after - callctx.sp_before);
#endif
}

void __NAKED__ host_naked_syscall() {
#if __arm64__ || __aarch64__
#if __APPLE__
  __ASM__("svc #0x80");
#else
  __ASM__("svc #0x0");
#endif
  __ASM__("ret");
#elif __x86_64__ || __x64__
  __AMS__("syscall");
  __ASM__("ret");
#else
#error Unsupported host architecture.
#endif
}

} // namespace icpp
