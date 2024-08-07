/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <cstdint>
#include <string_view>

#if __arm64__ || __aarch64__
#define ARCH_ARM64 1
#elif __x86_64__ || __x64__ || _M_AMD64
#define ARCH_X64 1
#else
#error Unsupported host architecture.
#endif

namespace icpp {

enum ArchType {
  Unsupported,
  X86_64,
  AArch64,
};

enum ObjectType {
  MachO_Reloc,
  MachO_Exe,
  ELF_Reloc,
  ELF_Exe,
  COFF_Reloc,
  COFF_Exe,
};

enum SystemType {
  Windows,
  macOS,
  Linux,
  Android,
  iOS,
};

enum InsnType {
  // common instruction
  INSN_ABORT = 0, // invalid opcode
  INSN_HARDWARE,  // will be emulated by unicorn engine
  // conditional jump instruction, e.g.:
  // b.ne, tbz, cbz in arm64
  // jnz, jgl, je in x86_64
  INSN_CONDJUMP,

  // arm64 instruction
  INSN_ARM64_RETURN,
  INSN_ARM64_SYSCALL,
  INSN_ARM64_CALL,
  INSN_ARM64_CALLREG,
  INSN_ARM64_JUMP,
  INSN_ARM64_JUMPREG,
  INSN_ARM64_ADR,
  INSN_ARM64_ADRP,
  INSN_ARM64_LDRSWL,
  INSN_ARM64_LDRWL,
  INSN_ARM64_LDRXL,
  INSN_ARM64_LDRSL,
  INSN_ARM64_LDRDL,
  INSN_ARM64_LDRQL,

  // x86_64 instruction
  INSN_X64_RETURN,
  INSN_X64_SYSCALL,
  INSN_X64_CALL,
  INSN_X64_CALLREG,
  INSN_X64_CALLMEM,
  INSN_X64_JUMP,
  INSN_X64_JUMPCOND,
  INSN_X64_JUMPREG,
  INSN_X64_JUMPMEM,
  INSN_X64_MOV8RM,
  INSN_X64_MOV8MR,
  INSN_X64_MOV8MI,
  INSN_X64_MOV16RM,
  INSN_X64_MOV16MR,
  INSN_X64_MOV16MI,
  INSN_X64_MOV32RM,
  INSN_X64_MOV32MR,
  INSN_X64_MOV32MI,
  INSN_X64_MOV64RM,
  INSN_X64_MOV64MR,
  INSN_X64_MOV64MI32,
  INSN_X64_LEA32,
  INSN_X64_LEA64,
  INSN_X64_MOVAPSRM,
  INSN_X64_MOVAPSMR,
  INSN_X64_MOVUPSRM,
  INSN_X64_MOVUPSMR,
  INSN_X64_MOVAPDRM,
  INSN_X64_MOVAPDMR,
  INSN_X64_MOVUPDRM,
  INSN_X64_MOVUPDMR,
  INSN_X64_CMP8MI,
  INSN_X64_CMP8MI8,
  INSN_X64_CMP16MI,
  INSN_X64_CMP16MI8,
  INSN_X64_CMP32MI,
  INSN_X64_CMP32MI8,
  INSN_X64_CMP64MI32,
  INSN_X64_CMP64MI8,
  INSN_X64_CMP8RM,
  INSN_X64_CMP16RM,
  INSN_X64_CMP32RM,
  INSN_X64_CMP64RM,
  INSN_X64_CMP8MR,
  INSN_X64_CMP16MR,
  INSN_X64_CMP32MR,
  INSN_X64_CMP64MR,
  INSN_X64_MOVSX16RM8,
  INSN_X64_MOVSX16RM16,
  INSN_X64_MOVSX16RM32,
  INSN_X64_MOVSX32RM8,
  INSN_X64_MOVSX32RM16,
  INSN_X64_MOVSX32RM32,
  INSN_X64_MOVSX64RM8,
  INSN_X64_MOVSX64RM16,
  INSN_X64_MOVSX64RM32,
  INSN_X64_MOVZX16RM8,
  INSN_X64_MOVZX16RM16,
  INSN_X64_MOVZX32RM8,
  INSN_X64_MOVZX32RM16,
  INSN_X64_MOVZX64RM8,
  INSN_X64_MOVZX64RM16,
  INSN_X64_TEST8MI,
  INSN_X64_TEST8MR,
  INSN_X64_TEST16MI,
  INSN_X64_TEST16MR,
  INSN_X64_TEST32MI,
  INSN_X64_TEST32MR,
  INSN_X64_TEST64MI32,
  INSN_X64_TEST64MR,
  INSN_X64_CMOV16RM,
  INSN_X64_CMOV32RM,
  INSN_X64_CMOV64RM,

  INSN_TYPE_MAX,
};

constexpr int A64_FP = 29;
constexpr int A64_LR = 30;
constexpr int A64_SP = 31;

struct ContextA64 {
  // general purpose register
  uint64_t r[32]; // 0-28,29-fp,30-lr,31-sp
  // neon vector register
  uint8_t v[32][16];
};

struct ContextX64 {
  // general purpose register
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rbp;
  uint64_t rsi;
  uint64_t rdi;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  // simd xmm register
  uint8_t xmm[32][16];
  // rflags
  // https://en.wikipedia.org/wiki/FLAGS_register
  union {
    struct {
      uint64_t CF : 1, Rsv1 : 1, PF : 1, Rsv3 : 1, AF : 1, Rsv5 : 1, ZF : 1,
          SF : 1, TF : 1, IF : 1, DF : 1, OF : 1, IOPL : 2, NT : 1, RSV15 : 1,
          RF : 1, VM : 1, AC : 1, VIF : 1, VIP : 1, ID : 1, Rsv22 : 10,
          Rsv32 : 32;
    } bit;
    uint64_t val;
  } rflags;
  // float number regster
  uint16_t fctrl;
  uint8_t fstats[26];
  uint8_t stmmx[8][10];
  // stack pointer register
  uint64_t rsp;
};

enum ConditionTypeX64 {
  CONDT_jae = 0,
  CONDT_ja,
  CONDT_jbe,
  CONDT_jb,
  CONDT_je,
  CONDT_jge,
  CONDT_jg,
  CONDT_jle,
  CONDT_jl,
  CONDT_jne,
  CONDT_jno,
  CONDT_jnp,
  CONDT_jns,
  CONDT_jo,
  CONDT_jp,
  CONDT_js,
  CONDT_jrcxz,
  CONDT_jecxz,
  CONDT_x64_end,
};

#if ARCH_ARM64
typedef ContextA64 ContextICPP;
#else
typedef ContextX64 ContextICPP;
#endif

// the stack switch size between the host and interpreter vm
#define switch_stack_strsize "0x1000"
constexpr const int switch_stack_size = 0x1000;

ArchType host_arch();
SystemType host_system();
std::string_view arch_name(ArchType arch);
std::string_view system_name(SystemType arch);

// load the current host register context to ctx, used to initialize
// the original context for interpreter
void host_context(ContextICPP *ctx);

// call a host function with specified register context,
// ctx is a ContextA64 or ContextX64 instance,
// func is a host function address
void host_call(void *ctx, const void *func);

// execute a host raw syscall instruction,
// you can use it with specified register context to do the real work,
// e.g.: host_call(context, host_naked_syscall)
void host_naked_syscall();

// execute a host cmp/test instruction,
// return the updated rflags
uint64_t host_naked_compare1(uint64_t left, uint64_t right);
uint64_t host_naked_compare2(uint64_t left, uint64_t right);
uint64_t host_naked_compare4(uint64_t left, uint64_t right);
uint64_t host_naked_compare8(uint64_t left, uint64_t right);
uint64_t host_naked_test1(uint64_t left, uint64_t right);
uint64_t host_naked_test2(uint64_t left, uint64_t right);
uint64_t host_naked_test4(uint64_t left, uint64_t right);
uint64_t host_naked_test8(uint64_t left, uint64_t right);

template <typename T> uint64_t host_compare(uint64_t left, uint64_t right) {
  switch (sizeof(T)) {
  case 1:
    return host_naked_compare1(left, right);
  case 2:
    return host_naked_compare2(left, right);
  case 4:
    return host_naked_compare4(left, right);
  default:
    return host_naked_compare8(left, right);
  }
}

template <typename T> uint64_t host_test(uint64_t left, uint64_t right) {
  switch (sizeof(T)) {
  case 1:
    return host_naked_test1(left, right);
  case 2:
    return host_naked_test2(left, right);
  case 4:
    return host_naked_test4(left, right);
  default:
    return host_naked_test8(left, right);
  }
}

// fill the host return instruction's opcode into an int64_t
uint64_t host_insn_rets();

/*
when vm registers a callback function to host, we must dynamically
generate a executable host callback wrapper to it, otherwise program
will crash as all of the iobject pages are not executable, e.g.:

original:
  sysapi(...vmfunc...);

wrapped:
  sysapi(...vmfunc_stub...);
  vmfunc_stub:
    ...
    ExecEngine.run(vmfunc);
    ...
*/
struct StubContext {
  const void *context;
  uint64_t vmfunc;
};
const void *host_callback_stub(const StubContext &ctx, char *&codeptr);

} // namespace icpp
