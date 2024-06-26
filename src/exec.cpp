/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "exec.h"
#include "debugger.h"
#include "loader.h"
#include "object.h"
#include "runcfg.h"
#include "utils.h"

#include <llvm/ADT/Twine.h>
#include <llvm/BinaryFormat/Magic.h>

namespace icpp {

struct ExecEngine {
  ExecEngine(std::unique_ptr<Object> object,
             const std::vector<std::string> &deps, const char *procfg,
             const std::vector<const char *> &iargs)
      : loader_(object.get(), deps), runcfg_(procfg), iargs_(iargs),
        object_(object.get()) {
    auto err = uc_open(object->ucArch(), object->ucMode(), &uc_);
    if (err != UC_ERR_OK) {
      std::cout << "Failed to create unicorn engine instance: "
                << uc_strerror(err) << std::endl;
      return;
    }
    if (runcfg_.hasDebugger()) {
      debugger_ = std::make_unique<Debugger>();
    }
    stack_.resize(runcfg_.stackSize());
  }
  ~ExecEngine() {
    if (uc_) {
      uc_close(uc_);
    }
  }

  void run();

private:
  void execCtor();
  void initMainRegister();
  void execMain();
  void execDtor();
  void execLoop(uint64_t pc);
  bool interpret(const InsnInfo *&inst, uint64_t &pc, int &step);

  void initMainRegisterAArch64();
  void initMainRegisterSysVX64();
  void initMainRegisterWinX64();
  void initMainRegisterCommonX64();

  ContextA64 loadRegisterAArch64();
  void saveRegisterAArch64(const ContextA64 &ctx);
  ContextX64 loadRegisterX64();
  void saveRegisterX64(const ContextX64 &ctx);

  char *topStack() {
    return reinterpret_cast<char *>(stack_.data()) + runcfg_.stackSize();
  }

  constexpr void *topReturn() { return static_cast<void *>(this); }

private:
  Loader loader_;
  RunConfig runcfg_;
  const std::vector<const char *> &iargs_;

  Object *object_ = nullptr;
  uc_engine *uc_ = nullptr;
  std::unique_ptr<Debugger> debugger_;

  std::string stack_;
};

void ExecEngine::execCtor() {}

void ExecEngine::initMainRegister() {
  switch (object_->arch()) {
  case AArch64:
    initMainRegisterAArch64();
    break;
  case X86_64:
    switch (object_->type()) {
    case COFF_Exe:
    case COFF_Reloc:
      initMainRegisterWinX64();
      break;
    default:
      initMainRegisterSysVX64();
      break;
    }
    break;
  default:
    break;
  }
}

void ExecEngine::execMain() {
  initMainRegister();
  execLoop(reinterpret_cast<uint64_t>(object_->mainEntry()));
}

ContextA64 ExecEngine::loadRegisterAArch64() {
  ContextA64 ctx;
  for (int i = 0; i <= 28; i++) {
    uc_reg_read(uc_, UC_ARM64_REG_X0 + i, &ctx.r[i]);
  }
  uc_reg_read(uc_, UC_ARM64_REG_X29, &ctx.r[A64_FP]);
  uc_reg_read(uc_, UC_ARM64_REG_X30, &ctx.r[A64_LR]);
  uc_reg_read(uc_, UC_ARM64_REG_SP, &ctx.r[A64_SP]);
  for (int i = 0; i < 32; i++) {
    uc_reg_read(uc_, UC_ARM64_REG_V0 + i, &ctx.v[i]);
  }
  return ctx;
}

void ExecEngine::saveRegisterAArch64(const ContextA64 &ctx) {
  for (int i = 0; i <= 28; i++) {
    uc_reg_write(uc_, UC_ARM64_REG_X0 + i, &ctx.r[i]);
  }
  uc_reg_write(uc_, UC_ARM64_REG_X29, &ctx.r[A64_FP]);
  uc_reg_write(uc_, UC_ARM64_REG_X30, &ctx.r[A64_LR]);
  uc_reg_write(uc_, UC_ARM64_REG_SP, &ctx.r[A64_SP]);
  for (int i = 0; i < 32; i++) {
    uc_reg_write(uc_, UC_ARM64_REG_V0 + i, &ctx.v[i]);
  }
}

ContextX64 ExecEngine::loadRegisterX64() {
  ContextX64 ctx;
  uc_reg_read(uc_, UC_X86_REG_RSP, &ctx.rsp);
  uc_reg_read(uc_, UC_X86_REG_RBP, &ctx.rbp);
  uc_reg_read(uc_, UC_X86_REG_RAX, &ctx.rax);
  uc_reg_read(uc_, UC_X86_REG_RBX, &ctx.rbx);
  uc_reg_read(uc_, UC_X86_REG_RCX, &ctx.rcx);
  uc_reg_read(uc_, UC_X86_REG_RDX, &ctx.rdx);
  uc_reg_read(uc_, UC_X86_REG_RSI, &ctx.rsi);
  uc_reg_read(uc_, UC_X86_REG_RDI, &ctx.rdi);
  uc_reg_read(uc_, UC_X86_REG_R8, &ctx.r8);
  uc_reg_read(uc_, UC_X86_REG_R9, &ctx.r9);
  uc_reg_read(uc_, UC_X86_REG_R10, &ctx.r10);
  uc_reg_read(uc_, UC_X86_REG_R11, &ctx.r11);
  uc_reg_read(uc_, UC_X86_REG_R12, &ctx.r12);
  uc_reg_read(uc_, UC_X86_REG_R13, &ctx.r13);
  uc_reg_read(uc_, UC_X86_REG_R14, &ctx.r14);
  uc_reg_read(uc_, UC_X86_REG_R15, &ctx.r15);
  for (int i = 0; i < 8; i++) {
    uc_reg_read(uc_, UC_X86_REG_ST0 + i, &ctx.stmmx[i]);
  }
  for (int i = 0; i < 32; i++) {
    uc_reg_read(uc_, UC_X86_REG_XMM0, &ctx.xmm[i]);
  }
  return ctx;
}

void ExecEngine::saveRegisterX64(const ContextX64 &ctx) {
  uc_reg_write(uc_, UC_X86_REG_RSP, &ctx.rsp);
  uc_reg_write(uc_, UC_X86_REG_RBP, &ctx.rbp);
  uc_reg_write(uc_, UC_X86_REG_RAX, &ctx.rax);
  uc_reg_write(uc_, UC_X86_REG_RBX, &ctx.rbx);
  uc_reg_write(uc_, UC_X86_REG_RCX, &ctx.rcx);
  uc_reg_write(uc_, UC_X86_REG_RDX, &ctx.rdx);
  uc_reg_write(uc_, UC_X86_REG_RSI, &ctx.rsi);
  uc_reg_write(uc_, UC_X86_REG_RDI, &ctx.rdi);
  uc_reg_write(uc_, UC_X86_REG_R8, &ctx.r8);
  uc_reg_write(uc_, UC_X86_REG_R9, &ctx.r9);
  uc_reg_write(uc_, UC_X86_REG_R10, &ctx.r10);
  uc_reg_write(uc_, UC_X86_REG_R11, &ctx.r11);
  uc_reg_write(uc_, UC_X86_REG_R12, &ctx.r12);
  uc_reg_write(uc_, UC_X86_REG_R13, &ctx.r13);
  uc_reg_write(uc_, UC_X86_REG_R14, &ctx.r14);
  uc_reg_write(uc_, UC_X86_REG_R15, &ctx.r15);
  for (int i = 0; i < 8; i++) {
    uc_reg_write(uc_, UC_X86_REG_ST0 + i, &ctx.stmmx[i]);
  }
  for (int i = 0; i < 32; i++) {
    uc_reg_write(uc_, UC_X86_REG_XMM0, &ctx.xmm[i]);
  }
}

bool ExecEngine::interpret(const InsnInfo *&inst, uint64_t &pc, int &step) {
  // we should interpret the relocation, branch, jump, call and syscall
  // instructions manually, the unicorn engine can just execute those simple
  // instructions (i.e., instruction without relocation and jump operation) in
  // our case
  unsigned origstep = step;
  auto curi = inst;
  if (step <= 0) {
    // calculate the maximized steps that can be passed to uc_emu_start
    for (step = 0; curi->type == INSN_HARDWARE; curi++, step++)
      ;
  } else {
    // check whether the step-count instructions have relocation/jump-operation
    // or not if so, the step size should be re-adjusted
    int tmpstep = 0;
    for (; curi->type == INSN_HARDWARE; curi++, tmpstep++)
      ;
    step = std::min(step, tmpstep);
  }
  if (step) {
    // indicates the current instruction hasn't been processed and should let
    // uc_emu_start continue to execute it
    return false;
  }
  // interpret the pre-decoded instructions
  for (unsigned i = 0; i < origstep && inst->type != INSN_HARDWARE; i++) {
    bool jump = false;
    switch (inst->type) {
    // common instruction
    case INSN_ABORT:
      UNIMPL_ABORT();
      break;
    // arm64 instruction
    case INSN_ARM64_RETURN: {
      uint64_t retaddr;
      uc_reg_read(uc_, UC_ARM64_REG_LR, &retaddr);
      if (object_->cover(retaddr)) {
        pc = retaddr;
        inst = object_->insnInfo(pc);
        jump = true;
      } else if (reinterpret_cast<const void *>(retaddr) == topReturn()) {
        pc = retaddr; // finished interpreting
        return true;
      }
      break;
    }
    case INSN_ARM64_SYSCALL:
      UNIMPL_ABORT();
      break;
    // encoded meta data layout:[uint64_t]
    case INSN_ARM64_CALL: {
      auto retaddr = pc + inst->len;
      if (inst->rflag) {
        // call external function
        auto target = object_->relocTarget(inst->reloc);
        auto context = loadRegisterAArch64();
        context.r[A64_LR] = retaddr; // set return address
        host_call(&context, target);
        saveRegisterAArch64(context);
      } else {
        // call internal function
        auto metaptr = object_->metaInfo<uint64_t>(inst, pc);
        // set return address
        uc_reg_write(uc_, UC_ARM64_REG_LR, &retaddr);
        pc += (metaptr[0] << 2);      // advance pc with bl instruction
        inst = object_->insnInfo(pc); // update current inst
        jump = true;
      }
      break;
    }
    case INSN_ARM64_CALLREG:
      UNIMPL_ABORT();
      break;
    case INSN_ARM64_JUMP:
      UNIMPL_ABORT();
      break;
    case INSN_ARM64_JUMPREG:
      UNIMPL_ABORT();
      break;
    case INSN_ARM64_ADR:
      UNIMPL_ABORT();
      break;
    // encoded meta data layout:[uint16_t, uint64_t]
    case INSN_ARM64_ADRP: {
      auto metaptr = object_->metaInfo<uint16_t>(inst, pc);
      uint64_t target = 0;
      if (inst->rflag) {
        target = reinterpret_cast<uint64_t>(object_->relocTarget(inst->reloc));
      } else {
        auto imm = *reinterpret_cast<const uint64_t *>(&metaptr[1]);
        target = pc + ((imm << 12) & ~((1 << 12) - 1));
      }
      uc_reg_write(uc_, metaptr[0], &target);
      break;
    }
    case INSN_ARM64_LDRSWL:
      UNIMPL_ABORT();
      break;
    case INSN_ARM64_LDRWL:
      UNIMPL_ABORT();
      break;
    case INSN_ARM64_LDRXL:
      UNIMPL_ABORT();
      break;
    case INSN_ARM64_LDRSL:
      UNIMPL_ABORT();
      break;
    case INSN_ARM64_LDRDL:
      UNIMPL_ABORT();
      break;
    case INSN_ARM64_LDRQL:
      UNIMPL_ABORT();
      break;
    // x86_64 instruction
    case INSN_X64_RETURN:
      UNIMPL_ABORT();
      break;
    case INSN_X64_SYSCALL:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CALL:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CALLREG:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CALLMEM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_JUMP:
      UNIMPL_ABORT();
      break;
    case INSN_X64_JUMPREG:
      UNIMPL_ABORT();
      break;
    case INSN_X64_JUMPMEM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV8RR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV8RM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV8MR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV8MI:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV16RR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV16RM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV16MR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV16MI:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV32RR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV32RM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV32MR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV32MI:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV64RR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV64RM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV64MR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOV64MI32:
      UNIMPL_ABORT();
      break;
    case INSN_X64_LEA32:
      UNIMPL_ABORT();
      break;
    case INSN_X64_LEA64:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVAPSRM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVAPSMR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVUPSRM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVUPSMR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVAPDRM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVAPDMR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVUPDRM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVUPDMR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVI:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVIMEM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP8MI:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP8MI8:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP16MI:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP16MI8:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP32MI:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP32MI8:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP64MI32:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP64MI8:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP8RM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP16RM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP32RM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_CMP64RM:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVSX16RM8:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVSX16RM16:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVSX16RM32:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVSX32RM8:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVSX32RM16:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVSX32RM32:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVSX64RM8:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVSX64RM16:
      UNIMPL_ABORT();
      break;
    case INSN_X64_MOVSX64RM32:
      UNIMPL_ABORT();
      break;
    case INSN_X64_TEST8MI:
      UNIMPL_ABORT();
      break;
    case INSN_X64_TEST8MR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_TEST16MI:
      UNIMPL_ABORT();
      break;
    case INSN_X64_TEST16MR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_TEST32MI:
      UNIMPL_ABORT();
      break;
    case INSN_X64_TEST32MR:
      UNIMPL_ABORT();
      break;
    case INSN_X64_TEST64MI32:
      UNIMPL_ABORT();
      break;
    case INSN_X64_TEST64MR:
      UNIMPL_ABORT();
      break;
    default:
      log_print(Runtime, "Unknown instruction type {} at rva {:x}.", inst->type,
                object_->vm2rva(pc));
      abort();
      break;
    }
    // advance to the next instruction if didn't jump
    if (!jump) {
      pc += inst->len;
      inst++;
    }
  }
  // indicates the current instruction has been processed
  return true;
}

void ExecEngine::execLoop(uint64_t pc) {
  if (!pc) {
    return;
  }
  // debugger internal thread
  Debugger::Thread *dbgthread = nullptr;
  if (debugger_)
    dbgthread = debugger_->enter(object_->arch(), uc_);

  // pc register id for different architecture
  int pcreg;
  switch (object_->arch()) {
  case AArch64:
    pcreg = UC_ARM64_REG_PC;
    break;
  case X86_64:
    pcreg = UC_X86_REG_RIP;
    break;
  default:
    UNIMPL_ABORT();
    return;
  }
  // instruction information related to pc
  auto inst = object_->insnInfo(pc);
  // executing loop, break when hitting the initialized return address
  while (pc != reinterpret_cast<uint64_t>(topReturn())) {
    // debugging
    if (debugger_) {
      debugger_->entry(dbgthread, object_->vm2rva(pc));
      if (debugger_->stopped()) {
        // stop executing by user request
        break;
      }
    }

    // interpret relocation, branch, call, jump and syscall etc.
    auto step = runcfg_.stepSize();
    if (interpret(inst, pc, step)) {
      continue;
    }

    // running instructions by unicorn engine
    auto err = uc_emu_start(uc_, pc, -1, 0, step);
    if (err != UC_ERR_OK) {
      std::cout << "Fatal error occurred: " << uc_strerror(err)
                << ", current pc=0x" << std::hex << pc << "." << std::endl;
      break;
    }
    // update inst with step
    inst += step;

    // update current pc
    uc_reg_read(uc_, pcreg, &pc);
  }
  if (debugger_)
    debugger_->leave();
}

#define reg_write(reg, val)                                                    \
  {                                                                            \
    auto u64 = reinterpret_cast<uint64_t>(val);                                \
    uc_reg_write(uc_, reg, &u64);                                              \
  }

void ExecEngine::initMainRegisterAArch64() {
  // x0: argc
  // x1: argv
  reg_write(UC_ARM64_REG_X0, reinterpret_cast<const void *>(iargs_.size()));
  reg_write(UC_ARM64_REG_X1, reinterpret_cast<const void *>(&iargs_[0]));
  reg_write(UC_ARM64_REG_SP, topStack());
  reg_write(UC_ARM64_REG_LR, topReturn());
}

void ExecEngine::initMainRegisterCommonX64() {
  auto rsp = reinterpret_cast<void **>(topStack());
  // push topReturn()
  rsp--;
  rsp[0] = topReturn();
  reg_write(UC_X86_REG_RSP, reinterpret_cast<const void *>(rsp));
}

void ExecEngine::initMainRegisterSysVX64() {
  // System V AMD64 ABI
  // rdi: argc
  // rsi: argv
  reg_write(UC_X86_REG_RDI, reinterpret_cast<const void *>(iargs_.size()));
  reg_write(UC_X86_REG_RSI, reinterpret_cast<const void *>(&iargs_[0]));
  initMainRegisterCommonX64();
}

void ExecEngine::initMainRegisterWinX64() {
  // Microsoft Windows X64 ABI
  // rcx: argc
  // rdx: argv
  reg_write(UC_X86_REG_RCX, reinterpret_cast<const void *>(iargs_.size()));
  reg_write(UC_X86_REG_RDX, reinterpret_cast<const void *>(&iargs_[0]));
  initMainRegisterCommonX64();
}

void ExecEngine::execDtor() {}

void ExecEngine::run() {
  if (!uc_ || !loader_.valid()) {
    return;
  }
  execCtor();
  execMain();
  execDtor();
}

void exec_main(std::string_view path, const std::vector<std::string> &deps,
               const char *procfg, int iargc, char **iargv) {
  llvm::file_magic magic;
  auto err = llvm::identify_magic(llvm::Twine(path), magic);
  if (err) {
    std::cout << "Failed to identify the file type of '" << path
              << "': " << err.message() << std::endl;
    return;
  }

  std::unique_ptr<Object> object;
  using fm = llvm::file_magic;
  switch (magic) {
  case fm::macho_object:
    object = std::make_unique<MachORelocObject>(path);
    break;
  case fm::macho_executable:
    object = std::make_unique<MachOExeObject>(path);
    break;
  case fm::elf_relocatable:
    object = std::make_unique<ELFRelocObject>(path);
    break;
  case fm::elf_executable:
    object = std::make_unique<ELFExeObject>(path);
    break;
  case fm::coff_object:
    object = std::make_unique<COFFRelocObject>(path);
    break;
  case fm::pecoff_executable:
    object = std::make_unique<COFFExeObject>(path);
    break;
  default:
    std::cout << "Unsupported input file type " << magic
              << ", currently supported file type includes "
                 "MachO/ELF/PE-Object/Executable."
              << std::endl;
    return;
  }
  if (!object->valid()) {
    std::cout << "Unsupported input file type " << magic
              << ", currently supported file type includes "
                 "MachO/ELF/PE-Object/Executable-X86_64/AArch64."
              << std::endl;
  }

  // construct arguments passed to the main entry of the input file
  std::vector<const char *> iargs;
  iargs.push_back(path.data());
  for (int i = 0; i < iargc; i++)
    iargs.push_back(iargv[i]);
  ExecEngine(std::move(object), deps, procfg, iargs).run();
}

} // namespace icpp
