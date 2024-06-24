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
  bool execPreprocess(uint64_t &pc, int &step);

  void initMainRegisterAArch64();
  void initMainRegisterSysVX64();
  void initMainRegisterWinX64();
  void initMainRegisterCommonX64();

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

bool ExecEngine::execPreprocess(uint64_t &pc, int &step) {
  // we should process the relocation, branch, jump, call and syscall
  // instructions manually, the unicorn engine can just execute those simple
  // instructions (i.e., instruction without relocation and jump operation) in
  // our case
  if (step <= 0) {
    // calculate the maximized steps that can be passed to uc_emu_start
  } else if (step == 1) {
    // check whether the current instruction has relocation/jump-operation or
    // not
  } else {
    // check whether the step-count instructions have relocation/jump-operation
    // or not if so, the step size should be re-adjusted
  }
  // indicates the current instruction hasn't been processed and should let
  // uc_emu_start continue to execute it
  return false;
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

    // preprocess relocation, branch, call, jump and syscall etc.
    auto step = runcfg_.stepSize();
    if (execPreprocess(pc, step)) {
      continue;
    }

    // running instructions by unicorn engine
    auto err = uc_emu_start(uc_, pc, -1, 0, step);
    if (err != UC_ERR_OK) {
      std::cout << "Fatal error occurred: " << uc_strerror(err)
                << ", current pc=0x" << std::hex << pc << "." << std::endl;
      break;
    }

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
