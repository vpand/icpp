/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "exec.h"
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
  // instructions manually the unicorn engine can just execute those simple
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
  while (pc != reinterpret_cast<uint64_t>(topReturn())) {
    auto step = runcfg_.stepSize();
    if (execPreprocess(pc, step)) {
      continue;
    }

    auto err = uc_emu_start(uc_, pc, -1, 0, step);
    if (err != UC_ERR_OK) {
      std::cout << "Fatal error occurred: " << uc_strerror(err)
                << ", current pc=0x" << std::hex << pc << "." << std::endl;
      break;
    }
    switch (object_->arch()) {
    case AArch64:
      uc_reg_read(uc_, UC_ARM64_REG_PC, &pc);
      break;
    case X86_64:
      uc_reg_read(uc_, UC_X86_REG_RIP, &pc);
      break;
    default:
      return;
    }
  }
}

void ExecEngine::initMainRegisterAArch64() {
  // x0: argc
  // x1: argv
  uc_reg_write(uc_, UC_ARM64_REG_X0,
               reinterpret_cast<const void *>(iargs_.size()));
  uc_reg_write(uc_, UC_ARM64_REG_X1,
               reinterpret_cast<const void *>(&iargs_[0]));
  uc_reg_write(uc_, UC_ARM64_REG_SP, topStack());
  uc_reg_write(uc_, UC_ARM64_REG_LR, topReturn());
}

void ExecEngine::initMainRegisterCommonX64() {
  auto rsp = reinterpret_cast<void **>(topStack());
  // push topReturn()
  rsp--;
  rsp[0] = topReturn();
  uc_reg_write(uc_, UC_X86_REG_RSP, reinterpret_cast<const void *>(rsp));
}

void ExecEngine::initMainRegisterSysVX64() {
  // System V ADM64 ABI
  // rdi: argc
  // rsi: argv
  uc_reg_write(uc_, UC_X86_REG_RDI,
               reinterpret_cast<const void *>(iargs_.size()));
  uc_reg_write(uc_, UC_X86_REG_RSI, reinterpret_cast<const void *>(&iargs_[0]));
  initMainRegisterCommonX64();
}

void ExecEngine::initMainRegisterWinX64() {
  // Microsoft Windows X64 ABI
  // rcx: argc
  // rdx: argv
  uc_reg_write(uc_, UC_X86_REG_RCX,
               reinterpret_cast<const void *>(iargs_.size()));
  uc_reg_write(uc_, UC_X86_REG_RDX, reinterpret_cast<const void *>(&iargs_[0]));
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
