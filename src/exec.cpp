// Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#include "exec.h"
#include "arch.h"
#include "debugger.h"
#include "loader.h"
#include "object.h"
#include "platform.h"
#include "runcfg.h"
#include "utils.h"

#include <AetherVM.h>
#include <csetjmp>
#include <llvm/ADT/Twine.h>
#include <llvm/BinaryFormat/Magic.h>
#include <llvm/Support/Signals.h>
#include <mutex>

#define LOG_EXECUTION 0

#if ON_WINDOWS && ARCH_ARM64
#define WIN_ARM64 1
#endif

namespace icpp {

struct ExecEngine {
  // clone a new execute engine for thread function
  ExecEngine(ExecEngine &exec)
      : clone_(true), loader_(exec.loader_), iargs_(exec.iargs_),
        iobject_(exec.iobject_), vmstubs_(exec.vmstubs_),
        stubvms_(exec.stubvms_) {
    init();
  }

  ExecEngine(std::shared_ptr<Object> object,
             const std::vector<std::string> &deps,
             const std::vector<const char *> &iargs)
      : loader_(object.get(), deps), iargs_(iargs), iobject_(object) {
    init();
  }

  ~ExecEngine() {
    if (clone_)
      return;

    // execute destructor in iobject file
    execDtor();

    auto rets = host_insn_rets();
    for (auto page : stubpages_) {
      auto iptr = reinterpret_cast<uint64_t *>(page);
      // as the script may have registered callback to host system,
      // we can't simply free this page, so fill them with return instructions.
      page_writable(page);
      for (int i = 0; i < mem_page_size / 8; i++, *iptr++ = rets)
        ;
      page_executable(page);
      page_flush(page);
    }
  }

  int run(bool lib = false);
  bool run(uint64_t vm, uint64_t arg0, uint64_t arg1);
  void run(uint64_t pc, ContextICPP *regs);
  uint64_t returnValue(); // get x0/rax register value
  void dump();

private:
  void init();

  /*
  object constructor, main and destructor executor
  */
  bool execCtor();
  bool execMain();
  bool execDtor();
  bool execLoop(uint64_t pc);

  // executable check and get the iobject instance which this pc belongs to,
  // it may update the current running iobject if necessary
  bool executable(uint64_t target);

  // icpp interpret entry
  bool interpret(const InsnInfo *&inst, uint64_t &pc, int &step);

  // some special functions should be invoked with stub helper
  // e.g.: thread create, system api callback, etc.
  // if target is kind of abort, exit or throw, the retaddr will be modified to
  // stop interpreting
  bool specialCallProcess(uint64_t &target, uint64_t &retaddr);

  /*
  helper routines for aarch64
  */
  bool interpretCallAArch64(const InsnInfo *&inst, uint64_t &pc,
                            uint64_t target);
  bool interpretJumpAArch64(const InsnInfo *&inst, uint64_t &pc,
                            uint64_t target);
  void interpretPCLdrAArch64(const InsnInfo *&inst, uint64_t &pc);

  /*
  helper routines for x86_64
  */
  bool interpretCallX64(const InsnInfo *&inst, uint64_t &pc, uint64_t target);
  bool interpretJumpX64(const InsnInfo *&inst, uint64_t &pc, uint64_t target);
  uint64_t interpretCalcMemX64(const InsnInfo *&inst, uint64_t &pc, int memop,
                               const uint16_t **opsptr = nullptr);
  template <typename T>
  void interpretMovX64(const InsnInfo *&inst, uint64_t &pc, int regop,
                       int memop, bool movrm);
  void interpretMovMRX64(const InsnInfo *&inst, uint64_t &pc, int bytes);
  template <typename T>
  void interpretMovMIX64(const InsnInfo *&inst, uint64_t &pc);
  template <typename TSRC, typename TDES>
  void interpretFlagsMemImm(const InsnInfo *&inst, uint64_t &pc, bool cmp);
  template <typename T>
  void interpretFlagsRegMem(const InsnInfo *&inst, uint64_t &pc, bool cmp);
  template <typename T>
  void interpretFlagsMemReg(const InsnInfo *&inst, uint64_t &pc, bool cmp);
  template <typename TSRC, typename TDES>
  void interpretSignExtendRegMem(const InsnInfo *&inst, uint64_t &pc);
  template <typename TSRC, typename TDES>
  void interpretZeroExtendRegMem(const InsnInfo *&inst, uint64_t &pc);
  void interpretCondMovRegMem(const InsnInfo *&inst, uint64_t &pc);
  void interpretSSERegMem(const InsnInfo *&inst, uint64_t &pc);

  /*
  register startup initializer
  */
  void initMainRegister(const void *argc, const void *argv);
  void initMainRegisterAArch64(const void *argc, const void *argv);
  void initMainRegisterSysVX64(const void *argc, const void *argv);
  void initMainRegisterWinX64(const void *argc, const void *argv);
  void initMainRegisterCommonX64();

  /*
  helper routines for AetherVM and host register context switch
  */
  ContextA64 loadRegisterAArch64();
  void saveRegisterAArch64(const ContextA64 &ctx);
  ContextX64 loadRegisterX64();
  void saveRegisterX64(const ContextX64 &ctx);

  char *topStack() {
    return reinterpret_cast<char *>(stack_.data()) +
           RunConfig::inst()->stackSize() - switch_stack_size;
  }

  constexpr void *topReturn() {
    return topreturn_ ? topreturn_ : static_cast<void *>(this);
  }

  // create a new stub function for the target
  uint64_t createStub(uint64_t vmfunc);

  // check whether the target is a stub or not, if so returns the
  // vm target directly
  uint64_t checkStub(uint64_t target) {
    auto found = stubvms_.find(target);
    return found != stubvms_.end() ? found->second : target;
  }

  void writeRegister(int reg, const void *pvalue) { abort(); }

private:
  // this is a cloned instance
  bool clone_ = false;

  // object dependency module loader
  Loader loader_;
  // argc and argv for object main entry
  const std::vector<const char *> &iargs_;

  // current running object instance
  Object *robject_ = nullptr;
  // the initial object instance
  std::shared_ptr<Object> iobject_;

  // virtual processor from AetherVM
  aether::BinaryEngine engine_ = nullptr;
  // virtual processor debugger working with vmpstudio plugin
  // see ICPP_SRC/vmpstudio for more information
  Debugger *debugger_ = nullptr;

  // vm stack
  std::string stack_;
  // used to resume some fatal error, e.g.: segfault
  std::jmp_buf jmpbuf_;

  // exit code
  int exitcode_ = 0;

  // dynamically registered dtors by atexit, __cxa_atexit, etc.
  struct Atexit {
    Object *object;
    uint64_t vm;
    uint64_t args[2];
  };
  std::vector<Atexit> dyndtors_;

  // callback functions' stub code page
  std::vector<char *> stubpages_;
  // current available stub code start address
  char *stubcode_ = nullptr, *stubend_ = nullptr;
  // <vm, stub> caches
  std::map<uint64_t, uint64_t> vmstubs_;
  // <stub, vm> caches
  std::map<uint64_t, uint64_t> stubvms_;
  void *topreturn_ = nullptr; // return address when called from stub

#if WIN_ARM64
  char *wintls_ = nullptr;
#endif
};

// current thread execution engine instance
static thread_local ExecEngine *exec_engine = nullptr;
// <vm, dyncode> cache, the dyncode is generated by the interpreter to fix some
// instruction which has relocation record
static thread_local std::map<uint64_t, std::vector<uint8_t>> dyn_codes;

void ExecEngine::run(uint64_t pc, ContextICPP *regs) {
  constexpr int stack_switch_size = 128;
  using namespace aether;

  // backup the old context and set a new one
#if ARCH_ARM64
  auto pcrid = Register::PC;
  auto backup = loadRegisterAArch64();
  char *vmstack =
      reinterpret_cast<char *>(backup.r[A64_SP]) - stack_switch_size;
  char *hoststack = reinterpret_cast<char *>(regs->r[A64_SP]);
  topreturn_ = reinterpret_cast<void *>(regs->r[A64_LR]);
  // set vm stack
  regs->r[A64_SP] = reinterpret_cast<uint64_t>(vmstack);
  saveRegisterAArch64(*regs);
#else
  auto pcrid = Register::RIP;
  auto backup = loadRegisterX64();
  char *vmstack = reinterpret_cast<char *>(backup.rsp) - stack_switch_size;
  char *hoststack = reinterpret_cast<char *>(regs->rsp);
  topreturn_ = *reinterpret_cast<void **>(regs->rsp);
  // set vm stack
  regs->rsp = reinterpret_cast<uint64_t>(vmstack);
  saveRegisterX64(*regs);
#endif
  // backup old pc
  uint64_t pcbackup = engine.getRegister(pcrid)->u8;

  // load host stack
  std::memcpy(vmstack, hoststack, stack_switch_size);
  // run the current pc
  execLoop(pc);
  // load vm stack
  std::memcpy(hoststack, vmstack, stack_switch_size);

  topreturn_ = nullptr;

  // save the current context and restore the old one
#if ARCH_ARM64
  *regs = loadRegisterAArch64();
  saveRegisterAArch64(backup);
  regs->r[A64_SP] = reinterpret_cast<uint64_t>(hoststack);
#else
  *regs = loadRegisterX64();
  saveRegisterX64(backup);
  regs->rsp = reinterpret_cast<uint64_t>(hoststack);
#endif
  // restore old pc
  engine.setRegister(pcrid, {.u8 = pcbackup});
}

extern "C" void exec_engine_main(StubContext *ctx, ContextICPP *regs) {
#if ARCH_X64
  // stub code has set rax as rsp
  regs->rsp = regs->rax;
#endif

  auto engine = (ExecEngine *)ctx->engine;
  engine->run(ctx->vmfunc, regs);
}

void ExecEngine::init() {
  exec_engine = this;

  robject_ = iobject_.get();

  // set the initial register context copied from host
  ContextICPP initctx;
  host_context(&initctx);
#if ARCH_ARM64
  saveRegisterAArch64(initctx);
#if WIN_ARM64
  wintls_ = reinterpret_cast<char *>(initctx.r[18]);
#endif
#else
  saveRegisterX64(initctx);
#endif

  if (RunConfig::inst()->hasDebugger()) {
    // initialize debugger instance
    debugger_ = Debugger::inst();
  }
  // interpreter vm stack buffer
  stack_.resize(RunConfig::inst()->stackSize());
}

static inline char *alloc_page(char *&end) {
  auto page = page_alloc();
  page_writable(page);
  end = page + mem_page_size - 0x60;
  return page;
}

bool ExecEngine::execCtor() {
  // initialize the stub code page
  auto stubpots = iobject_->stubSpots();
  if (stubpots.size()) {
    auto page = alloc_page(stubend_);
    stubcode_ = page;
    stubpages_.push_back(page);

    // make function stub, the vm function called from host side must
    // be in stub mode, because the page it belongs to doesn't have the
    // executable permission
    for (auto &spot : stubpots) {
      auto target = *reinterpret_cast<uint64_t *>(spot.vm);
      auto found = vmstubs_.find(target);
      if (found == vmstubs_.end()) {
        // create a new stub for this iobject vm target function
        auto stub = host_callback_stub({this, target}, stubcode_);
        found =
            vmstubs_.insert({target, reinterpret_cast<uint64_t>(stub)}).first;
        stubvms_.insert({found->second, found->first});
        // overflow check
        if (stubcode_ > stubend_) {
          // set the stub page in read&exec mode
          page_executable(page);
          page_flush(page);

          // allocate a new page
          page = alloc_page(stubend_);
          stubcode_ = page;
          stubpages_.push_back(page);
        }
      }
      // redirect to the exeuctable stub
      *reinterpret_cast<uint64_t *>(spot.vm) = found->second;
    }
    stubpots.clear();

    // set the stub page in read&exec mode
    page_executable(page);
    page_flush(page);
  }

  // now, we can execute any of the code in this iobject safely
  for (auto target : iobject_->ctorEntries()) {
    robject_ = iobject_.get();
    if (!run(reinterpret_cast<uint64_t>(target), 0, 0))
      return false;
  }
  return true;
}

bool ExecEngine::execDtor() {
  for (auto target : iobject_->dtorEntries()) {
    robject_ = iobject_.get();
    if (!run(reinterpret_cast<uint64_t>(target), 0, 0))
      return false;
  }
  for (auto &ate : dyndtors_) {
    robject_ = ate.object;
    if (!run(reinterpret_cast<uint64_t>(ate.vm), ate.args[0], ate.args[1]))
      return false;
  }
  return true;
}

void ExecEngine::initMainRegister(const void *argc, const void *argv) {
  switch (robject_->arch()) {
  case AArch64:
    initMainRegisterAArch64(argc, argv);
    break;
  case X86_64:
    switch (robject_->type()) {
    case COFF_Exe:
    case COFF_Reloc:
      initMainRegisterWinX64(argc, argv);
      break;
    default:
      initMainRegisterSysVX64(argc, argv);
      break;
    }
    break;
  default:
    break;
  }
}

uint64_t ExecEngine::returnValue() {
  int regid;
  switch (robject_->arch()) {
  case AArch64:
    regid = Register::X0;
    break;
  case X86_64:
    regid = Register::RAX;
    break;
  default:
    return 0;
  }
  return engine.getRegister(regid)->u8;
}

bool ExecEngine::execMain() {
  auto mainfn = iobject_->mainEntry();
  if (!mainfn) {
    // save this iobject module to the loader
    Loader::cacheObject(iobject_);
    return false;
  }

  return run(reinterpret_cast<uint64_t>(mainfn), iargs_.size(),
             reinterpret_cast<uint64_t>(&iargs_[0]));
}

bool ExecEngine::run(uint64_t vm, uint64_t arg0, uint64_t arg1) {
  if (::setjmp(jmpbuf_))
    return false;

  try {
    initMainRegister(reinterpret_cast<const void *>(arg0),
                     reinterpret_cast<const void *>(arg1));
    return execLoop(vm);
  } catch (std::exception &e) {
    log_print(Runtime, "Exception ocurred: {}.", e.what());
  } catch (...) {
    log_print(Runtime, "Exception ocurred, unknown type.");
  }
  dump();
  return false;
}

ContextA64 ExecEngine::loadRegisterAArch64() {
  using namespace aether;
  ContextA64 ctx;
  for (int i = 0; i <= 28; i++) {
    ctx.r[i] = engine.getRegister((Register)((int)Register::X0 + i))->u8;
  }
  ctx.r[A64_FP] = engine.getRegister(Register::X29);
  ctx.r[A64_LR] = engine.getRegister(Register::X30);
  ctx.r[A64_SP] = engine.getRegister(Register::SP);
  for (int i = 0; i < 32; i++) {
    std::memcpy(&ctx.v[i], engine.getRegister((Register)(int)Register::V0 + i),
                sizeof(ctx.v[i]));
  }
  return ctx;
}

void ExecEngine::saveRegisterAArch64(const ContextA64 &ctx) {
  for (int i = 0; i <= 28; i++) {
    engine.setRegister((Register)((int)Register::X0 + i), {.u8 = ctx.r[i]});
  }
  engine.setRegister(Register::X29, {.u8 = ctx.r[A64_FP]});
  engine.setRegister(Register::X30, {.u8 = ctx.r[A64_LR]});
  engine.setRegister(Register::SP, {.u8 = ctx.r[A64_SP]});
  for (int i = 0; i < 32; i++) {
    engine.setRegister((Register)((int)Register::V0 + i), {.u8 = &ctx.v[i]});
  }
}

ContextX64 ExecEngine::loadRegisterX64() {
  ContextX64 ctx;
  ctx.rsp = engine.getRegister(Register::RSP)->u8;
  ctx.rbp = engine.getRegister(Register::RBP)->u8;
  ctx.rax = engine.getRegister(Register::RAX)->u8;
  ctx.rbx = engine.getRegister(Register::RBX)->u8;
  ctx.rcx = engine.getRegister(Register::RCX)->u8;
  ctx.rdx = engine.getRegister(Register::RDX)->u8;
  ctx.rsi = engine.getRegister(Register::RSI)->u8;
  ctx.rdi = engine.getRegister(Register::RDI)->u8;
  ctx.r8 = engine.getRegister(Register::R8)->u8;
  ctx.r9 = engine.getRegister(Register::R9)->u8;
  ctx.r10 = engine.getRegister(Register::R10)->u8;
  ctx.r11 = engine.getRegister(Register::R11)->u8;
  ctx.r12 = engine.getRegister(Register::R12)->u8;
  ctx.r13 = engine.getRegister(Register::R13)->u8;
  ctx.r14 = engine.getRegister(Register::R14)->u8;
  ctx.r15 = engine.getRegister(Register::R15)->u8;
  for (int i = 0; i < 8; i++) {
    std::memcpy(&ctx.stmmx[i],
                engine.getRegister((Register)(int)Register::ST0 + i),
                sizeof(ctx.stmmx[i]));
  }
  for (int i = 0; i < 32; i++) {
    std::memcpy(&ctx.xmm[i],
                engine.getRegister((Register)(int)Register::XMM0 + i),
                sizeof(ctx.xmm[i]));
  }
  return ctx;
}

void ExecEngine::saveRegisterX64(const ContextX64 &ctx) {
  engine.setRegister(Register::RSP, {.u8 = ctx.rsp});
  engine.setRegister(Register::RBP, {.u8 = ctx.rbp});
  engine.setRegister(Register::RAX, {.u8 = ctx.rax});
  engine.setRegister(Register::RBX, {.u8 = ctx.rbx});
  engine.setRegister(Register::RCX, {.u8 = ctx.rcx});
  engine.setRegister(Register::RDX, {.u8 = ctx.rdx});
  engine.setRegister(Register::RSI, {.u8 = ctx.rsi});
  engine.setRegister(Register::RDI, {.u8 = ctx.rdi});
  engine.setRegister(Register::R8, {.u8 = ctx.r8});
  engine.setRegister(Register::R9, {.u8 = ctx.r9});
  engine.setRegister(Register::R10, {.u8 = ctx.r10});
  engine.setRegister(Register::R11, {.u8 = ctx.r11});
  engine.setRegister(Register::R12, {.u8 = ctx.r12});
  engine.setRegister(Register::R13, {.u8 = ctx.r13});
  engine.setRegister(Register::R14, {.u8 = ctx.r14});
  engine.setRegister(Register::R15, {.u8 = ctx.r15});
  for (int i = 0; i < 8; i++) {
    std::memcpy((void *)engine.setRegister((Register)(int)Register::ST0 + i),
                &ctx.stmmx[i], sizeof(ctx.stmmx[i]));
    std::memcpy((void *)engine.setRegister((Register)(int)Register::MM0 + i),
                &ctx.stmmx[i], sizeof(ctx.stmmx[i]));
  }
  for (int i = 0; i < 32; i++) {
    std::memcpy((void *)engine.getRegister((Register)((int)Register::XMM0 + i)),
                &ctx.xmm[i], sizeof(ctx.xmm[i]));
  }
}

struct exec_thread_context_t {
  ExecEngine *parent_exe;
  // the original thread entry and argument
  uint64_t tentry;
  uint64_t targ;
};

static thread_return_t exec_thread_stub(void *pcontext) {
  auto context = reinterpret_cast<exec_thread_context_t *>(pcontext);
  // clone a new execute engine instance
  auto exec = std::make_unique<ExecEngine>(*context->parent_exe);
  // execute the real thread entry
  exec->run(context->tentry, context->targ, 0);
  // get the thread entry return value
  auto retval = exec->returnValue();
  // free the dynamically allocated context
  delete context;
  return thread_return_t(retval);
}

static void nop_function() {}

uint64_t ExecEngine::createStub(uint64_t vmfunc) {
  if (!stubpages_.size()) {
    // initialize a new page
    stubcode_ = alloc_page(stubend_);
    stubpages_.push_back(stubcode_);
  }

  auto page = *stubpages_.rbegin();
  if (stubcode_ > stubend_) {
    // allocate a new page
    page = alloc_page(stubend_);
    stubcode_ = page;
    stubpages_.push_back(page);
  } else {
    page_writable(page);
  }
  auto stub = host_callback_stub({this, vmfunc}, stubcode_);
  page_executable(page);
  page_flush(page);
  return reinterpret_cast<uint64_t>(stub);
}

bool ExecEngine::specialCallProcess(uint64_t &target, uint64_t &retaddr) {
  uint64_t args[4], backups[4];
  int rids[4], retrid; // register id
  switch (robject_->arch()) {
  case AArch64:
    rids[0] = Register::X0;
    rids[1] = Register::X1;
    rids[2] = Register::X2;
    rids[3] = Register::X3;
    retrid = Register::X0;
    break;
  case X86_64:
    switch (robject_->type()) {
    case COFF_Exe:
    case COFF_Reloc:
      // windows abi: rcx, rdx, r8, r9
      rids[0] = Register::RCX;
      rids[1] = Register::RDX;
      rids[2] = Register::R8;
      rids[3] = Register::R9;
      break;
    default:
      // system v abi: rdi, rsi, rdx, rcx, r8, r9
      rids[0] = Register::RDI;
      rids[1] = Register::RSI;
      rids[2] = Register::RDX;
      rids[3] = Register::RCX;
      break;
    }
    retrid = Register::RAX;
    break;
  default:
    UNIMPL_ABORT();
    break;
  }
  // read current arugments
  for (size_t i = 0; i < std::size(args); i++)
    engine.getRegister(rids[i], &args[i]);
  std::memcpy(backups, args, sizeof(args));

  if (reinterpret_cast<uint64_t>(thread_create) == target ||
      reinterpret_cast<uint64_t>(libcpp_thread_create) == target) {
    // index of thread and argument in thread_create_func arguments list
    int ientry = 2, iarg = 3;
    if (reinterpret_cast<uint64_t>(libcpp_thread_create) == target) {
      ientry = 1;
      iarg = 2;
    }

    auto context = new exec_thread_context_t{this, args[ientry], args[iarg]};
    // replace to our stub instance
    args[ientry] = reinterpret_cast<uint64_t>(exec_thread_stub);
    args[iarg] = reinterpret_cast<uint64_t>(context);
  } else if (reinterpret_cast<uint64_t>(atexit) == target ||
             reinterpret_cast<uint64_t>(__cxa_atexit) == target) {
    Object *iobj;
    if (robject_->executable(args[0], &iobj)) {
      Atexit aep; // at exit parameters
      aep.object = iobj;
      aep.vm = args[0]; // exit routine
      aep.args[0] = args[1];
      aep.args[1] = args[2];
      dyndtors_.push_back(aep);
      // replace it with a nop stub function
      args[0] = reinterpret_cast<uint64_t>(nop_function);
      target = args[0];
    }
  } else if (reinterpret_cast<uint64_t>(exit) == target) {
    exitcode_ = args[0]; // save script's exit code
    target = reinterpret_cast<uint64_t>(nop_function);
    retaddr = reinterpret_cast<uint64_t>(topReturn());
  } else if (reinterpret_cast<uint64_t>(abort) == target) {
    log_print(Runtime, "Abort called in script.");
    dump();
    exitcode_ = -1;
    target = reinterpret_cast<uint64_t>(nop_function);
    retaddr = reinterpret_cast<uint64_t>(topReturn());
  } else if (reinterpret_cast<uint64_t>(__stack_chk_fail) == target) {
    log_print(Runtime, "Fatal error, stack overflow checked.");
    dump();
    std::exit(-1);
  } else if (reinterpret_cast<uint64_t>(__cxa_throw) == target) {
#if ON_WINDOWS || __APPLE__
    log_print(Runtime,
              "Exception thrown in script: exception={:x}, rtti={:x}, "
              "caller.rva={:x}.",
              args[0], args[1], robject_->vm2vrva(retaddr));
#else
    auto typeinfo = reinterpret_cast<std::type_info *>(args[1]);
    // char * exception
    if (typeinfo == &typeid(const char *) || typeinfo == &typeid(char *)) {
      log_print(Runtime, "Exception thrown in script: {}",
                *reinterpret_cast<const char **>(args[0]));
    }
    // integer and float point exception
    else if (typeinfo == &typeid(char) || typeinfo == &typeid(unsigned char) ||
             typeinfo == &typeid(short) ||
             typeinfo == &typeid(unsigned short) || typeinfo == &typeid(int) ||
             typeinfo == &typeid(unsigned int) || typeinfo == &typeid(long) ||
             typeinfo == &typeid(unsigned long) ||
             typeinfo == &typeid(long long) ||
             typeinfo == &typeid(unsigned long long) ||
             typeinfo == &typeid(float) || typeinfo == &typeid(double)) {
      log_print(Runtime, "Exception thrown in script: {:x}", args[0]);
    }
    // std::exception
    else {
      log_print(Runtime, "Exception thrown in script: {}",
                reinterpret_cast<std::exception *>(args[0])->what());
    }
#endif
    exitcode_ = -1;
    target = reinterpret_cast<uint64_t>(nop_function);
    retaddr = reinterpret_cast<uint64_t>(topReturn());
  }
#if ON_UNIX
  else if (reinterpret_cast<uint64_t>(fork) == target) {
    target = reinterpret_cast<uint64_t>(nop_function);

    auto pid = fork();
    log_print(Develop, "PID {}, fork result {}.", getpid(), pid);
    engine.setRegister(retrid, &pid);
  }
#endif
  else {
    for (size_t i = 0; i < std::size(args); i++) {
      Object *iobj;
      if (robject_->executable(args[i], &iobj)) {
        auto found = vmstubs_.find(args[i]);
        if (found == vmstubs_.end()) {
          // create a new stub for this iobject vm target function
          found = vmstubs_.insert({args[i], createStub(args[i])}).first;
          stubvms_.insert({found->second, found->first});
        }
        args[i] = found->second;
      }
    }
  }

  // redirect printf to remote client
  if (RunConfig::gadget) {
    if (reinterpret_cast<uint64_t>(printf) == target) {
      target = reinterpret_cast<uint64_t>(RunConfig::inst()->printf);
    } else if (reinterpret_cast<uint64_t>(puts) == target) {
      target = reinterpret_cast<uint64_t>(RunConfig::inst()->puts);
    }
  }

  // update changed arugments
  bool update = false;
  for (size_t i = 0; i < std::size(args); i++) {
    if (backups[i] != args[i]) {
      update = true;
      engine.setRegister(rids[i], &args[i]);
    }
  }
  return update;
}

bool ExecEngine::executable(uint64_t target) {
  if (robject_->executable(target, &robject_))
    return true;

  // as Loader's internal cache doesn't cache main-exe kind of iobject,
  // so we have to check it herein manually
  if (iobject_->executable(target, nullptr)) {
    robject_ = iobject_.get();
    return true;
  }
  return false;
}

bool ExecEngine::interpretCallAArch64(const InsnInfo *&inst, uint64_t &pc,
                                      uint64_t target) {
  auto retaddr = pc + inst->len;
#if LOG_EXECUTION
  log_print(Develop, "Calling {:x} from {:x}", robject_->vm2vrva(target),
            robject_->vm2vrva(retaddr));
#endif

  if (executable(target)) {
    // call internal function
    // set return address
    engine.setRegister(Register::LR, &retaddr);
    pc = target;
    inst = robject_->insnInfo(pc); // update current inst
    return true;
  } else {
    // check and process some api which has callback argument
    specialCallProcess(target, retaddr);

    // call external function
    if (target != reinterpret_cast<uint64_t>(nop_function)) {
      auto context = loadRegisterAArch64();
      context.r[A64_LR] = retaddr; // set return address
      host_call(&context, reinterpret_cast<const void *>(target));
      saveRegisterAArch64(context);
    }

    // finish interpreting
    if (retaddr == reinterpret_cast<uint64_t>(topReturn())) {
      pc = retaddr;
      return true;
    }
    return false;
  }
}

bool ExecEngine::interpretJumpAArch64(const InsnInfo *&inst, uint64_t &pc,
                                      uint64_t target) {
  if (executable(target)) {
    // jump to internal destination
    pc = target;
    inst = robject_->insnInfo(pc); // update current inst
    return true;
  } else {
    // jump to external function
    auto context = loadRegisterAArch64();
    auto retaddr = context.r[A64_LR];
    if (executable(retaddr) ||
        topReturn() == reinterpret_cast<void *>(retaddr)) {
      // check and process some api which has callback argument
      bool update = specialCallProcess(target, retaddr);

      if (target != reinterpret_cast<uint64_t>(nop_function)) {
        if (update)
          context = loadRegisterAArch64();
        host_call(&context, reinterpret_cast<const void *>(target));
        saveRegisterAArch64(context);
      }

      // return to caller
      pc = retaddr;
      if (retaddr != reinterpret_cast<uint64_t>(topReturn())) {
        // update current inst
        inst = robject_->insnInfo(pc);
      }
      return true;
    }
    UNIMPL_ABORT();
    return false;
  }
}

void ExecEngine::interpretPCLdrAArch64(const InsnInfo *&inst, uint64_t &pc) {
  // encoded meta data layout of all LDRxL:[uint16_t, uint64_t]
  auto metaptr = robject_->metaInfo<uint16_t>(inst, pc);
  uint64_t target = 0;
  if (inst->rflag)
    target = reinterpret_cast<uint64_t>(robject_->relocTarget(inst->reloc));
  else
    target = pc;
  target += (*reinterpret_cast<const uint64_t *>(&metaptr[1]) << 2);
  writeRegister(metaptr[0], reinterpret_cast<const void *>(target));
}

bool ExecEngine::interpretCallX64(const InsnInfo *&inst, uint64_t &pc,
                                  uint64_t target) {
  auto retaddr = pc + inst->len;
#if LOG_EXECUTION
  log_print(Develop, "Calling {:x} from {:x}", robject_->vm2vrva(target),
            robject_->vm2vrva(retaddr));
#endif

  if (executable(target)) {
    uint64_t rsp;
    engine.getRegister(Register::RSP, &rsp);
    // push return address
    rsp -= 8;
    *reinterpret_cast<uint64_t *>(rsp) = retaddr;
    engine.setRegister(Register::RSP, &rsp);
    // call internal function
    pc = target;
    inst = robject_->insnInfo(pc); // update current inst
    return true;
  } else {
    // check and process some api which has callback argument
    specialCallProcess(target, retaddr);

    // call external function
    if (target != reinterpret_cast<uint64_t>(nop_function)) {
      auto context = loadRegisterX64();
      host_call(&context, reinterpret_cast<const void *>(target));
      saveRegisterX64(context);
    }

    // finish interpreting
    if (retaddr == reinterpret_cast<uint64_t>(topReturn())) {
      pc = retaddr;
      return true;
    }
    return false;
  }
}

bool ExecEngine::interpretJumpX64(const InsnInfo *&inst, uint64_t &pc,
                                  uint64_t target) {
  if (executable(target)) {
    // jump to internal destination
    pc = target;
    inst = robject_->insnInfo(pc); // update current inst
    return true;
  } else {
    // jump to external function
    uint64_t rsp, retaddr;
    engine.getRegister(Register::RSP, &rsp);
    retaddr = *reinterpret_cast<uint64_t *>(rsp);
    auto context = loadRegisterX64();
    if (executable(retaddr) ||
        topReturn() == reinterpret_cast<void *>(retaddr)) {
      // check and process some api which has callback argument
      bool update = specialCallProcess(target, retaddr);

      if (target != reinterpret_cast<uint64_t>(nop_function)) {
        if (update)
          context = loadRegisterX64();
        host_call(&context, reinterpret_cast<const void *>(target));
        saveRegisterX64(context);
      }

      // return to caller
      pc = retaddr;
      // pop return address
      rsp += 8;
      engine.setRegister(Register::RSP, &rsp);
      if (retaddr != reinterpret_cast<uint64_t>(topReturn())) {
        // update current inst
        inst = robject_->insnInfo(pc);
      }
      return true;
    }
    UNIMPL_ABORT();
    return false;
  }
}

uint64_t ExecEngine::interpretCalcMemX64(const InsnInfo *&inst, uint64_t &pc,
                                         int memop, const uint16_t **opsptr) {
  // reg is uint16_t, imm is uint64_t in meta array stream
  auto ops = robject_->metaInfo<uint16_t>(inst, pc);
  if (opsptr)
    *opsptr = ops;
  // memop indicates the memory operands startup index in uint16_t meta array
  // memory representation in x86_64 instruction: basereg + expimm*expreg +
  // offimm
  int basereg_op_idx = memop;
  int expimm_op_idx = basereg_op_idx + 1;
  int expreg_op_idx = expimm_op_idx + 4;
  int offimm_op_idx = expreg_op_idx + 1;
  int segreg_op_idx = offimm_op_idx + 4;
  uint64_t basereg = 0, expreg = 0;
  // read base and exponent register value
  if (ops[basereg_op_idx] == Register::RIP)
    basereg = pc;
  else
    engine.getRegister(ops[basereg_op_idx], &basereg);
  engine.getRegister(ops[expreg_op_idx], &expreg);
  // pickup exponent and offset value
  auto expimm = *reinterpret_cast<const int64_t *>(&ops[expimm_op_idx]);
  auto offimm = *reinterpret_cast<const int64_t *>(&ops[offimm_op_idx]);
  // calculate the final memory address from raw instruction
  uint64_t memaddr = (uint64_t)(basereg + expimm * expreg + offimm);
  if (ops[basereg_op_idx] == Register::RIP) {
    // rip related memory reference
    if (inst->rflag) {
      // FIXME:: should dynamically calculate this offimm with relocation ?
      if (offimm == -1)
        offimm = 0;

      // relocate to the real runtime address
      memaddr = reinterpret_cast<uint64_t>(robject_->relocTarget(inst->reloc)) +
                offimm;
    } else {
      // adjust location with instruction length
      memaddr += inst->len;
    }
  } else if (inst->segflag) {
    // process segment register value
    switch (ops[segreg_op_idx]) {
    case Register::GS:
#if ON_WINDOWS
      switch (offimm) {
      case 0x58: {
        /*
        65 4C 8B 0C 25  | movq %gs:0x58, %r9
        4F 8B 04 C1     | movq (%r9,%r8,8), %r8
        41 3B 88 00 00  | cmpl (%r8), %ecx
        */
        // simulate a three level pointer
        static auto epochspot1 = Loader::simulateTlsEpoch();
        static auto epochspot2 = &epochspot1;
        return reinterpret_cast<uint64_t>(&epochspot2);
      }
      default:
        UNIMPL_ABORT();
        break;
      }
      break;
#endif
    case Register::DS:
    case Register::FS:
    case Register::SS:
      UNIMPL_ABORT();
      break;
    default:
      break;
    }
  }
  return memaddr;
}

template <typename T>
void ExecEngine::interpretMovX64(const InsnInfo *&inst, uint64_t &pc, int regop,
                                 int memop, bool movrm) {
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, memop, &ops);
  if (movrm) {
    // mov reg, mem
    writeRegister(ops[regop], reinterpret_cast<const void *>(target));
  } else {
    // mov mem, reg
    uint64_t value[4];
    auto regid = ops[regop];
    engine.getRegister(ops[regop], value);
    if (Register::YMM0 <= regid && regid <= Register::ZMM31) {
      log_print(Runtime, "YMM/ZMM register moving isn't supported now.");
      abort();
    } else if (Register::XMM0 <= regid && regid <= Register::XMM31) {
      memcpy(reinterpret_cast<void *>(target), value, 16);
    } else {
      *reinterpret_cast<T *>(target) = static_cast<T>(value[0]);
    }
  }
}

void ExecEngine::interpretMovMRX64(const InsnInfo *&inst, uint64_t &pc,
                                   int bytes) {
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, 0, &ops);

  uint64_t value[4];
  engine.getRegister(ops[11], value);
  // mov mem, gpr/mmx/xmm
  std::memcpy(reinterpret_cast<void *>(target), value, bytes);
}

template <typename T>
void ExecEngine::interpretMovMIX64(const InsnInfo *&inst, uint64_t &pc) {
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, 0, &ops);
  // mov mem, imm
  *reinterpret_cast<T *>(target) =
      static_cast<T>(*reinterpret_cast<const uint64_t *>(&ops[11]));
}

template <typename TSRC, typename TDES>
void ExecEngine::interpretFlagsMemImm(const InsnInfo *&inst, uint64_t &pc,
                                      bool cmp) {
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, 0, &ops);
  // cmp/test instruction
  auto updator = cmp ? host_compare<TDES> : host_test<TDES>;
  // calculate the new rflags
  auto rflags =
      updator(*reinterpret_cast<const TSRC *>(target),
              static_cast<TSRC>(*reinterpret_cast<const TDES *>(&ops[11])));
  // update rflags
  engine.setRegister(Register::RFLAGS, &rflags);
}

template <typename T>
void ExecEngine::interpretFlagsRegMem(const InsnInfo *&inst, uint64_t &pc,
                                      bool cmp) {
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, 1, &ops);
  // cmp/test instruction
  auto updator = cmp ? host_compare<T> : host_test<T>;
  uint64_t value;
  engine.getRegister(ops[0], &value);
  // calculate the new rflags
  auto rflags =
      updator(static_cast<T>(value), *reinterpret_cast<const T *>(target));
  // update rflags
  engine.setRegister(Register::RFLAGS, &rflags);
}

template <typename T>
void ExecEngine::interpretFlagsMemReg(const InsnInfo *&inst, uint64_t &pc,
                                      bool cmp) {
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, 0, &ops);
  // cmp/test instruction
  auto updator = cmp ? host_compare<T> : host_test<T>;
  uint64_t value;
  engine.getRegister(ops[11], &value);
  // calculate the new rflags
  auto rflags =
      updator(*reinterpret_cast<const T *>(target), static_cast<T>(value));
  // update rflags
  engine.setRegister(Register::RFLAGS, &rflags);
}

template <typename TSRC, typename TDES>
void ExecEngine::interpretSignExtendRegMem(const InsnInfo *&inst,
                                           uint64_t &pc) {
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, 1, &ops);
  // movsx reg, mem
  auto result = static_cast<TSRC>(*reinterpret_cast<const TDES *>(target));
  writeRegister(ops[0], &result);
}

template <typename TSRC, typename TDES>
void ExecEngine::interpretZeroExtendRegMem(const InsnInfo *&inst,
                                           uint64_t &pc) {
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, 1, &ops);
  // movzx reg, mem
  auto result = static_cast<TSRC>(*reinterpret_cast<const TDES *>(target));
  writeRegister(ops[0], &result);
}

void ExecEngine::interpretCondMovRegMem(const InsnInfo *&inst, uint64_t &pc) {
  /*
  <MCInst 1183
    <MCOperand Reg>
    <MCOperand Reg>
    <MCOperand Reg> <MCOperand Imm> <MCOperand Reg> <MCOperand Imm>
    <MCOperand Reg>
    <MCOperand Imm>
  >
  */
  constexpr int resultreg_op_idx = 0;
  constexpr int cmpreg_op_idx = resultreg_op_idx + 1;
  constexpr int basereg_op_idx = cmpreg_op_idx + 1;
  constexpr int expimm_op_idx = basereg_op_idx + 1;
  constexpr int expreg_op_idx = expimm_op_idx + 4;
  constexpr int offimm_op_idx = expreg_op_idx + 1;
  constexpr int segreg_op_idx = offimm_op_idx + 4;
  constexpr int condimm_op_idx = segreg_op_idx + 1;
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, basereg_op_idx, &ops);
  auto found = dyn_codes.find(pc);
  if (found == dyn_codes.end()) {
    char dyncode[64];
    char *ptr = &dyncode[0];
    // set the content of the target pointer
    *(uint64_t *)ptr = *(uint64_t *)target;
    ptr += 8;
    // copy opcode
    char *opcode = ptr;
    *(uint32_t *)ptr = *(uint32_t *)pc;
    ptr += 4;
    // set the new offset
    *(int32_t *)ptr = -8 - inst->len;
    // cache the dynamically generated instruction
    found = dyn_codes.insert({pc, {&dyncode[0], ptr + 4}}).first;
  } else {
    // set the content of the target pointer
    *(uint64_t *)found->second.data() = *(uint64_t *)target;
  }
  // execute the dynamically generated instruction
  auto opcode = found->second.data() + 8;
  auto result = engine.emulate({(uint8_t *)opcode, inst->len});
  if (!result) {
    log_print(Runtime, "Fatal error occurred when simuating cmov instruction.");
    dump();
    std::exit(-1);
  }
}

void ExecEngine::interpretSSERegMem(const InsnInfo *&inst, uint64_t &pc) {
  auto target = reinterpret_cast<uint64_t>(robject_->relocTarget(inst->reloc));
  auto found = dyn_codes.find(pc);
  if (found == dyn_codes.end()) {
    // SSE_INSN xmmN, [TARGET]
    uint8_t dyncode[64]; // xmm buffer needs to be 0x10 alignment
    auto ptr = &dyncode[0];
    // copy the buffer of target with the size of xmm register
    std::memcpy(ptr, (void *)target, 0x10);
    ptr += 0x10;
    // copy opcode
    auto opcode = ptr;
    *(uint32_t *)ptr = *(uint32_t *)pc;
    ptr += inst->len - 4;
    // target = pc + oplen + offset
    // offset = target - (pc + oplen)
    // set the new offset
    *(int32_t *)ptr = -0x10 - inst->len;
    // cache the dynamically generated instruction
    found = dyn_codes.insert({pc, {&dyncode[0], ptr + 4}}).first;
  } else {
    // copy the buffer of target with the size of xmm register
    std::memcpy((void *)found->second.data(), (void *)target, 0x10);
  }
  // execute the dynamically generated instruction
  auto opcode = found->second.data() + 0x10;
  auto result = engine.emulate({(uint8_t *)opcode, inst->len});
  if (!result) {
    log_print(Runtime,
              "Fatal error occurred when simuating SSE/AVX instruction.");
    dump();
    std::exit(-1);
  }
}

static bool can_emulate(const InsnInfo *inst) {
  switch (inst->type) {
  case INSN_CONDJUMP:
  case INSN_ARM64_RETURN:
  case INSN_ARM64_SYSCALL:
  case INSN_ARM64_CALL:
  case INSN_ARM64_CALLREG:
  case INSN_ARM64_JUMP:
  case INSN_ARM64_JUMPREG:
  case INSN_X64_RETURN:
  case INSN_X64_SYSCALL:
  case INSN_X64_CALL:
  case INSN_X64_CALLREG:
  case INSN_X64_CALLMEM:
  case INSN_X64_JUMP:
  case INSN_X64_JUMPCOND:
  case INSN_X64_JUMPREG:
  case INSN_X64_JUMPMEM:
  case INSN_X64_CMP8MI:
  case INSN_X64_CMP8MI8:
  case INSN_X64_CMP16MI:
  case INSN_X64_CMP16MI8:
  case INSN_X64_CMP32MI:
  case INSN_X64_CMP32MI8:
  case INSN_X64_CMP64MI32:
  case INSN_X64_CMP64MI8:
  case INSN_X64_CMP8RM:
  case INSN_X64_CMP16RM:
  case INSN_X64_CMP32RM:
  case INSN_X64_CMP64RM:
  case INSN_X64_CMP8MR:
  case INSN_X64_CMP16MR:
  case INSN_X64_CMP32MR:
  case INSN_X64_CMP64MR:
  case INSN_X64_TEST8MI:
  case INSN_X64_TEST8MR:
  case INSN_X64_TEST16MI:
  case INSN_X64_TEST16MR:
  case INSN_X64_TEST32MI:
  case INSN_X64_TEST32MR:
  case INSN_X64_TEST64MI32:
  case INSN_X64_TEST64MR:
    return false;
  case INSN_HARDWARE:
#if ARCH_X64
    // if this inst contains relocation, it must be in the SSE or above
    // instruction set, we should relocate it later.
    return inst->rflag == 0;
#else
    return true;
#endif
  default:
    // if the current instruction contains relocation or non-code
    // segment register, then it must be interpreted otherwise can
    // be emulated.
#if ARCH_X64
    if (inst->segflag)
      return false;
#endif
    return inst->rflag == 0;
  }
}

#include "exec-x64.inc"

bool ExecEngine::interpret(const InsnInfo *&inst, uint64_t &pc, int &step) {
  // we should interpret the relocation, branch, jump, call and syscall
  // instructions manually, the AetherVM engine can just execute those simple
  // instructions (i.e., instruction without relocation and jump operation) in
  // our case
  unsigned origstep = step;
  auto curi = inst;
  if (step <= 0) {
    // calculate the maximized steps that can be passed to AetherVM
    for (step = 0; can_emulate(curi); curi++, step++)
      ;
  } else {
    // check whether the step-count instructions have relocation/jump-operation
    // or not if so, the step size should be re-adjusted
    int tmpstep = 0;
    for (; can_emulate(curi); curi++, tmpstep++)
      ;
    step = std::min(step, tmpstep);
  }
  if (step) {
    // indicates the current instruction hasn't been processed and should let
    // AetherVM continue to execute it
    return false;
  }
  // interpret the pre-decoded instructions
  for (unsigned i = 0; i < origstep && !can_emulate(inst); i++) {
#if LOG_EXECUTION
    log_print(Develop, "Interpret {:x} I{}", robject_->vm2vrva(pc), inst->type);
#endif

    // call and return within object should update this to true
    bool jump = false;
    switch (inst->type) {
    // common instruction
    case INSN_ABORT:
      log_print(Runtime,
                "Breakpoint or trap instruction hit at rva {:x}. Aborting...",
                robject_->vm2vrva(pc));
      dump();
      std::exit(-1);
      break;
    // conditional jump instruction
    case INSN_CONDJUMP:
      // only let AetherVM engine consumed 1 instruction in this situation
      step = 1;
      return false;
    // arm64 instruction
    case INSN_ARM64_RETURN: {
      uint64_t retaddr;
      engine.getRegister(Register::LR, &retaddr);
      if (executable(retaddr)) {
        pc = retaddr;
        inst = robject_->insnInfo(pc);
        jump = true;
      } else if (reinterpret_cast<const void *>(retaddr) == topReturn()) {
        pc = retaddr; // finished interpreting
        return true;
      } else {
        UNIMPL_ABORT();
      }
      break;
    }
    case INSN_ARM64_SYSCALL:
      interpretCallAArch64(inst, pc,
                           reinterpret_cast<uint64_t>(host_naked_syscall));
      break;
    // encoded meta data layout:[uint64_t]
    case INSN_ARM64_CALL: {
      uint64_t target;
      if (inst->rflag) {
        target = reinterpret_cast<uint64_t>(robject_->relocTarget(inst->reloc));
      } else {
        auto metaptr = robject_->metaInfo<uint64_t>(inst, pc);
        target = pc + (metaptr[0] << 2);
      }
      jump = interpretCallAArch64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[uint16_t]
    case INSN_ARM64_CALLREG: {
      auto metaptr = robject_->metaInfo<uint16_t>(inst, pc);
      uint64_t target;
      engine.getRegister(metaptr[0], &target);
      target = checkStub(target);
      jump = interpretCallAArch64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[uint64_t]
    case INSN_ARM64_JUMP: {
      uint64_t target;
      if (inst->rflag) {
        target = reinterpret_cast<uint64_t>(robject_->relocTarget(inst->reloc));
      } else {
        auto metaptr = robject_->metaInfo<uint64_t>(inst, pc);
        target = pc + (metaptr[0] << 2);
      }
      jump = interpretJumpAArch64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[uint16_t]
    case INSN_ARM64_JUMPREG: {
      auto metaptr = robject_->metaInfo<uint16_t>(inst, pc);
      uint64_t target;
      engine.getRegister(metaptr[0], &target);
      target = checkStub(target);
      jump = interpretJumpAArch64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[uint16_t, uint64_t]
    case INSN_ARM64_ADR:
    case INSN_ARM64_ADRP: {
      auto metaptr = robject_->metaInfo<uint16_t>(inst, pc);
      uint64_t target = 0;
      if (inst->rflag) {
        target = reinterpret_cast<uint64_t>(robject_->relocTarget(inst->reloc));
      } else {
        auto imm = *reinterpret_cast<const uint64_t *>(&metaptr[1]);
        if (inst->type == INSN_ARM64_ADRP)
          target = pc + ((imm << 12) & ~((1 << 12) - 1));
        else
          target = pc + imm;
      }
      engine.setRegister(metaptr[0], &target);
      break;
    }
    case INSN_ARM64_LDRSWL:
    case INSN_ARM64_LDRWL:
    case INSN_ARM64_LDRXL:
    case INSN_ARM64_LDRSL:
    case INSN_ARM64_LDRDL:
    case INSN_ARM64_LDRQL:
      interpretPCLdrAArch64(inst, pc);
      break;
    // x86_64 instruction
    // encoded meta data layout:[uint64_t]
    case INSN_X64_RETURN: {
      uint64_t retaddr, rsp;
      engine.getRegister(Register::RSP, &rsp);
      retaddr = *reinterpret_cast<uint64_t *>(rsp);
      // pop return address
      rsp += 8;
      // instruction: retn bytes
      rsp += *robject_->metaInfo<uint64_t>(inst, pc);
      engine.setRegister(Register::RSP, &rsp);
      pc = retaddr;
      if (executable(retaddr)) {
        inst = robject_->insnInfo(pc);
        jump = true;
      } else if (reinterpret_cast<const void *>(retaddr) == topReturn()) {
        // finished interpreting
        return true;
      } else {
        UNIMPL_ABORT();
      }
      break;
    }
    case INSN_X64_SYSCALL:
      interpretCallX64(inst, pc,
                       reinterpret_cast<uint64_t>(host_naked_syscall));
      break;
    // encoded meta data layout:[uint64_t]
    case INSN_X64_CALL: {
      uint64_t target;
      if (inst->rflag) {
        target = reinterpret_cast<uint64_t>(robject_->relocTarget(inst->reloc));
      } else {
        auto metaptr = robject_->metaInfo<uint64_t>(inst, pc);
        target = pc + metaptr[0] + inst->len;
      }
      jump = interpretCallX64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[uint16_t]
    case INSN_X64_CALLREG: {
      auto metaptr = robject_->metaInfo<uint16_t>(inst, pc);
      uint64_t target;
      engine.getRegister(metaptr[0], &target);
      target = checkStub(target);
      jump = interpretCallX64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[[uint16_t-memory_items]]
    case INSN_X64_CALLMEM: {
      auto targetmem = interpretCalcMemX64(inst, pc, 0);
      auto target = *reinterpret_cast<uint64_t *>(targetmem);
      target = checkStub(target);
      jump = interpretCallX64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[uint64_t]
    case INSN_X64_JUMP: {
      uint64_t target;
      if (inst->rflag) {
        target = reinterpret_cast<uint64_t>(robject_->relocTarget(inst->reloc));
      } else {
        auto metaptr = robject_->metaInfo<uint64_t>(inst, pc);
        target = pc + metaptr[0] + inst->len;
      }
      jump = interpretJumpX64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[uint64_t, uint64_t]
    case INSN_X64_JUMPCOND: {
      if (!inst->rflag) {
        // only let AetherVM engine consumed 1 instruction in this situation
        step = 1;
        return false;
      }

      uint64_t target =
          reinterpret_cast<uint64_t>(robject_->relocTarget(inst->reloc));
      auto metaptr = robject_->metaInfo<uint16_t>(inst, pc);
      ContextX64 context{0};
      engine.getRegister(Register::RCX, &context.rcx);
      engine.getRegister(Register::RFLAGS, &context.rflags);
      if (hitCondX64(&context, metaptr[4]))
        jump = interpretJumpX64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[uint16_t]
    case INSN_X64_JUMPREG: {
      auto metaptr = robject_->metaInfo<uint16_t>(inst, pc);
      uint64_t target;
      engine.getRegister(metaptr[0], &target);
      target = checkStub(target);
      jump = interpretJumpX64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[[uint16_t-memory_items]]
    case INSN_X64_JUMPMEM: {
      auto targetmem = interpretCalcMemX64(inst, pc, 0);
      auto target = *reinterpret_cast<uint64_t *>(targetmem);
      target = checkStub(target);
      jump = interpretJumpX64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[uint16_t, [uint16_t-memory_items]]
    case INSN_X64_MOV8RM:
      interpretMovX64<uint8_t>(inst, pc, 0, 1, true);
      break;
    // encoded meta data layout:[[uint16_t-memory_items], uint16_t]
    case INSN_X64_MOV8MR:
      interpretMovX64<uint8_t>(inst, pc, 11, 0, false);
      break;
    // encoded meta data layout:[[uint16_t-memory_items], uint64_t]
    case INSN_X64_MOV8MI:
      interpretMovMIX64<uint8_t>(inst, pc);
      break;
    case INSN_X64_MOV16RM:
      interpretMovX64<uint16_t>(inst, pc, 0, 1, true);
      break;
    case INSN_X64_MOV16MR:
      interpretMovX64<uint16_t>(inst, pc, 11, 0, false);
      break;
    case INSN_X64_MOV16MI:
      interpretMovMIX64<uint16_t>(inst, pc);
      break;
    case INSN_X64_MOV32RM:
      interpretMovX64<uint32_t>(inst, pc, 0, 1, true);
      break;
    case INSN_X64_MOV32MR:
      interpretMovX64<uint32_t>(inst, pc, 11, 0, false);
      break;
    case INSN_X64_MOV32MI:
      interpretMovMIX64<uint32_t>(inst, pc);
      break;
    case INSN_X64_MOV64RM:
      interpretMovX64<uint64_t>(inst, pc, 0, 1, true);
      break;
    case INSN_X64_MOV64MR:
      interpretMovX64<uint64_t>(inst, pc, 11, 0, false);
      break;
    case INSN_X64_MOV64MI32:
      interpretMovMIX64<uint64_t>(inst, pc);
      break;
    // encoded meta data layout:[uint16_t, [uint16_t-memory_items]]
    case INSN_X64_LEA32:
    case INSN_X64_LEA64: {
      const uint16_t *ops;
      auto target = interpretCalcMemX64(inst, pc, 1, &ops);
      writeRegister(ops[0], reinterpret_cast<const void *>(&target));
      break;
    }
    case INSN_X64_MOVAPSRM:
      interpretMovX64<uint64_t>(inst, pc, 0, 1, true);
      break;
    case INSN_X64_MOVAPSMR:
      interpretMovMRX64(inst, pc, 16);
      break;
    case INSN_X64_MOVUPSRM:
      interpretMovX64<uint64_t>(inst, pc, 0, 1, true);
      break;
    case INSN_X64_MOVUPSMR:
      interpretMovMRX64(inst, pc, 16);
      break;
    case INSN_X64_MOVAPDRM:
      interpretMovX64<uint64_t>(inst, pc, 0, 1, true);
      break;
    case INSN_X64_MOVAPDMR:
      interpretMovMRX64(inst, pc, 16);
      break;
    case INSN_X64_MOVUPDRM:
      interpretMovX64<uint64_t>(inst, pc, 0, 1, true);
      break;
    case INSN_X64_MOVUPDMR:
      interpretMovMRX64(inst, pc, 16);
      break;
    case INSN_X64_MOVSX16RM8:
      interpretSignExtendRegMem<int16_t, int8_t>(inst, pc);
      break;
    case INSN_X64_MOVSX16RM16:
      interpretSignExtendRegMem<int16_t, int16_t>(inst, pc);
      break;
    case INSN_X64_MOVSX16RM32:
      interpretSignExtendRegMem<int16_t, int32_t>(inst, pc);
      break;
    case INSN_X64_MOVSX32RM8:
      interpretSignExtendRegMem<int32_t, int8_t>(inst, pc);
      break;
    case INSN_X64_MOVSX32RM16:
      interpretSignExtendRegMem<int32_t, int16_t>(inst, pc);
      break;
    case INSN_X64_MOVSX32RM32:
      interpretSignExtendRegMem<int32_t, int32_t>(inst, pc);
      break;
    case INSN_X64_MOVSX64RM8:
      interpretSignExtendRegMem<int64_t, int8_t>(inst, pc);
      break;
    case INSN_X64_MOVSX64RM16:
      interpretSignExtendRegMem<int64_t, int16_t>(inst, pc);
      break;
    case INSN_X64_MOVSX64RM32:
      interpretSignExtendRegMem<int64_t, int32_t>(inst, pc);
      break;
    case INSN_X64_MOVZX16RM8:
      interpretZeroExtendRegMem<uint16_t, uint8_t>(inst, pc);
      break;
    case INSN_X64_MOVZX16RM16:
      interpretZeroExtendRegMem<uint16_t, uint16_t>(inst, pc);
      break;
    case INSN_X64_MOVZX32RM8:
      interpretZeroExtendRegMem<uint32_t, uint8_t>(inst, pc);
      break;
    case INSN_X64_MOVZX32RM16:
      interpretZeroExtendRegMem<uint32_t, uint16_t>(inst, pc);
      break;
    case INSN_X64_MOVZX64RM8:
      interpretZeroExtendRegMem<uint64_t, uint8_t>(inst, pc);
      break;
    case INSN_X64_MOVZX64RM16:
      interpretZeroExtendRegMem<uint64_t, uint16_t>(inst, pc);
      break;
    case INSN_X64_CMP8MI:
    case INSN_X64_CMP8MI8:
      interpretFlagsMemImm<int8_t, int8_t>(inst, pc, true);
      break;
    case INSN_X64_CMP16MI:
      interpretFlagsMemImm<int16_t, int16_t>(inst, pc, true);
      break;
    case INSN_X64_CMP16MI8:
      interpretFlagsMemImm<int16_t, int8_t>(inst, pc, true);
      break;
    case INSN_X64_CMP32MI:
      interpretFlagsMemImm<int32_t, int32_t>(inst, pc, true);
      break;
    case INSN_X64_CMP32MI8:
      interpretFlagsMemImm<int32_t, int8_t>(inst, pc, true);
      break;
    case INSN_X64_CMP64MI32:
      interpretFlagsMemImm<int64_t, int32_t>(inst, pc, true);
      break;
    case INSN_X64_CMP64MI8:
      interpretFlagsMemImm<int64_t, int8_t>(inst, pc, true);
      break;
    case INSN_X64_CMP8RM:
      interpretFlagsRegMem<int8_t>(inst, pc, true);
      break;
    case INSN_X64_CMP16RM:
      interpretFlagsRegMem<int16_t>(inst, pc, true);
      break;
    case INSN_X64_CMP32RM:
      interpretFlagsRegMem<int32_t>(inst, pc, true);
      break;
    case INSN_X64_CMP64RM:
      interpretFlagsRegMem<int64_t>(inst, pc, true);
      break;
    case INSN_X64_CMP8MR:
      interpretFlagsMemReg<int8_t>(inst, pc, true);
      break;
    case INSN_X64_CMP16MR:
      interpretFlagsMemReg<int16_t>(inst, pc, true);
      break;
    case INSN_X64_CMP32MR:
      interpretFlagsMemReg<int32_t>(inst, pc, true);
      break;
    case INSN_X64_CMP64MR:
      interpretFlagsMemReg<int64_t>(inst, pc, true);
      break;
    case INSN_X64_TEST8MI:
      interpretFlagsMemImm<int8_t, int8_t>(inst, pc, false);
      break;
    case INSN_X64_TEST8MR:
      interpretFlagsMemReg<int8_t>(inst, pc, false);
      break;
    case INSN_X64_TEST16MI:
      interpretFlagsMemImm<int16_t, int8_t>(inst, pc, false);
      break;
    case INSN_X64_TEST16MR:
      interpretFlagsMemReg<int16_t>(inst, pc, false);
      break;
    case INSN_X64_TEST32MI:
      interpretFlagsMemImm<int32_t, int8_t>(inst, pc, false);
      break;
    case INSN_X64_TEST32MR:
      interpretFlagsMemReg<int32_t>(inst, pc, false);
      break;
    case INSN_X64_TEST64MI32:
      interpretFlagsMemImm<int64_t, int32_t>(inst, pc, false);
      break;
    case INSN_X64_TEST64MR:
      interpretFlagsMemReg<int64_t>(inst, pc, false);
      break;
    // encoded meta data layout:[uint16_t, uint16_t, [uint16_t-memory_items],
    // uint64_t] i.e.: cmov reg0, reg1, [mem], cond
    case INSN_X64_CMOV16RM:
    case INSN_X64_CMOV32RM:
    case INSN_X64_CMOV64RM:
      interpretCondMovRegMem(inst, pc);
      break;
    default:
#if ARCH_X64
      if (inst->rflag && *(uint32_t *)(pc + inst->len - 4) == 0) {
        // relocate and emulate the SSE instruction
        interpretSSERegMem(inst, pc);
        break;
      }
#endif
      log_print(Runtime, "Unknown instruction type {} at rva {:x}.", inst->type,
                robject_->vm2vrva(pc));
      abort();
      break;
    }
    // hit return address
    if (pc == reinterpret_cast<uint64_t>(topReturn()))
      return true;
    // advance to the next instruction if didn't jump
    if (!jump) {
      pc += inst->len;
      inst++;
    }
  }
  // indicates the current instruction has been processed
  return true;
}

bool ExecEngine::execLoop(uint64_t pc) {
#if WIN_ARM64
  auto epochptr = Loader::simulateTlsEpoch();
  auto tlsepoch = reinterpret_cast<uint64_t *>(wintls_ + 0x58);
#endif

  // debugger internal thread
  Debugger::Thread *dbgthread = nullptr;
  if (debugger_)
    dbgthread = debugger_->enter(robject_->arch(), &engine);

  // pc register id for different architecture
  int pcreg;
  switch (robject_->arch()) {
  case AArch64:
    pcreg = Register::PC;
    break;
  case X86_64:
    pcreg = Register::RIP;
    break;
  default:
    UNIMPL_ABORT();
    return false;
  }
  // instruction information related to pc
  auto inst = robject_->insnInfo(pc);
  auto defstep = RunConfig::inst()->stepSize();
  // cache the last jump destination, it can make loop running faster
  // because of avoiding dynamic searching for the target instruction
  auto lastjpc = pc;
  auto lastjinst = inst;
  // executing loop, break when hitting the initialized return address
  while (pc != reinterpret_cast<uint64_t>(topReturn())) {
    // debugging
    if (debugger_) {
      debugger_->entry(dbgthread, robject_->vm2vrva(pc), inst);
      if (debugger_->stopped()) {
        // stop executing by user request
        break;
      }
    }

    // interpret relocation, branch, call, jump and syscall etc.
    auto step = defstep;
    if (interpret(inst, pc, step)) {
      continue;
    }

#if LOG_EXECUTION
    log_print(Develop, "Emulation {:x}", robject_->vm2vrva(pc));
#endif

#if WIN_ARM64
    // as we haven't relocated the real relocation for tls epoch,
    // herein give it the simulated address
    auto oldepochptr = tlsepoch[0];
    *tlsepoch = reinterpret_cast<uint64_t>(&epochptr);
#endif

    // running instructions by AetherVM engine
    for (auto i = 0; i < step; i++, inst++)
      engine_.emulate({(uint8_t *)pc, inst->len});

#if WIN_ARM64
    // restore the original epoch pointer
    *tlsepoch = oldepochptr;
#endif

    // update current pc
    pc = engine_.readRegister(aether::Register::PC)->u8;
    // check whether the last instruction is jump type
    if (inst->rva != robject_->vm2rvaSimple(pc)) {
      if (pc == lastjpc) {
        // use the cached instruction
        inst = lastjinst;
      } else {
        // dynamically search the destination instruction
        inst = robject_->insnInfo(pc);
        // cache the jump destination instruction
        lastjinst = inst;
        lastjpc = pc;
      }
    }
  }
  if (debugger_)
    debugger_->leave();
  return true;
}

#define reg_write(reg, val)                                                    \
  {                                                                            \
    auto u64 = reinterpret_cast<uint64_t>(val);                                \
    engine.setRegister(reg, &u64);                                             \
  }

void ExecEngine::initMainRegisterAArch64(const void *argc, const void *argv) {
  // x0: argc
  // x1: argv
  reg_write(Register::X0, argc);
  reg_write(Register::X1, argv);
  reg_write(Register::SP, topStack());
  reg_write(Register::LR, topReturn());
}

void ExecEngine::initMainRegisterCommonX64() {
  auto rsp = reinterpret_cast<void **>(topStack());
  // push topReturn()
  rsp--;
  rsp[0] = topReturn();
  reg_write(Register::RSP, reinterpret_cast<const void *>(rsp));
}

void ExecEngine::initMainRegisterSysVX64(const void *argc, const void *argv) {
  // System V AMD64 ABI
  // rdi: argc
  // rsi: argv
  reg_write(Register::RDI, argc);
  reg_write(Register::RSI, argv);
  initMainRegisterCommonX64();
}

void ExecEngine::initMainRegisterWinX64(const void *argc, const void *argv) {
  // Microsoft Windows X64 ABI
  // rcx: argc
  // rdx: argv
  reg_write(Register::RCX, argc);
  reg_write(Register::RDX, argv);
  initMainRegisterCommonX64();
}

void ExecEngine::dump() {
  // load registers
  uint64_t regs[32], regsz, pc;
  switch (robject_->arch()) {
  case AArch64: {
    auto ctx = loadRegisterAArch64();
    regsz = 31;
    engine.getRegister(Register::PC, &pc);
    std::memcpy(regs, &ctx, sizeof(regs[0]) * regsz);
    break;
  }
  case X86_64: {
    auto ctx = loadRegisterX64();
    regsz = 15;
    engine.getRegister(Register::RIP, &pc);
    std::memcpy(regs, &ctx, sizeof(regs[0]) * regsz);
    break;
  }
  default:
    regsz = 0;
    break;
  }

  log_print(Raw,
            "\nICPP crashed when running {}, here's some details:\n"
            "Current pc=0x{:x}, rva=0x{:x}, "
            "opc={:016x}.\n",
            iargs_[0], pc, robject_->vm2vrva(pc),
            *reinterpret_cast<uint64_t *>(pc));
  robject_->dump();

  Debugger debugger(Stopped);
  debugger.dump(robject_->arch(), &engine, robject_->vm2vrva(pc));

  log_print(Raw, "\n");
  std::longjmp(jmpbuf_, true);
}

static bool llvm_signal_installed = false;
static void llvm_signal_handler(void *) {
  exec_engine->dump();
  // never return to llvm
  std::exit(-1);
}

int ExecEngine::run(bool lib) {
  if (!loader_.valid()) {
    return -1;
  }

  if (!llvm_signal_installed) {
    llvm_signal_installed = true;
    llvm::sys::AddSignalHandler(llvm_signal_handler, nullptr);
  }

  if (RunConfig::inst()->hasDebugger()) {
    log_print(Runtime, "Debugging object {}", robject_->path());
  }

  if (execCtor()) {
    if (!lib && execMain()) {
      if (!robject_->isCache() && !RunConfig::repl && !RunConfig::gadget &&
          !exitcode_) {
        // generate the interpretable object file if everthing went well
        robject_->generateCache();
      }
    }
  }
  return exitcode_;
}

int exec_main(std::string_view path, const std::vector<std::string> &deps,
              std::string_view srcpath, int iargc, char **iargv,
              bool &validcache) {
  auto object = create_object(srcpath, path, validcache);
  if (!object)
    return -1;
  if (!object->valid()) {
    log_print(Runtime, "Unsupported input arch type, currently supported arch "
                       "includes: X86_64, AArch64.");
    return -1;
  }
  if (object->arch() != host_arch()) {
    log_print(Runtime,
              "Unsupported input arch type, currently supported arch "
              "should be the same as host's, expected {}.",
              arch_name(host_arch()));
    return -1;
  }

  // construct arguments passed to the main entry of the input file
  std::vector<const char *> iargs;
  iargs.push_back(srcpath.data());
  for (int i = 0; i < iargc; i++)
    iargs.push_back(iargv[i]);
  return ExecEngine(object, deps, iargs).run();
}

void exec_object(std::shared_ptr<Object> object) {
  std::vector<std::string> deps;
  std::vector<const char *> iargs;
  iargs.push_back(object->path().data());
  ExecEngine(object, deps, iargs).run();
}

void init_library(std::shared_ptr<Object> imod) {
  std::vector<std::string> deps;
  std::vector<const char *> iargs;
  iargs.push_back(imod->path().data());
  ExecEngine(imod, deps, iargs).run(true);
}

} // namespace icpp
