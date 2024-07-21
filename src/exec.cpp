/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "exec.h"
#include "debugger.h"
#include "loader.h"
#include "object.h"
#include "platform.h"
#include "runcfg.h"
#include "utils.h"

#include <csetjmp>
#include <llvm/ADT/Twine.h>
#include <llvm/BinaryFormat/Magic.h>
#include <llvm/Support/Signals.h>
#include <mutex>
#include <unicorn/unicorn.h>

#define LOG_EXECUTION 0

namespace icpp {

// uc instance cache
struct UnicornEngine {
  uc_engine *acquire(Object *object) {
    std::lock_guard lock(mutex);
    uc_engine *uc;
    if (free.size()) {
      // get a free cache uc
      uc = *free.begin();
      free.erase(free.begin());
    } else {
      // there's no available cache uc, create a new one
      auto err = uc_open(arch(object), mode(object), &uc);
      if (err != UC_ERR_OK) {
        std::cout << "Failed to create unicorn engine instance: "
                  << uc_strerror(err) << std::endl;
        std::exit(-1);
      }
#if __x86_64__
      // make sure the dr7 contains 0, as we'll reuse it as a zero register,
      // this situation will occur when the llvm MCInst contains an EIZ/RIZ
      // register
      uint64_t zero = 0;
      uc_reg_write(uc, UC_X86_REG_DR7, &zero);
#else
      // use the max version of arm64 cpu
      uc_ctl_set_cpu_model(uc, UC_CPU_ARM64_MAX);
#endif
    }
    busy.insert(uc);
    return uc;
  }

  void release(uc_engine *uc) {
    std::lock_guard lock(mutex);
    // save to free list
    free.insert(uc);
    // remove from busy list
    busy.erase(busy.find(uc));
  }

  static uc_arch arch(Object *object) {
    switch (object->arch()) {
    case AArch64:
      return UC_ARCH_ARM64;
    case X86_64:
      return UC_ARCH_X86;
    default:
      return UC_ARCH_MAX; // unsupported
    }
  }

  static uc_mode mode(Object *object) {
    switch (object->arch()) {
    case X86_64:
      return UC_MODE_64;
    default:
      return UC_MODE_LITTLE_ENDIAN;
    }
  }

  ~UnicornEngine() {
    // release all cached uc instance
    for (auto uc : free)
      uc_close(uc);
    for (auto uc : busy)
      log_print(
          Develop,
          "Virtual CPU instance {} is still running while exiting program.",
          reinterpret_cast<void *>(uc));
  }

private:
  // available uc instance
  std::set<uc_engine *> free;
  // uc instance used by some thread
  std::set<uc_engine *> busy;

  std::mutex mutex;
} ue;

struct ExecEngine {
  // clone a new execute engine for thread function
  ExecEngine(ExecEngine &exec)
      : loader_(exec.loader_), iargs_(exec.iargs_), iobject_(exec.iobject_) {
    init();
  }

  ExecEngine(std::shared_ptr<Object> object,
             const std::vector<std::string> &deps,
             const std::vector<const char *> &iargs)
      : loader_(object.get(), deps), iargs_(iargs), iobject_(object) {
    init();
  }
  ~ExecEngine() {
    // execute destructor in iobject file
    execDtor();
    // give back the borrowed uc instance
    ue.release(uc_);

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
  template <typename TSRC, typename TDES>
  void interpretSignExtendRegMem(const InsnInfo *&inst, uint64_t &pc);

  /*
  register startup initializer
  */
  void initMainRegister(const void *argc, const void *argv);
  void initMainRegisterAArch64(const void *argc, const void *argv);
  void initMainRegisterSysVX64(const void *argc, const void *argv);
  void initMainRegisterWinX64(const void *argc, const void *argv);
  void initMainRegisterCommonX64();

  /*
  helper routines for unicorn and host register context switch
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

private:
  // object dependency module loader
  Loader loader_;
  // argc and argv for object main entry
  const std::vector<const char *> &iargs_;

  // current running object instance
  Object *robject_ = nullptr;
  // the initial object instance
  std::shared_ptr<Object> iobject_;

  // virtual qemu processor from unicorn engine
  uc_engine *uc_ = nullptr;
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
};

void ExecEngine::run(uint64_t pc, ContextICPP *regs) {
  constexpr const int stack_switch_size = 128;
  // backup the old context and set a new one
#if ARCH_ARM64
  auto pcrid = UC_ARM64_REG_PC;
  auto backup = loadRegisterAArch64();
  char *vmstack =
      reinterpret_cast<char *>(backup.r[A64_SP]) - stack_switch_size;
  char *hoststack = reinterpret_cast<char *>(regs->r[A64_SP]);
  // load host stack
  std::memcpy(vmstack, hoststack, stack_switch_size);
  topreturn_ = reinterpret_cast<void *>(regs->r[A64_LR]);
  // set vm stack
  regs->r[A64_SP] = reinterpret_cast<uint64_t>(vmstack);
  saveRegisterAArch64(*regs);
#else
  auto pcrid = UC_X86_REG_RIP;
  auto backup = loadRegisterX64();
  char *vmstack = reinterpret_cast<char *>(backup.rsp) - stack_switch_size;
  char *hoststack = reinterpret_cast<char *>(regs->rsp);
  // load host stack
  std::memcpy(vmstack, hoststack, stack_switch_size);
  topreturn_ = *reinterpret_cast<void **>(regs->rsp);
  // set vm stack
  regs->rsp = reinterpret_cast<uint64_t>(vmstack);
  saveRegisterX64(*regs);
#endif
  // backup old pc
  uint64_t pcbackup;
  uc_reg_read(uc_, pcrid, &pcbackup);

  // run the current pc
  execLoop(pc);
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
  uc_reg_write(uc_, pcrid, &pcbackup);
}

extern "C" void exec_engine_main(StubContext *ctx, ContextICPP *regs) {
  auto engine = (ExecEngine *)(ctx->context);
  engine->run(ctx->vmfunc, regs);
}

void ExecEngine::init() {
  robject_ = iobject_.get();
  // get a unicorn instruction emulation instance
  uc_ = ue.acquire(robject_);

  // set the initial register context copied from host
  ContextICPP initctx;
  host_context(&initctx);
#if ARCH_ARM64
  saveRegisterAArch64(initctx);
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
  auto page = alloc_page(stubend_);
  stubcode_ = page;
  stubpages_.push_back(page);

  // make function stub, the vm function called from host side must
  // be in stub mode, because the page it belongs to doesn't have the
  // executable permission
  for (auto spot : iobject_->stubSpots()) {
    auto target = *reinterpret_cast<uint64_t *>(spot);
    auto found = vmstubs_.find(target);
    if (found == vmstubs_.end()) {
      // create a new stub for this iobject vm target function
      auto stub = host_callback_stub({this, target}, stubcode_);
      found = vmstubs_.insert({target, reinterpret_cast<uint64_t>(stub)}).first;
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
    *reinterpret_cast<uint64_t *>(spot) = found->second;
  }

  // set the stub page in read&exec mode
  page_executable(page);
  page_flush(page);

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
    regid = UC_ARM64_REG_X0;
    break;
  case X86_64:
    regid = UC_X86_REG_RAX;
    break;
  default:
    return 0;
  }
  uint64_t value;
  uc_reg_read(uc_, regid, &value);
  return value;
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
  int rids[4]; // register id
  switch (robject_->arch()) {
  case AArch64:
    rids[0] = UC_ARM64_REG_X0;
    rids[1] = UC_ARM64_REG_X1;
    rids[2] = UC_ARM64_REG_X2;
    rids[3] = UC_ARM64_REG_X3;
    break;
  case X86_64:
    switch (robject_->type()) {
    case COFF_Exe:
    case COFF_Reloc:
      // windows abi: rcx, rdx, r8, r9
      rids[0] = UC_X86_REG_RCX;
      rids[1] = UC_X86_REG_RDX;
      rids[2] = UC_X86_REG_R8;
      rids[3] = UC_X86_REG_R9;
      break;
    default:
      // system v abi: rdi, rsi, rdx, rcx, r8, r9
      rids[0] = UC_X86_REG_RDI;
      rids[1] = UC_X86_REG_RSI;
      rids[2] = UC_X86_REG_RDX;
      rids[3] = UC_X86_REG_RCX;
      break;
    }
    break;
  default:
    UNIMPL_ABORT();
    break;
  }
  // read current arugments
  for (size_t i = 0; i < std::size(args); i++)
    uc_reg_read(uc_, rids[i], &args[i]);
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
    log_print(Runtime, "Exception thrown in script: exception={:x}, rtti={:x}.",
              args[0], args[1]);
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
  } else {
    for (size_t i = 0; i < std::size(args); i++) {
      Object *iobj;
      if (robject_->executable(target, &iobj)) {
        auto found = vmstubs_.find(target);
        if (found == vmstubs_.end()) {
          // create a new stub for this iobject vm target function
          found = vmstubs_.insert({target, createStub(target)}).first;
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
      uc_reg_write(uc_, rids[i], &args[i]);
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
  if (executable(target)) {
    // call internal function
    // set return address
    uc_reg_write(uc_, UC_ARM64_REG_LR, &retaddr);
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
  uc_reg_write(uc_, metaptr[0], reinterpret_cast<const void *>(target));
}

bool ExecEngine::interpretCallX64(const InsnInfo *&inst, uint64_t &pc,
                                  uint64_t target) {
  auto retaddr = pc + inst->len;
  if (executable(target)) {
    uint64_t rsp;
    uc_reg_read(uc_, UC_X86_REG_RSP, &rsp);
    // push return address
    rsp -= 8;
    *reinterpret_cast<uint64_t *>(rsp) = retaddr;
    uc_reg_write(uc_, UC_X86_REG_RSP, &rsp);
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
    uc_reg_read(uc_, UC_X86_REG_RSP, &rsp);
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
  uint64_t basereg = 0, expreg = 0;
  // read base and exponent register value
  uc_reg_read(uc_, ops[basereg_op_idx], &basereg);
  uc_reg_read(uc_, ops[expreg_op_idx], &expreg);
  // pickup exponent and offset value
  auto expimm = *reinterpret_cast<const int64_t *>(&ops[expimm_op_idx]);
  auto offimm = *reinterpret_cast<const int64_t *>(&ops[offimm_op_idx]);
  // calculate the final memory address from raw instruction
  uint64_t memaddr = (uint64_t)(basereg + expimm * expreg + offimm);
  if (ops[basereg_op_idx] == UC_X86_REG_RIP) {
    // rip related memory reference
    if (inst->rflag) {
      // relocate to other runtime address
      memaddr = reinterpret_cast<uint64_t>(robject_->relocTarget(inst->reloc)) +
                offimm;
    } else {
      // adjust location with instruction length
      memaddr += inst->len;
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
    uc_reg_write(uc_, ops[regop], reinterpret_cast<const void *>(target));
  } else {
    // mov mem, reg
    uint64_t value[4];
    auto regid = ops[regop];
    uc_reg_read(uc_, ops[regop], value);
    if (UC_X86_REG_YMM0 <= regid && regid <= UC_X86_REG_ZMM31) {
      log_print(Runtime, "YMM/ZMM register moving isn't supported now.");
      abort();
    } else if (UC_X86_REG_XMM0 <= regid && regid <= UC_X86_REG_XMM31) {
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
  uc_reg_read(uc_, ops[11], value);
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
  auto updator = cmp ? host_naked_compare : host_naked_test;
  // calculate the new rflags
  auto rflags =
      updator(*reinterpret_cast<const TSRC *>(target),
              static_cast<TSRC>(*reinterpret_cast<const TDES *>(&ops[11])));
  // update rflags
  uc_reg_write(uc_, UC_X86_REG_RFLAGS, &rflags);
}

template <typename T>
void ExecEngine::interpretFlagsRegMem(const InsnInfo *&inst, uint64_t &pc,
                                      bool cmp) {
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, 1, &ops);
  // cmp/test instruction
  auto updator = cmp ? host_naked_compare : host_naked_test;
  uint64_t value;
  uc_reg_read(uc_, ops[0], &value);
  // calculate the new rflags
  auto rflags =
      updator(static_cast<T>(value), *reinterpret_cast<const T *>(target));
  // update rflags
  uc_reg_write(uc_, UC_X86_REG_RFLAGS, &rflags);
}

template <typename TSRC, typename TDES>
void ExecEngine::interpretSignExtendRegMem(const InsnInfo *&inst,
                                           uint64_t &pc) {
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, 1, &ops);
  // movsx reg, mem
  auto result = static_cast<TSRC>(*reinterpret_cast<const TDES *>(target));
  uc_reg_write(uc_, ops[0], &result);
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
  case INSN_X64_JUMPREG:
  case INSN_X64_JUMPMEM:
    return false;
  case INSN_HARDWARE:
    return true;
  default:
    // if the current instruction contains relocation, then it must
    // be interpreted otherwise emulated.
    return inst->rflag == 0;
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
    // uc_emu_start continue to execute it
    return false;
  }
  // interpret the pre-decoded instructions
  for (unsigned i = 0; i < origstep && inst->type != INSN_HARDWARE; i++) {
#if LOG_EXECUTION
    log_print(Develop, "Interpret {:x} I{}", inst->rva, inst->type);
#endif

    // call and return within object should update this to true
    bool jump = false;
    switch (inst->type) {
    // common instruction
    case INSN_ABORT:
      log_print(Runtime,
                "Breakpoint or trap instruction hit at rva {:x}. Aborting...",
                robject_->vm2rva(pc));
      dump();
      std::exit(-1);
      break;
    // conditional jump instruction
    case INSN_CONDJUMP:
      // only let unicorn engine consumed 1 instruction in this situation
      step = 1;
      return false;
    // arm64 instruction
    case INSN_ARM64_RETURN: {
      uint64_t retaddr;
      uc_reg_read(uc_, UC_ARM64_REG_LR, &retaddr);
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
      uc_reg_read(uc_, metaptr[0], &target);
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
      uc_reg_read(uc_, metaptr[0], &target);
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
      uc_reg_write(uc_, metaptr[0], &target);
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
      uc_reg_read(uc_, UC_X86_REG_RSP, &rsp);
      retaddr = *reinterpret_cast<uint64_t *>(rsp);
      // pop return address
      rsp += 8;
      // instruction: retn bytes
      rsp += *robject_->metaInfo<uint64_t>(inst, pc);
      uc_reg_write(uc_, UC_X86_REG_RSP, &rsp);
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
      uc_reg_read(uc_, metaptr[0], &target);
      target = checkStub(target);
      jump = interpretCallX64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[[uint16_t-memory_items]]
    case INSN_X64_CALLMEM: {
      auto target = interpretCalcMemX64(inst, pc, 0);
      jump = interpretCallX64(inst, pc, *reinterpret_cast<uint64_t *>(target));
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
    // encoded meta data layout:[uint16_t]
    case INSN_X64_JUMPREG: {
      auto metaptr = robject_->metaInfo<uint16_t>(inst, pc);
      uint64_t target;
      uc_reg_read(uc_, metaptr[0], &target);
      target = checkStub(target);
      jump = interpretJumpX64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[[uint16_t-memory_items]]
    case INSN_X64_JUMPMEM: {
      auto target = interpretCalcMemX64(inst, pc, 0);
      jump = interpretJumpX64(inst, pc, *reinterpret_cast<uint64_t *>(target));
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
      interpretMovX64<uint32_t>(inst, pc, 11, 0, false);
      break;
    case INSN_X64_MOV64MI32:
      interpretMovMIX64<uint64_t>(inst, pc);
      break;
    // encoded meta data layout:[uint16_t, [uint16_t-memory_items]]
    case INSN_X64_LEA32:
    case INSN_X64_LEA64: {
      const uint16_t *ops;
      auto target = interpretCalcMemX64(inst, pc, 1, &ops);
      uc_reg_write(uc_, ops[0], reinterpret_cast<const void *>(&target));
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
    case INSN_X64_CMP8MI:
    case INSN_X64_CMP8MI8:
      interpretFlagsMemImm<uint8_t, uint8_t>(inst, pc, true);
      break;
    case INSN_X64_CMP16MI:
      interpretFlagsMemImm<uint16_t, uint16_t>(inst, pc, true);
      break;
    case INSN_X64_CMP16MI8:
      interpretFlagsMemImm<uint16_t, uint8_t>(inst, pc, true);
      break;
    case INSN_X64_CMP32MI:
      interpretFlagsMemImm<uint32_t, uint32_t>(inst, pc, true);
      break;
    case INSN_X64_CMP32MI8:
      interpretFlagsMemImm<uint32_t, uint8_t>(inst, pc, true);
      break;
    case INSN_X64_CMP64MI32:
      interpretFlagsMemImm<uint64_t, uint32_t>(inst, pc, true);
      break;
    case INSN_X64_CMP64MI8:
      interpretFlagsMemImm<uint64_t, uint8_t>(inst, pc, true);
      break;
    case INSN_X64_CMP8RM:
      interpretFlagsRegMem<uint8_t>(inst, pc, true);
      break;
    case INSN_X64_CMP16RM:
      interpretFlagsRegMem<uint16_t>(inst, pc, true);
      break;
    case INSN_X64_CMP32RM:
      interpretFlagsRegMem<uint32_t>(inst, pc, true);
      break;
    case INSN_X64_CMP64RM:
      interpretFlagsRegMem<uint64_t>(inst, pc, true);
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
    case INSN_X64_TEST8MI:
      interpretFlagsMemImm<uint8_t, uint8_t>(inst, pc, false);
      break;
    case INSN_X64_TEST8MR:
      interpretFlagsRegMem<uint8_t>(inst, pc, false);
      break;
    case INSN_X64_TEST16MI:
      interpretFlagsMemImm<uint16_t, uint8_t>(inst, pc, false);
      break;
    case INSN_X64_TEST16MR:
      interpretFlagsRegMem<uint16_t>(inst, pc, false);
      break;
    case INSN_X64_TEST32MI:
      interpretFlagsMemImm<uint32_t, uint8_t>(inst, pc, false);
      break;
    case INSN_X64_TEST32MR:
      interpretFlagsRegMem<uint32_t>(inst, pc, false);
      break;
    case INSN_X64_TEST64MI32:
      interpretFlagsMemImm<uint64_t, uint32_t>(inst, pc, false);
      break;
    case INSN_X64_TEST64MR:
      interpretFlagsRegMem<uint64_t>(inst, pc, false);
      break;
    default:
      log_print(Runtime, "Unknown instruction type {} at rva {:x}.", inst->type,
                robject_->vm2rva(pc));
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
  // debugger internal thread
  Debugger::Thread *dbgthread = nullptr;
  if (debugger_)
    dbgthread = debugger_->enter(robject_->arch(), uc_);

  // pc register id for different architecture
  int pcreg;
  switch (robject_->arch()) {
  case AArch64:
    pcreg = UC_ARM64_REG_PC;
    break;
  case X86_64:
    pcreg = UC_X86_REG_RIP;
    break;
  default:
    UNIMPL_ABORT();
    return false;
  }
  // instruction information related to pc
  auto inst = robject_->insnInfo(pc);
  // cache the last jump destination, it can make loop running faster
  // because of avoiding dynamic searching for the target instruction
  auto lastjpc = pc;
  auto lastjinst = inst;
  // executing loop, break when hitting the initialized return address
  while (pc != reinterpret_cast<uint64_t>(topReturn())) {
    // debugging
    if (debugger_) {
      debugger_->entry(dbgthread, inst->rva, inst);
      if (debugger_->stopped()) {
        // stop executing by user request
        break;
      }
    }

    // interpret relocation, branch, call, jump and syscall etc.
    auto step = RunConfig::inst()->stepSize();
    if (interpret(inst, pc, step)) {
      continue;
    }

#if LOG_EXECUTION
    log_print(Develop, "Emulation {:x}", inst->rva);
#endif

    // running instructions by unicorn engine
    auto err = uc_emu_start(uc_, pc, -1, 0, step);
    if (err != UC_ERR_OK) {
      log_print(Runtime, "Fatal error occurred: {}.", uc_strerror(err));
      dump();
      std::exit(-1);
    }

    // update current pc
    uc_reg_read(uc_, pcreg, &pc);
    // update inst with step
    inst += step;
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
    uc_reg_write(uc_, reg, &u64);                                              \
  }

void ExecEngine::initMainRegisterAArch64(const void *argc, const void *argv) {
  // x0: argc
  // x1: argv
  reg_write(UC_ARM64_REG_X0, argc);
  reg_write(UC_ARM64_REG_X1, argv);
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

void ExecEngine::initMainRegisterSysVX64(const void *argc, const void *argv) {
  // System V AMD64 ABI
  // rdi: argc
  // rsi: argv
  reg_write(UC_X86_REG_RDI, argc);
  reg_write(UC_X86_REG_RSI, argv);
  initMainRegisterCommonX64();
}

void ExecEngine::initMainRegisterWinX64(const void *argc, const void *argv) {
  // Microsoft Windows X64 ABI
  // rcx: argc
  // rdx: argv
  reg_write(UC_X86_REG_RCX, argc);
  reg_write(UC_X86_REG_RDX, argv);
  initMainRegisterCommonX64();
}

void ExecEngine::dump() {
  // load registers
  uint64_t regs[32], regsz, pc;
  switch (robject_->arch()) {
  case AArch64: {
    auto ctx = loadRegisterAArch64();
    regsz = 31;
    uc_reg_read(uc_, UC_ARM64_REG_PC, &pc);
    std::memcpy(regs, &ctx, sizeof(regs[0]) * regsz);
    break;
  }
  case X86_64: {
    auto ctx = loadRegisterX64();
    regsz = 15;
    uc_reg_read(uc_, UC_X86_REG_RIP, &pc);
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
            iargs_[0], pc, robject_->vm2rva(pc),
            *reinterpret_cast<uint64_t *>(pc));
  robject_->dump();

  Debugger debugger(Stopped);
  debugger.dump(robject_->arch(), uc_, robject_->vm2rva(pc));

  log_print(Raw, "Address Details:");
  for (uint64_t i = 0; i < regsz; i++) {
    if (robject_->executable(regs[i], nullptr)) {
      auto info = robject_->sourceInfo(regs[i]);
      log_print(Raw, "{:08x}: {}",
                static_cast<uint32_t>(robject_->vm2rva(regs[i])), info);
    }
  }

  log_print(Raw, "\n");
  std::longjmp(jmpbuf_, true);
}

// current execution engine instance
static ExecEngine *exec_engine = nullptr;
static bool llvm_signal_installed = false;
static void llvm_signal_handler(void *) {
  exec_engine->dump();
  // never return to llvm
  std::exit(-1);
}

int ExecEngine::run(bool lib) {
  if (!uc_ || !loader_.valid()) {
    return -1;
  }

  if (!llvm_signal_installed) {
    llvm_signal_installed = true;
    llvm::sys::AddSignalHandler(llvm_signal_handler, nullptr);
  }
  // update current execute engine instance
  exec_engine = this;

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
  for (int i = 0; i < iargc - 1; i++)
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
