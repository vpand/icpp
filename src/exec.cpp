/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
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
#include <mutex>

#if ICPP_GADGET
#if __APPLE__
#include "client/mac/handler/exception_handler.h"
#elif __linux__
#include "client/linux/handler/exception_handler.h"
#else
#include "client/windows/handler/exception_handler.h"
#endif
#else
#include "llvm/Support/Signals.h"
#endif

#ifdef _WIN32
#include <Windows.h>
#else
#include <pthread.h>
#endif

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
      auto err = uc_open(object->ucArch(), object->ucMode(), &uc);
      if (err != UC_ERR_OK) {
        std::cout << "Failed to create unicorn engine instance: "
                  << uc_strerror(err) << std::endl;
        std::exit(-1);
      }
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

  ~UnicornEngine() {
    // release all cached uc instance
    for (auto uc : free)
      uc_close(uc);
    for (auto uc : busy)
      log_print(
          Runtime,
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
      : loader_(exec.loader_), runcfg_(exec.runcfg_), iargs_(exec.iargs_),
        iobject_(exec.iobject_) {
    init();
  }

  ExecEngine(std::shared_ptr<Object> object,
             const std::vector<std::string> &deps, const char *procfg,
             const std::vector<const char *> &iargs)
      : loader_(object.get(), deps), runcfg_(procfg), iargs_(iargs),
        iobject_(object) {
    init();
  }
  ~ExecEngine() {
    // execute destructor in iobject file
    execDtor();
    // give back the borrowed uc instance
    ue.release(uc_);
  }

  void run();
  bool run(uint64_t vm, uint64_t arg0, uint64_t arg1);
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

  // icpp interpret entry
  bool interpret(const InsnInfo *&inst, uint64_t &pc, int &step);

  // some special functions should be invoked with stub helper
  // e.g.: thread create, system api callback, etc.
  bool specialCallProcess(uint64_t target);

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
    return reinterpret_cast<char *>(stack_.data()) + runcfg_.stackSize();
  }

  constexpr void *topReturn() { return static_cast<void *>(this); }

private:
  // object dependency module loader
  Loader loader_;
  // running config for advanced user from a json configuration file
  RunConfig runcfg_;
  // argc and argv for object main entry
  const std::vector<const char *> &iargs_;

  // current running object instance
  Object *robject_ = nullptr;
  // the initial object instance
  std::shared_ptr<Object> iobject_;
  /*
  virtual processor and debugger
  */
  uc_engine *uc_ = nullptr;
  std::unique_ptr<Debugger> debugger_;

  // vm stack
  std::string stack_;
};

void ExecEngine::init() {
  robject_ = iobject_.get();
  // get a unicorn instruction emulation instance
  uc_ = ue.acquire(robject_);

  if (runcfg_.hasDebugger()) {
    // initialize debugger instance
    debugger_ = std::make_unique<Debugger>();
  }
  // interpreter vm stack buffer
  stack_.resize(runcfg_.stackSize());
}

bool ExecEngine::execCtor() { return true; }

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
    // save iobject module to loader cache
    Loader::cacheObject(iobject_);

    // module has no main but it's a valid iobject,
    // return true to have a chance to generate its cache
    return true;
  }

  return run(reinterpret_cast<uint64_t>(mainfn), iargs_.size(),
             reinterpret_cast<uint64_t>(&iargs_[0]));
}

bool ExecEngine::run(uint64_t vm, uint64_t arg0, uint64_t arg1) {
  try {
    initMainRegister(reinterpret_cast<const void *>(arg0),
                     reinterpret_cast<const void *>(arg1));
    return execLoop(vm);
  } catch (std::system_error &e) {
    log_print(Runtime, "Exception ocurred, system error: {}.", e.what());
  } catch (std::logic_error &e) {
    log_print(Runtime, "Exception ocurred, logical error: {}.", e.what());
  } catch (std::invalid_argument &e) {
    log_print(Runtime, "Exception ocurred, invalid argument error: {}.",
              e.what());
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

// thread function stub
#ifdef _WIN32
static HANDLE (*thread_create_func)(
    [ in, optional ] LPSECURITY_ATTRIBUTES lpThreadAttributes,
    [in] SIZE_T dwStackSize, [in] LPTHREAD_START_ROUTINE lpStartAddress,
    [ in, optional ] __drv_aliasesMem LPVOID lpParameter,
    [in] DWORD dwCreationFlags,
    [ out, optional ] LPDWORD lpThreadId) = CreateThread;
typedef DWORD thread_return_t;
#else
static int (*thread_create_func)(pthread_t *thread, const pthread_attr_t *attr,
                                 void *(*start_routine)(void *),
                                 void *arg) = pthread_create;
typedef void *thread_return_t;
#endif

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

bool ExecEngine::specialCallProcess(uint64_t target) {
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

  if (reinterpret_cast<uint64_t>(thread_create_func) == target) {
    // index of thread and argument in thread_create_func arguments list
#ifdef _WIN32
    int ientry = 1, iarg = 2;
#else
    int ientry = 2, iarg = 3;
#endif

    auto context = new exec_thread_context_t{this, args[ientry], args[iarg]};
    // replace to our stub instance
    args[ientry] = reinterpret_cast<uint64_t>(exec_thread_stub);
    args[iarg] = reinterpret_cast<uint64_t>(context);
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

bool ExecEngine::interpretCallAArch64(const InsnInfo *&inst, uint64_t &pc,
                                      uint64_t target) {
  auto retaddr = pc + inst->len;
  if (robject_->executable(target, &robject_)) {
    // call internal function
    // set return address
    uc_reg_write(uc_, UC_ARM64_REG_LR, &retaddr);
    pc = target;
    inst = robject_->insnInfo(pc); // update current inst
    return true;
  } else {
    // check and process some api which has callback argument
    specialCallProcess(target);

    // call external function
    auto context = loadRegisterAArch64();
    context.r[A64_LR] = retaddr; // set return address
    host_call(&context, reinterpret_cast<const void *>(target));
    saveRegisterAArch64(context);
    return false;
  }
}

bool ExecEngine::interpretJumpAArch64(const InsnInfo *&inst, uint64_t &pc,
                                      uint64_t target) {
  if (robject_->executable(target, &robject_)) {
    // jump to internal destination
    pc = target;
    inst = robject_->insnInfo(pc); // update current inst
    return true;
  } else {
    // jump to external function
    auto context = loadRegisterAArch64();
    if (robject_->executable(context.r[A64_LR], &robject_)) {
      // check and process some api which has callback argument
      specialCallProcess(target);

      // return to our control
      pc = context.r[A64_LR];
      host_call(&context, reinterpret_cast<const void *>(target));
      saveRegisterAArch64(context);
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
  if (robject_->executable(target, &robject_)) {
    auto retaddr = pc + inst->len;
    uint64_t rsp;
    uc_reg_read(uc_, UC_X86_REG_RSP, &rsp);
    // push return address
    rsp -= 8;
    *reinterpret_cast<uint64_t *>(rsp) = retaddr;
    // call internal function
    pc = target;
    inst = robject_->insnInfo(pc); // update current inst
    return true;
  } else {
    // check and process some api which has callback argument
    specialCallProcess(target);

    // call external function
    auto context = loadRegisterX64();
    host_call(&context, reinterpret_cast<const void *>(target));
    saveRegisterX64(context);
    return false;
  }
}

bool ExecEngine::interpretJumpX64(const InsnInfo *&inst, uint64_t &pc,
                                  uint64_t target) {
  if (robject_->executable(target, &robject_)) {
    // jump to internal destination
    pc = target;
    inst = robject_->insnInfo(pc); // update current inst
    return true;
  } else {
    // jump to external function
    uint64_t rsp, retaddr;
    uc_reg_read(uc_, UC_X86_REG_RSP, &rsp);
    retaddr = *reinterpret_cast<uint64_t *>(rsp);
    auto context = loadRegisterAArch64();
    if (robject_->executable(retaddr, &robject_)) {
      // check and process some api which has callback argument
      specialCallProcess(target);

      // return to our control
      pc = retaddr;
      host_call(&context, reinterpret_cast<const void *>(target));
      saveRegisterAArch64(context);
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
    uint64_t value;
    uc_reg_read(uc_, ops[regop], &value);
    *reinterpret_cast<T *>(target) = static_cast<T>(value);
  }
}

void ExecEngine::interpretMovMRX64(const InsnInfo *&inst, uint64_t &pc,
                                   int bytes) {
  const uint16_t *ops;
  auto target = interpretCalcMemX64(inst, pc, 0, &ops);

  uint64_t value[2];
  uc_reg_read(uc_, ops[11], &value);
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
#if 0
    log_print(Develop, "Interpret {:x} I{}", robject_->vm2rva(pc), inst->type);
#endif

    // call and return within object should update this to true
    bool jump = false;
    switch (inst->type) {
    // common instruction
    case INSN_ABORT:
      log_print(Runtime,
                "Breakpoint or trap instruction hit at rva {:x}.\nAborting...",
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
      if (robject_->executable(retaddr, &robject_)) {
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
      if (robject_->executable(retaddr, &robject_)) {
        // instruction: retn bytes
        rsp += *robject_->metaInfo<uint32_t>(inst, pc);
        uc_reg_write(uc_, UC_X86_REG_RSP, &rsp);
        pc = retaddr;
        inst = robject_->insnInfo(pc);
        jump = true;
      } else if (reinterpret_cast<const void *>(retaddr) == topReturn()) {
        rsp += *robject_->metaInfo<uint32_t>(inst, pc);
        uc_reg_write(uc_, UC_X86_REG_RSP, &rsp);
        pc = retaddr; // finished interpreting
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
      jump = interpretCallX64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[[uint16_t-memory_items]]
    case INSN_X64_CALLMEM: {
      auto target = interpretCalcMemX64(inst, pc, 0);
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
    // encoded meta data layout:[uint16_t]
    case INSN_X64_JUMPREG: {
      auto metaptr = robject_->metaInfo<uint16_t>(inst, pc);
      uint64_t target;
      uc_reg_read(uc_, metaptr[0], &target);
      jump = interpretJumpX64(inst, pc, target);
      break;
    }
    // encoded meta data layout:[[uint16_t-memory_items]]
    case INSN_X64_JUMPMEM: {
      auto target = interpretCalcMemX64(inst, pc, 0);
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
  // executing loop, break when hitting the initialized return address
  while (pc != reinterpret_cast<uint64_t>(topReturn())) {
    // debugging
    if (debugger_) {
      debugger_->entry(dbgthread, robject_->vm2rva(pc));
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

#if 0
    log_print(Develop, "Emulation {:x}", robject_->vm2rva(pc));
#endif

    // running instructions by unicorn engine
    auto err = uc_emu_start(uc_, pc, -1, 0, step);
    if (err != UC_ERR_OK) {
      log_print(Runtime, "Fatal error occurred: {}.", uc_strerror(err));
      dump();
      return false;
    }

    // update current pc
    uc_reg_read(uc_, pcreg, &pc);
    // update inst with step
    inst += step;
    if (inst->rva != robject_->vm2rva(pc)) {
      // last instruction is jump type
      inst = robject_->insnInfo(pc);
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

bool ExecEngine::execDtor() { return true; }

void ExecEngine::dump() {
  // load registers
  uint64_t regs[32], regsz, pc;
  int pcrid;
  switch (robject_->arch()) {
  case AArch64: {
    auto ctx = loadRegisterAArch64();
    regsz = 32;
    uc_reg_read(uc_, UC_ARM64_REG_PC, &pc);
    std::memcpy(regs, &ctx, sizeof(regs[0]) * regsz);
    break;
  }
  case X86_64: {
    auto ctx = loadRegisterX64();
    regsz = 16;
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
}

/*
signal hanlder to dump runtime information when crashes
*/
#if ICPP_GADGET

static bool breakpad_filter_callback(void *context) {
  auto exec = reinterpret_cast<ExecEngine *>(context);
  exec->dump();
  // never return to breakpad
  abort();
  return false;
}

#else

static ExecEngine *exec_engine = nullptr;
static bool llvm_signal_installed = false;
static void llvm_signal_handler(void *) {
  exec_engine->dump();
  // never return to llvm
  std::exit(-1);
}

#endif // ICPP_GADGET

void ExecEngine::run() {
  if (!uc_ || !loader_.valid()) {
    return;
  }

#if ICPP_GADGET
  google_breakpad::ExceptionHandler ehandler(
      "",                       /* minidump output directory */
      breakpad_filter_callback, /* filter */
      0,                        /* minidump callback */
      this                      /* calback_context */
#ifdef _WIN32
      ,
      google_breakpad::ExceptionHandler::HANDLER_ALL /* handler_types */
#else
      ,
      true /* install_handler */
#if __APPLE__
      ,
      nullptr /* port name, set to null so in-process dump generation is used.
               */
#endif
#endif
  );
#else
  if (!llvm_signal_installed) {
    llvm_signal_installed = true;
    llvm::sys::AddSignalHandler(llvm_signal_handler, nullptr);
  }
  // update current execute engine instance
  exec_engine = this;
#endif

  if (execCtor()) {
    if (execMain()) {
      if (!robject_->isCache()) {
        // generate the interpretable object file if everthing went well
        robject_->generateCache();
      }
    }
  }
}

void exec_main(std::string_view path, const std::vector<std::string> &deps,
               const char *procfg, std::string_view srcpath, int iargc,
               char **iargv) {
  llvm::file_magic magic;
  auto err = llvm::identify_magic(llvm::Twine(path), magic);
  if (err) {
    std::cout << "Failed to identify the file type of '" << path
              << "': " << err.message() << std::endl;
    return;
  }

  std::shared_ptr<Object> object;
  using fm = llvm::file_magic;
  switch (magic) {
  case fm::macho_object:
    object = std::make_unique<MachORelocObject>(srcpath, path);
    break;
  case fm::macho_executable:
    object = std::make_unique<MachOExeObject>(srcpath, path);
    break;
  case fm::elf_relocatable:
    object = std::make_unique<ELFRelocObject>(srcpath, path);
    break;
  case fm::elf_executable:
    object = std::make_unique<ELFExeObject>(srcpath, path);
    break;
  case fm::coff_object:
    object = std::make_unique<COFFRelocObject>(srcpath, path);
    break;
  case fm::pecoff_executable:
    object = std::make_unique<COFFExeObject>(srcpath, path);
    break;
  default: {
    if (path.ends_with(".io")) {
      auto tmp = std::make_unique<InterpObject>(srcpath, path);
      if (tmp->valid()) {
        object = std::move(tmp);
        break;
      }
    }
    std::cout << "Unsupported input file type " << magic
              << ", currently supported file type includes "
                 "MachO/ELF/PE-Object/Executable."
              << std::endl;
    return;
  }
  }
  if (!object->valid()) {
    std::cout << "Unsupported input file type " << magic
              << ", currently supported file type includes "
                 "MachO/ELF/PE-Object/Executable-X86_64/AArch64."
              << std::endl;
  }

  // construct arguments passed to the main entry of the input file
  std::vector<const char *> iargs;
  iargs.push_back(srcpath.data());
  for (int i = 0; i < iargc - 1; i++)
    iargs.push_back(iargv[i]);
  ExecEngine(object, deps, procfg, iargs).run();
}

} // namespace icpp
