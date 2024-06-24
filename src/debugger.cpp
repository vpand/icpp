/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "debugger.h"
#include <icppdbg.pb.h>
#include <unicorn/unicorn.h>

namespace icppdbg = com::vpand::icppdbg;

namespace icpp {

static void sendRespose(std::shared_ptr<ip::tcp::socket> s,
                        const std::string &respbuf) {
  boost::system::error_code error;
  asio::write(*s, asio::buffer(respbuf), error);
  if (error) {
    log_print(Develop, "Failed to send command buffer {}.\n", error.message());
  }
}

static void sendRespose(std::shared_ptr<ip::tcp::socket> s,
                        icppdbg::CommandID id, const std::string &result) {
  icppdbg::Respond resp;
  resp.set_cmd(id);
  resp.set_result(result);

  auto respbuf = resp.SerializeAsString();
  sendRespose(s, respbuf);
}

std::string Debugger::Thread::registers() {
  std::string strs;
  if (arch == AArch64) {
    uc_arm64_reg regs[] = {
        UC_ARM64_REG_X0,  UC_ARM64_REG_X1,  UC_ARM64_REG_X2,  UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,  UC_ARM64_REG_X5,  UC_ARM64_REG_X6,  UC_ARM64_REG_X7,
        UC_ARM64_REG_X8,  UC_ARM64_REG_X9,  UC_ARM64_REG_X10, UC_ARM64_REG_X11,
        UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
        UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
        UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
        UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
        UC_ARM64_REG_X28, UC_ARM64_REG_FP,  UC_ARM64_REG_LR,  UC_ARM64_REG_SP,
    };
    uint64_t vals[std::size(regs)];
    uc_reg_read_batch(uc, reinterpret_cast<int *>(regs),
                      reinterpret_cast<void **>(vals), std::size(regs));
    for (size_t i = 0; i < std::size(regs); i++) {
      if (i <= 28)
        strs += std::format("x{:2} = {:x}\n", i, vals[i]);
      else if (i == 29)
        strs += std::format("fp  = {:x}\n", vals[i]);
      else if (i == 30)
        strs += std::format("lr  = {:x}\n", vals[i]);
      else
        strs += std::format("sp  = {:x}\n", vals[i]);
    }
    strs += std::format("pc  = {:x}\n", pc);
  } else if (arch == X86_64) {
    uc_x86_reg regs[] = {
        UC_X86_REG_RAX, UC_X86_REG_RBP, UC_X86_REG_RBX, UC_X86_REG_RCX,
        UC_X86_REG_RDI, UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RSP,
        UC_X86_REG_RIP, UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10,
        UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
        UC_X86_REG_R15,
    };
    static const char *names[] = {
        "rax", "rbp", "rbx", "rcx", "rdi", "rdx", "rsi", "rsp", "rip",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    };
    uint64_t vals[std::size(regs)];
    uc_reg_read_batch(uc, reinterpret_cast<int *>(regs),
                      reinterpret_cast<void **>(vals), std::size(regs));
    for (size_t i = 0; i < std::size(regs); i++) {
      strs += std::format("{} = {:x}\n", names[i], vals[i]);
    }
  } else {
    return "?";
  }
  return strs;
}

Debugger::Debugger() : listen_(&Debugger::listen, this) {}

Debugger::~Debugger() {
  ios_.stop();
  listen_.join();
}

Debugger::Thread *Debugger::enter(ArchType arch, uc_engine *uc) {
  std::lock_guard lock(mutex_);
  auto curth = std::this_thread::get_id();
  auto found = threads_.find({.tid = curth});
  if (found == threads_.end()) {
    // add a new thread
    found = threads_.insert({std::move(curth), uc, arch, 0}).first;
    // init mutex/cond facilities
    const_cast<Thread *>(&*found)->init();
  }
  if (!curthread_) {
    // initialize the current debuggee thread
    curthread_ = const_cast<Thread *>(&*found);
  }
  return const_cast<Thread *>(&*found);
}

void Debugger::entry(Thread *thread, uint64_t pc) {
  switch (status_) {
  case Running:
    runEntry(thread, pc);
    break;
  case Stepping:
    stepEntry(thread, pc, false);
    break;
  default:
    break;
  }
}

void Debugger::runEntry(Thread *thread, uint64_t pc) {
  // check breakpoint
  for (auto it = breakpoint_.begin(), end = breakpoint_.end(); it != end;
       it++) {
    if (it->addr == pc) {
      if (it->oneshot) {
        // remove oneshot breakpoint
        std::lock_guard lock(mutex_);
        breakpoint_.erase(it);
      }
      stepEntry(thread, pc, true);
      break;
    }
  }
}

void Debugger::stepEntry(Thread *thread, uint64_t pc, bool hitbp) {
  // update current pc
  thread->pc = pc;

  // notify debugger client
  {
    std::lock_guard lock(mutex_);
    for (auto s : clients_) {
      std::string result;
      if (hitbp) {
        result = std::format("Hit breakpoint at {:x}, #thread {}", pc,
                             reinterpret_cast<void *>(thread));
      } else {
        result =
            std::format("Stepping stopped at {:x} #thread {}\n{}", pc,
                        reinterpret_cast<void *>(thread), thread->registers());
      }
      sendRespose(s, icppdbg::PAUSE, result);
    }
  }

  // pause current thread, waiting user to stepi/stepo
  thread->itc->wait();
}

void Debugger::leave() {
  std::lock_guard lock(mutex_);
  auto found = threads_.find({.tid = std::this_thread::get_id()});
  if (curthread_ == &*found) {
    curthread_ = nullptr;
  }
  // delete current thread
  threads_.erase(found);
}

void Debugger::listen() {
  ip::tcp::acceptor acceptor(ios_, ip::tcp::endpoint(ip::tcp::v4(), dbgport));
  while (true) {
    try {
      auto socketptr = std::make_shared<ip::tcp::socket>(ios_);
      // waiting for connection
      acceptor.accept(*socketptr);
      if (ios_.stopped())
        break;
      std::thread(&Debugger::recv, this, socketptr);
    } catch (boost::system::system_error &error) {
      log_print(Develop, "Accept error: {}.", error.what());
      break;
    }
  }
}

void Debugger::recv(std::shared_ptr<ip::tcp::socket> socket_) {
  auto &socket = *socket_;
  auto sockit = clients_.end();
  // add client socket
  {
    std::lock_guard lock(mutex_);
    sockit = clients_.insert(clients_.begin(), socket_);
  }
  while (true) {
    boost::system::error_code error;
    // protocol header
    asio::streambuf hdrbuffer;
    asio::read(socket, hdrbuffer,
               asio::transfer_exactly(sizeof(icpp::ProtocolHdr)), error);
    if (error && error != asio::error::eof) {
      log_print(Develop,
                "Failed to read header buffer: {}.\nClosed connection.",
                error.message());
      break;
    }
    auto hdr = asio::buffer_cast<const icpp::ProtocolHdr *>(hdrbuffer.data());
    if (!hdr->len) {
      continue;
    }
    // protocol body serialized by protobuf
    asio::streambuf probuffer;
    asio::read(socket, probuffer, asio::transfer_exactly(hdr->len), error);
    if (error && error != asio::error::eof) {
      log_print(Develop, "Failed to read body buffer: {}.", error.message());
      continue;
    }
    process(hdr, asio::buffer_cast<const void *>(probuffer.data()),
            probuffer.size());
  }
  // remove client socket
  {
    std::lock_guard lock(mutex_);
    clients_.erase(sockit);
  }
}

void Debugger::process(const ProtocolHdr *hdr, const void *body, size_t size) {
  switch (hdr->cmd) {
  case icppdbg::SETBKPT:
  case icppdbg::DELBKPT: {
    icppdbg::CommandBreakpoint cmd;
    if (!cmd.ParseFromArray(body, size)) {
      log_print(Develop, "Failed to parse buffer cmd.{} size.{}", hdr->cmd,
                size);
      break;
    }
    procBreakpoint(cmd.addr(), hdr->cmd == icppdbg::SETBKPT);
    break;
  }
  case icppdbg::READMEM: {
    icppdbg::CommandReadMemory cmd;
    if (!cmd.ParseFromArray(body, size)) {
      log_print(Develop, "Failed to parse buffer cmd.{} size.{}", hdr->cmd,
                size);
      break;
    }
    procReadMem(cmd.addr(), cmd.size(), cmd.format());
    break;
  }
  case icppdbg::SWITCHTHREAD: {
    icppdbg::CommandSwitchThread cmd;
    if (!cmd.ParseFromArray(body, size)) {
      log_print(Develop, "Failed to parse buffer cmd.{} size.{}", hdr->cmd,
                size);
      break;
    }
    procSwitchThread(cmd.tid());
    break;
  }
  default: {
    icppdbg::Command cmd;
    if (!cmd.ParseFromArray(body, size)) {
      log_print(Develop, "Failed to parse buffer cmd.{} size.{}", hdr->cmd,
                size);
      break;
    }
    switch (hdr->cmd) {
    case icppdbg::PAUSE:
      procPause();
      break;
    case icppdbg::RUN:
      procRun();
      break;
    case icppdbg::STOP:
      procStop();
      break;
    case icppdbg::STEPI:
      procStepI();
      break;
    case icppdbg::STEPO:
      procStepO();
      break;
    case icppdbg::LISTTHREAD:
      procListThread();
      break;
    case icppdbg::LISTOBJECT:
      procListObject();
      break;
    default:
      break;
    }
    break;
  }
  }
}

#define foreach_client(statements)                                             \
  for (auto s : clients_) {                                                    \
    statements                                                                 \
  }

void Debugger::procBreakpoint(uint64_t addr, bool set) {
  std::lock_guard lock(mutex_);
  if (set) {
    breakpoint_.insert({addr, false});
    foreach_client({
      sendRespose(s, icppdbg::SETBKPT,
                  std::format("Set breakpoint at {:x}.", addr));
    });
  } else {
    auto found = breakpoint_.find({addr, false});
    if (found != breakpoint_.end()) {
      breakpoint_.erase(found);
      foreach_client({
        sendRespose(s, icppdbg::DELBKPT,
                    std::format("Removed breakpoint at {:x}.", addr));
      });
    } else {
      foreach_client({
        sendRespose(s, icppdbg::DELBKPT,
                    std::format("Set breakpoint at {:x}.", addr));
      });
    }
  }
}

template <typename T>
static std::string formatMemory(T *ptr, uint32_t count, uint32_t colsz,
                                std::string_view format) {
  std::string strs;
  for (uint32_t i = 0, col = 1; i < count; i++) {
    strs += std::vformat(format, std::make_format_args(ptr[i])) + " ";
    if (col % colsz == 0) {
      col = 1;
      strs += "\n";
    } else {
      col++;
    }
  }
  return strs;
}

void Debugger::procReadMem(uint64_t addr, uint32_t size,
                           const std::string &format) {
  std::lock_guard lock(mutex_);
  if (format == "str") {
    foreach_client({
      sendRespose(
          s, icppdbg::READMEM,
          std::format("Memory {:x} {} bytes :\n{}", addr, size,
                      std::string_view(reinterpret_cast<char *>(addr), size)));
    });
    return;
  }
  uint32_t itemsz = 0;
  if (format == "1ix")
    itemsz = 1;
  else if (format == "2ix")
    itemsz = 2;
  else if (format == "4ix")
    itemsz = 4;
  else if (format == "8ix")
    itemsz = 8;
  if (!itemsz) {
    foreach_client({
      sendRespose(s, icppdbg::READMEM,
                  std::format("Memory {:x} {} bytes : Unsupported format {}",
                              addr, size, format));
    });
    return;
  }
  uint32_t count = size / itemsz;
  uint32_t colsz = 16 / itemsz;
  switch (itemsz) {
  case 1:
    formatMemory(reinterpret_cast<uint8_t *>(addr), count, colsz, "{:02x}");
    break;
  case 2:
    formatMemory(reinterpret_cast<uint16_t *>(addr), count, colsz, "{:04x}");
    break;
  case 4:
    formatMemory(reinterpret_cast<uint32_t *>(addr), count, colsz, "{:08x}");
    break;
  default:
    formatMemory(reinterpret_cast<uint64_t *>(addr), count, colsz, "{:016x}");
    break;
  }
}

void Debugger::procSwitchThread(uint64_t tid) {
  std::lock_guard lock(mutex_);
  for (auto &t : threads_) {
    if (tid == reinterpret_cast<uint64_t>(&t.tid)) {
      curthread_ = const_cast<Thread *>(&t);
      foreach_client({
        sendRespose(s, icppdbg::SWITCHTHREAD,
                    std::format("Switched to thread {:x}.", tid));
      });
      return;
    }
  }
  foreach_client({
    sendRespose(s, icppdbg::SWITCHTHREAD,
                std::format("Failed to find thread {:x}.", tid));
  });
}

void Debugger::procPause() {
  std::lock_guard lock(mutex_);
  status_ = Stepping;
  foreach_client({
    sendRespose(s, icppdbg::PAUSE, std::format("Paused execute engine."));
  });
}

void Debugger::procRun() {
  std::lock_guard lock(mutex_);
  status_ = Running;
  for (auto &t : threads_) {
    t.itc->signal();
  }
  foreach_client({
    sendRespose(s, icppdbg::PAUSE, std::format("Running execute engine."));
  });
}

bool Debugger::stopped() { return status_ == Stopped; }

void Debugger::procStop() {
  std::lock_guard lock(mutex_);
  status_ = Stopped;
  for (auto &t : threads_) {
    t.itc->signal();
  }
  foreach_client({
    sendRespose(s, icppdbg::PAUSE, std::format("Stopped execute engine."));
  });
}

void Debugger::procStepI() {
  if (status_ == Running) {
    foreach_client({
      sendRespose(s, icppdbg::STEPI,
                  std::format("Pause execute engine before stepping."));
    });
    return;
  }

  std::lock_guard lock(mutex_);
  curthread_->itc->signal();
}

void Debugger::procStepO() {
  // currently make stepo the same as stepi
  procStepI();
}

void Debugger::procListThread() {
  std::lock_guard lock(mutex_);
  foreach_client({
    sendRespose(s, icppdbg::LISTTHREAD,
                std::format("Un-implement list thread currently."));
  });
}

void Debugger::procListObject() {
  std::lock_guard lock(mutex_);
  foreach_client({
    sendRespose(s, icppdbg::LISTOBJECT,
                std::format("Un-implement list thread currently."));
  });
}

} // namespace icpp
