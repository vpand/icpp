/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "debugger.h"
#include "utils.h"
#include <icppdbg.pb.h>

namespace icppdbg = com::vpand::icppdbg;

namespace icpp {

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
    stepEntry(thread, pc);
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
      stepEntry(thread, pc);
      break;
    }
  }
}

void Debugger::stepEntry(Thread *thread, uint64_t pc) {
  // update current pc
  thread->pc = pc;

  // pause current thread, waiting user to stepi/stepo
  std::unique_lock lock(*thread->mutex);
  thread->cond->wait(lock);
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
      auto socketptr = std::make_unique<ip::tcp::socket>(ios_);
      // waiting for connection
      acceptor.accept(*socketptr);
      if (ios_.stopped())
        break;
      std::thread(&Debugger::recv, this, std::move(socketptr));
    } catch (boost::system::system_error &error) {
      log_print(Develop, "Accept error: {}.", error.what());
      break;
    }
  }
}

void Debugger::recv(std::unique_ptr<ip::tcp::socket> socket_) {
  auto &socket = *socket_;
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

void Debugger::procBreakpoint(uint64_t addr, bool set) {}

void Debugger::procReadMem(uint64_t addr, uint32_t size,
                           const std::string &format) {}

void Debugger::procSwitchThread(uint64_t tid) {}

void Debugger::procPause() {}

void Debugger::procRun() {}

void Debugger::procStop() {}

void Debugger::procStepI() {}

void Debugger::procStepO() {}

void Debugger::procListThread() {}

void Debugger::procListObject() {}

} // namespace icpp
