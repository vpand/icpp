/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include "arch.h"
#include "utils.h"
#include <boost/asio.hpp>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <set>
#include <thread>

typedef struct uc_struct uc_engine;

namespace asio = boost::asio;
namespace ip = asio::ip;

namespace icpp {

const int dbgport = 24623; // defined on the date 2024.6.23

struct ProtocolHdr {
  std::uint32_t cmd : 8, // command id
      len : 24;          // protobuf length
};

class Debugger {
public:
  struct Thread {
    std::thread::id tid;
    uc_engine *uc;
    ArchType arch;
    uint64_t pc;

    // used for inter-thread communication
    std::unique_ptr<CondMutex> itc;

    void init() { itc = std::make_unique<CondMutex>(); }

    std::string registers();

    bool operator<(const Thread &right) const { return tid < right.tid; }
  };

public:
  Debugger();
  ~Debugger();

  Thread *enter(ArchType arch, uc_engine *uc);
  void entry(Thread *thread, uint64_t pc);
  void leave();
  bool stopped();

private:
  void runEntry(Thread *thread, uint64_t pc);
  void stepEntry(Thread *thread, uint64_t pc, bool hitbp);
  void listen();
  void recv(std::shared_ptr<ip::tcp::socket> socket);
  void process(const ProtocolHdr *hdr, const void *body, size_t size);
  void procBreakpoint(uint64_t addr, bool set);
  void procReadMem(uint64_t addr, uint32_t size, const std::string &format);
  void procSwitchThread(uint64_t tid);
  void procPause();
  void procRun();
  void procStop();
  void procStepI();
  void procStepO();
  void procListThread();
  void procListObject();

  struct Breakpoint {
    uint64_t addr;
    bool oneshot;

    bool operator<(const Breakpoint &right) const { return addr < right.addr; }
  };

  enum Status {
    Running,
    Stepping,
    Stopped,
  };

  // mutex for debugger data fields modifying
  std::mutex mutex_;

  std::set<Thread> threads_;
  std::set<Breakpoint> breakpoint_;
  Status status_ = Stepping;
  Thread *curthread_ = nullptr;

  // debugger server
  asio::io_service ios_;
  std::thread listen_;
  std::vector<std::shared_ptr<ip::tcp::socket>> clients_;
};

} // namespace icpp
