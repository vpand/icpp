/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under GPLv2.
   See LICENSE in root directory for more details
*/

#include <boost/asio.hpp>
#include <filesystem>
#include <format>
#include <icppdbg.pb.h>
#include <thread>

#include "../src/debugger.h"
#include "../src/icpp.h"
#include "../src/platform.h"

#define __VI_API__ __ICPP_EXPORT__

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace icppdbg = com::vpand::icppdbg;
namespace fs = std::filesystem;

static const char *vi_version = "0.1.0";

#ifdef ON_WINDOWS
static const char *api_cpp_print = "?print@cpp@@YAXPEBDZZ";
static const char *api_cpp_goto = "?cpu_goto@cpp@@YAX_K@Z";
#else
static const char *api_cpp_print = "_ZN3cpp5printEPKcz";
static const char *api_cpp_goto = "_ZN3cpp8cpu_gotoEy";
#endif

namespace icpp {
log_writer_func_t log_writer = nullptr;
}

template <typename... Args>
static inline void log_print(std::format_string<Args...> format,
                             Args &&...args) {
  static icpp::log_writer_func_t println = nullptr;
  if (!println) {
    // find Cutter++'s cpp::print API
    println =
        (icpp::log_writer_func_t)icpp::find_symbol(nullptr, api_cpp_print);
    if (!println)
      println = (icpp::log_writer_func_t)&std::puts;
  }

  auto msg = std::vformat(format.get(), std::make_format_args(args...));
  println(msg.data());
}

struct remote_icpp_t {
  remote_icpp_t();
  ~remote_icpp_t();

  void run();

  bool start();
  void stop();

  void send(icppdbg::CommandID id, const std::string &cmd);

  constexpr bool running() { return startup_; }

  std::string version;

private:
  void recv();
  void process(const icpp::ProtocolHdr *hdr, const void *body, size_t size);

  bool startup_ = false;
  asio::io_service ios_;
  ip::tcp::socket socket_;

  uint64_t curtid_ = 0; // current debuggee thread tid
} RI;

remote_icpp_t::remote_icpp_t() : socket_(ios_) {
  version = std::format("v{} with icpp.{}.{}.{}.{}", vi_version,
                        icpp::version_major, icpp::version_minor,
                        icpp::version_patch, icpp::version_extra);
  log_print(R"(
Visual ICPP Debugger {}                          
vi::connect(): connect to icpp debug server.
vi::disconnect(): disconnect to icpp debug server.
vi::pause(): pause current thread.
vi::run(): run current thread from pausing.
vi::stop(): stop running current script file.
vi::setbp(addr): set breakpoint at the specified address.
vi::delbp(addr): delete breakpoint at the specified address.
vi::readmem(addr, bytes, format): read memory at the specified address,
    the format can be: '1ix', '4ix', '8ix', 'str'.
vi::stepi(): step into 1 instruction.
vi::stepo(): step over 1 instruction.
vi::lsthread(): list all the running threads.
vi::lsobject(): list all the running objects.
vi::switchthread(tid): switch the debuggee thread.)",
            version);
}

remote_icpp_t::~remote_icpp_t() {}

void remote_icpp_t::process(const icpp::ProtocolHdr *hdr, const void *body,
                            size_t size) {
  switch (hdr->cmd) {
  case icppdbg::LISTTHREAD: {
    icppdbg::RespondListThread resp;
    if (!resp.ParseFromArray(body, size)) {
      log_print("Failed to parse buffer cmd.{} size.{}\n", hdr->cmd, size);
      break;
    }
    for (auto t : resp.threads()) {
      char prefix = ' ';
      if (!curtid_ || curtid_ == t.tid()) {
        prefix = '*';
        curtid_ = t.tid();
      }
      log_print("{}Thread tid={:x} curpc={:x}\n", prefix, t.tid(), t.curpc());
    }
    break;
  }
  case icppdbg::LISTOBJECT: {
    icppdbg::RespondListObject resp;
    if (!resp.ParseFromArray(body, size)) {
      log_print("Failed to parse buffer cmd.{} size.{}\n", hdr->cmd, size);
      break;
    }
    for (auto o : resp.objects()) {
      log_print("Object base={:x} path={}\n", o.base(), o.path());
    }
    break;
  }
  default: {
    icppdbg::Respond resp;
    if (!resp.ParseFromArray(body, size)) {
      log_print("Failed to parse buffer cmd.{}, size.{}.\n", hdr->cmd, size);
    }
    if (hdr->cmd == icppdbg::PAUSE) {
      std::string_view pcflag{"pc  = "};
      auto pos = resp.result().find(pcflag);
      if (pos == std::string::npos) {
        pcflag = "rip = ";
        pos = resp.result().find(pcflag);
      }
      if (pos != std::string::npos) {
        auto pc = std::stoull(
            std::string(resp.result().data() + pos + pcflag.length(), 16),
            nullptr, 16);

        typedef void (*cpu_goto_t)(uint64_t);
        static cpu_goto_t cpu_goto = nullptr;
        if (!cpu_goto) {
          cpu_goto = (cpu_goto_t)icpp::find_symbol(nullptr, api_cpp_goto);
          if (!cpu_goto)
            log_print("Failed to locate {}", api_cpp_goto);
        }

        cpu_goto(pc);
      }
    }
    log_print("{}\n", resp.result());
    break;
  }
  }
}

void remote_icpp_t::recv() {
  while (startup_) {
    boost::system::error_code error;
    // protocol header
    asio::streambuf hdrbuffer;
    asio::read(socket_, hdrbuffer,
               asio::transfer_exactly(sizeof(icpp::ProtocolHdr)), error);
    if (error) {
      if (startup_) {
        startup_ = false;
        stop();
        log_print("Failed to read header buffer: {}.\nClosed connection.\n",
                  error.message());
      }
      break;
    }
    auto hdr = asio::buffer_cast<const icpp::ProtocolHdr *>(hdrbuffer.data());
    if (!hdr->len) {
      continue;
    }
    // protocol body serialized by protobuf
    asio::streambuf probuffer;
    asio::read(socket_, probuffer, asio::transfer_exactly(hdr->len), error);
    if (error && error != asio::error::eof) {
      log_print("Failed to read body buffer: {}.\n", error.message());
      continue;
    }
    process(hdr, asio::buffer_cast<const void *>(probuffer.data()),
            probuffer.size());
  }
}

bool remote_icpp_t::start() {
  try {
    socket_.connect(ip::tcp::endpoint(ip::address::from_string("127.0.0.1"),
                                      icpp::dbgport));
    return true;
  } catch (boost::system::system_error &error) {
    log_print("Failed to connect to icpp debugger server: {}.\n", error.what());
    return false;
  }
}

namespace vi {
__VI_API__ void stop();
}

void remote_icpp_t::stop() {
  curtid_ = 0;

  try {
    if (socket_.is_open()) {
      vi::stop(); // notify icpp stop
      socket_.close();
    }
  } catch (boost::system::system_error &e) {
  }
}

void remote_icpp_t::send(icppdbg::CommandID id, const std::string &cmd) {
  std::string buff;
  buff.resize(sizeof(icpp::ProtocolHdr) + cmd.length());
  auto hdr = reinterpret_cast<icpp::ProtocolHdr *>(buff.data());
  hdr->cmd = id;
  hdr->len = static_cast<uint32_t>(cmd.length());
  std::memcpy(&hdr[1], cmd.data(), cmd.length());

  boost::system::error_code error;
  asio::write(socket_, asio::buffer(buff), error);
  if (error) {
    log_print("Failed to send command buffer {}.\n", error.message());
  }
}

void remote_icpp_t::run() {
  if (startup_) {
    stop();
    startup_ = false;
    log_print("Stopped visual icpp.\n");
  } else {
    startup_ = start();
    if (startup_) {
      std::thread(&remote_icpp_t::recv, this).detach();
      log_print("Started running visual icpp.\n");
    }
  }
}

namespace vi {

__VI_API__ void connect() {
  if (RI.running()) {
    return;
  }
  RI.run();
}

__VI_API__ void disconnect() {
  if (!RI.running()) {
    return;
  }
  RI.run();
}

__VI_API__ void pause() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::PAUSE);
  RI.send(cmd.cmd(), cmd.SerializeAsString());
}

__VI_API__ void run() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::RUN);
  RI.send(cmd.cmd(), cmd.SerializeAsString());
}

__VI_API__ void stop() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::STOP);
  RI.send(cmd.cmd(), cmd.SerializeAsString());
}

__VI_API__ void setbp(uint64_t addr) {
  icppdbg::CommandBreakpoint cmd;
  cmd.mutable_cmd()->set_cmd(icppdbg::SETBKPT);
  cmd.set_addr(addr);
  RI.send(cmd.mutable_cmd()->cmd(), cmd.SerializeAsString());
}

__VI_API__ void delbp(uint64_t addr) {
  icppdbg::CommandBreakpoint cmd;
  cmd.mutable_cmd()->set_cmd(icppdbg::DELBKPT);
  cmd.set_addr(addr);
  RI.send(cmd.mutable_cmd()->cmd(), cmd.SerializeAsString());
}

__VI_API__ void readmem(uint64_t addr, uint32_t bytes, const char *format) {
  icppdbg::CommandReadMemory cmd;
  cmd.mutable_cmd()->set_cmd(icppdbg::READMEM);
  cmd.set_addr(addr);
  cmd.set_size(bytes);
  cmd.set_format(format);
  RI.send(cmd.mutable_cmd()->cmd(), cmd.SerializeAsString());
}

__VI_API__ void stepi() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::STEPI);
  RI.send(cmd.cmd(), cmd.SerializeAsString());
}

__VI_API__ void stepo() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::STEPO);
  RI.send(cmd.cmd(), cmd.SerializeAsString());
}

__VI_API__ void lsthread() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::LISTTHREAD);
  RI.send(cmd.cmd(), cmd.SerializeAsString());
}

__VI_API__ void lsobject() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::LISTOBJECT);
  RI.send(cmd.cmd(), cmd.SerializeAsString());
}

__VI_API__ void switchthread(uint64_t tid) {
  icppdbg::CommandSwitchThread cmd;
  cmd.mutable_cmd()->set_cmd(icppdbg::SWITCHTHREAD);
  cmd.set_tid(tid);
  RI.send(cmd.mutable_cmd()->cmd(), cmd.SerializeAsString());
}

} // namespace vi
