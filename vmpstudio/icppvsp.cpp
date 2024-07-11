/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "../src/debugger.h"
#include "../src/icpp.h"
#include "vspdef.hpp"
#include <boost/asio.hpp>
#include <filesystem>
#include <format>
#include <icppdbg.pb.h>
#include <thread>

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace icppdbg = com::vpand::icppdbg;
namespace fs = std::filesystem;

static const char *vi_version = "0.1.0";

// vmpstudio api instance
static const vsp_api_t *api = nullptr;

template <typename... Args>
static inline void log_print(std::format_string<Args...> format,
                             Args &&...args) {
  auto msg = std::vformat(format.get(), std::make_format_args(args...));
  api->log(msg.data());
}

struct vsp_icpp_t {
  vsp_icpp_t();
  ~vsp_icpp_t();

  // can be invoked from VMPStudio/Plugin menu
  void run();

  // can be invoked from python
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
} vivsp;                // visual icpp vmpstudio plugin instance

vsp_icpp_t::vsp_icpp_t() : socket_(ios_) {
  version = std::format("v{} with icpp.{}.{}.{}.{}", vi_version,
                        icpp::version_major, icpp::version_minor,
                        icpp::version_patch, icpp::version_extra);
}

vsp_icpp_t::~vsp_icpp_t() {}

void vsp_icpp_t::process(const icpp::ProtocolHdr *hdr, const void *body,
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
    vsp_module_t module;
    api->getModule(&module);
    fs::path curmod(module.path);
    for (auto o : resp.objects()) {
      char prefix = ' ';
      fs::path omod(o.path());
      if (curmod.filename() == omod.filename()) {
        prefix = '*';
      }
      log_print("{}Object base={:x} path={}\n", prefix, o.base(), o.path());
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
      if (api->curArchType() == vsp_arch_x64)
        pcflag = "rip = ";
      auto pos = resp.result().find(pcflag);
      if (pos != std::string::npos) {
        auto pc = std::stoull(
            std::string(resp.result().data() + pos + pcflag.length(), 16),
            nullptr, 16);
        api->gotoCPUAddress(pc);
      }
    }
    log_print("{}\n", resp.result());
    break;
  }
  }
}

void vsp_icpp_t::recv() {
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

bool vsp_icpp_t::start() {
  if (!api->hasModule()) {
    log_print("There's no loaded module in VMPStudio, because of this, "
              "starting visual icpp doesn't make any sense.\n");
    return false;
  }
  try {
    socket_.connect(ip::tcp::endpoint(ip::address::from_string("127.0.0.1"),
                                      icpp::dbgport));
    return true;
  } catch (boost::system::system_error &error) {
    log_print("Failed to connect to icpp debugger server: {}.\n", error.what());
    return false;
  }
}

__VSP_API__ void vi_stop();

void vsp_icpp_t::stop() {
  curtid_ = 0;

  try {
    if (socket_.is_open()) {
      vi_stop(); // notify icpp stop
      socket_.close();
    }
  } catch (boost::system::system_error &e) {
  }
}

void vsp_icpp_t::send(icppdbg::CommandID id, const std::string &cmd) {
  if (!startup_) {
    log_print("You haven't start this plugin from VMPStudio/Plugin menu.\n");
    return;
  }

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

void vsp_icpp_t::run() {
  if (startup_) {
    stop();
    startup_ = false;
    log_print("Stopped visual icpp.\n");
  } else {
    startup_ = start();
    if (startup_) {
      std::thread(&vsp_icpp_t::recv, this).detach();
      log_print("Started running visual icpp.\n");
    }
  }
}

__VSP_API__ void vi_connect() {
  if (vivsp.running()) {
    return;
  }
  vivsp.run();
}

__VSP_API__ void vi_disconnect() {
  if (!vivsp.running()) {
    return;
  }
  vivsp.run();
}

__VSP_API__ void vi_pause() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::PAUSE);
  vivsp.send(cmd.cmd(), cmd.SerializeAsString());
}

__VSP_API__ void vi_run() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::RUN);
  vivsp.send(cmd.cmd(), cmd.SerializeAsString());
}

__VSP_API__ void vi_stop() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::STOP);
  vivsp.send(cmd.cmd(), cmd.SerializeAsString());
}

__VSP_API__ void vi_setbp(uint64_t addr) {
  icppdbg::CommandBreakpoint cmd;
  cmd.mutable_cmd()->set_cmd(icppdbg::SETBKPT);
  cmd.set_addr(addr);
  vivsp.send(cmd.mutable_cmd()->cmd(), cmd.SerializeAsString());
}

__VSP_API__ void vi_delbp(uint64_t addr) {
  icppdbg::CommandBreakpoint cmd;
  cmd.mutable_cmd()->set_cmd(icppdbg::DELBKPT);
  cmd.set_addr(addr);
  vivsp.send(cmd.mutable_cmd()->cmd(), cmd.SerializeAsString());
}

__VSP_API__ void vi_readmem(uint64_t addr, uint32_t bytes, const char *format) {
  icppdbg::CommandReadMemory cmd;
  cmd.mutable_cmd()->set_cmd(icppdbg::READMEM);
  cmd.set_addr(addr);
  cmd.set_size(bytes);
  cmd.set_format(format);
  vivsp.send(cmd.mutable_cmd()->cmd(), cmd.SerializeAsString());
}

__VSP_API__ void vi_stepi() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::STEPI);
  vivsp.send(cmd.cmd(), cmd.SerializeAsString());
}

__VSP_API__ void vi_stepo() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::STEPO);
  vivsp.send(cmd.cmd(), cmd.SerializeAsString());
}

__VSP_API__ void vi_lsthread() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::LISTTHREAD);
  vivsp.send(cmd.cmd(), cmd.SerializeAsString());
}

__VSP_API__ void vi_lsobject() {
  icppdbg::Command cmd;
  cmd.set_cmd(icppdbg::LISTOBJECT);
  vivsp.send(cmd.cmd(), cmd.SerializeAsString());
}

__VSP_API__ void vi_switchthread(uint64_t tid) {
  icppdbg::CommandSwitchThread cmd;
  cmd.mutable_cmd()->set_cmd(icppdbg::SWITCHTHREAD);
  cmd.set_tid(tid);
  vivsp.send(cmd.mutable_cmd()->cmd(), cmd.SerializeAsString());
}

vsp_error_t vsp_main(vsp_payload_t *vsp) {
  switch (vsp->event) {
  case vsp_event_loaded: {
    api = vsp->api; // save api to a global instance
    return vsp_err_ok;
  }
  case vsp_event_version: {
    vsp->result.str_const = __VSP_VERSION__;
    return vsp_err_ok;
  }
  case vsp_event_menuname: {
    vsp->result.str_const = "Visual ICPP";
    return vsp_err_ok;
  }
  case vsp_event_main_menu: {
    vivsp.run();
    return vsp_err_ok;
  }
  case vsp_event_vspinfo: {
    vsp->result.ptr.p0 = (void *)vivsp.version.data();
    vsp->result.ptr.p1 =
        (void *)"Visual ICPP for icpp execute engine developer.";
    return vsp_err_ok;
  }
  default:
    break;
  }
  return vsp_err_unimpl;
}
