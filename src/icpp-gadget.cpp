/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "arch.h"
#include "exec.h"
#include "icpp.h"
#include "object.h"
#include "platform.h"
#include "runcfg.h"
#include "utils.h"
#include <boost/asio.hpp>
#include <cstdarg>
#include <icppdbg.pb.h>
#include <icpppad.pb.h>
#include <llvm/Object/ObjectFile.h>
#include <unicorn/unicorn.h>

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace iopad = com::vpand::iopad;

namespace icpp {

class gadget {
public:
  gadget();
  ~gadget();

  template <typename... Args>
  int print(std::format_string<Args...> format, Args &&...args);

private:
  void listen();
  void recv(ip::tcp::socket *socket);
  void process(const ProtocolHdr *hdr, const void *body, size_t size);
  void procRun(std::string_view name, const std::string &obuff);

  asio::io_service ios_;
  std::unique_ptr<ip::tcp::acceptor> acceptor_;
  std::unique_ptr<std::thread> listen_;
  std::vector<std::unique_ptr<ip::tcp::socket>> clients_;
  std::vector<std::thread> clirecvs_;
  bool running_ = true;
} icppsvr;

static void send_buffer(ip::tcp::socket *s, iopad::CommandID id,
                        const std::string_view &respbuf) {
  std::string buff;
  buff.resize(sizeof(icpp::ProtocolHdr) + respbuf.length());
  auto hdr = reinterpret_cast<icpp::ProtocolHdr *>(buff.data());
  hdr->cmd = id;
  hdr->len = static_cast<uint32_t>(respbuf.length());
  std::memcpy(&hdr[1], respbuf.data(), respbuf.length());

  boost::system::error_code error;
  asio::write(*s, asio::buffer(buff), error);
  if (error) {
    log_print(Develop, "Failed to send command buffer {}.\n", error.message());
  }
}

static void send_respose(ip::tcp::socket *s, iopad::CommandID id,
                         const std::string &result) {
  iopad::Respond resp;
  resp.set_cmd(id);
  resp.set_result(result);

  auto respbuf = resp.SerializeAsString();
  send_buffer(s, id, respbuf);
}

static int gadget_printf(const char *format, ...);

template <typename... Args>
int gadget::print(std::format_string<Args...> format, Args &&...args) {
  auto msg = std::vformat(format.get(), std::make_format_args(args...));
  for (auto &s : clients_)
    send_respose(s.get(), iopad::RESPONE, msg);
  return static_cast<int>(msg.length());
}

gadget::gadget() {
  listen_ = std::make_unique<std::thread>(&gadget::listen, this);
  RunConfig::inst("")->memory = true;
  RunConfig::printf = gadget_printf;
}

gadget::~gadget() {
  if (!listen_)
    return;
  running_ = false;

  try {
    // close client sockets
    for (auto &s : clients_) {
      if (s->is_open()) {
        s->close();
      }
    }
    // wait client recv thread to exit
    for (auto &t : clirecvs_) {
      t.join();
    }
    // close acceptor
    acceptor_->close();
    listen_->join();
  } catch (...) {
  }
}

void gadget::listen() {
  acceptor_ = std::make_unique<ip::tcp::acceptor>(
      ios_, ip::tcp::endpoint(ip::tcp::v4(), gadget_port));
  while (true) {
    try {
      auto socketptr = std::make_unique<ip::tcp::socket>(ios_);
      // waiting for connection
      acceptor_->accept(*socketptr);
      if (!running_)
        break;
      clients_.push_back(std::move(socketptr));
      clirecvs_.push_back(std::move(
          std::thread(&gadget::recv, this, clients_.rbegin()->get())));
    } catch (boost::system::system_error &error) {
      log_print(Develop, "Accept error: {}.", error.what());
      break;
    }
  }
}

void gadget::recv(ip::tcp::socket *socket) {
  // let iopad know what kind of environment this icpp-gadget is running
  iopad::CommandSyncEnv cmd;
  cmd.mutable_cmd()->set_id(iopad::SYNCENV);
  cmd.set_arch(static_cast<iopad::ArchType>(host_arch()));
  cmd.set_ostype(static_cast<iopad::SystemType>(host_system()));
  send_buffer(socket, iopad::SYNCENV, cmd.SerializeAsString());

  while (true) {
    boost::system::error_code error;
    // protocol header
    asio::streambuf hdrbuffer;
    asio::read(*socket, hdrbuffer,
               asio::transfer_exactly(sizeof(icpp::ProtocolHdr)), error);
    if (error && error != asio::error::eof) {
      log_print(Develop,
                "Failed to read header buffer: {}.\nClosed connection.",
                error.message());
      break;
    }
    auto hdr = asio::buffer_cast<const icpp::ProtocolHdr *>(hdrbuffer.data());
    if (!hdr->len) {
      process(hdr, "", 0);
      continue;
    }
    // protocol body serialized by protobuf
    asio::streambuf probuffer;
    asio::read(*socket, probuffer, asio::transfer_exactly(hdr->len), error);
    if (error && error != asio::error::eof) {
      log_print(Develop, "Failed to read body buffer: {}.", error.message());
      continue;
    }
    process(hdr, asio::buffer_cast<const void *>(probuffer.data()),
            probuffer.size());
  }
}

void gadget::process(const ProtocolHdr *hdr, const void *body, size_t size) {
  switch (hdr->cmd) {
  case iopad::RUN: {
    iopad::CommandRun cmd;
    if (!cmd.ParseFromArray(body, size)) {
      log_print(Develop, "Failed to parse buffer cmd.{} size.{}", hdr->cmd,
                size);
      break;
    }
    procRun(cmd.name(), cmd.buff());
    break;
  }
  default:
    break;
  }
}

void gadget::procRun(std::string_view name, const std::string &obuff) {
  llvm::file_magic magic;
  auto err = llvm::identify_magic(obuff, magic);
  if (err) {
    log_print(Runtime, "Failed to identify the file type of '{}': {}.", name,
              err.message());
    return;
  }

  using fm = llvm::file_magic;
  std::shared_ptr<Object> object;
  switch (magic) {
  case fm::macho_object:
    object = std::make_shared<MachORelocObject>(name, name);
    break;
  case fm::elf_relocatable:
    object = std::make_shared<ELFRelocObject>(name, name);
    break;
  case fm::coff_object:
    object = std::make_shared<COFFRelocObject>(name, name);
    break;
  default:
    return;
  }
  exec_object(object);
}

int gadget_printf(const char *format, ...) {
  char text[4096];
  va_list ap;
  va_start(ap, format);
  auto textsz = std::vsnprintf(text, sizeof(text), format, ap);
  va_end(ap);

  return icppsvr.print("{}", text);
}

} // namespace icpp

__ICPP_EXPORT__ extern "C" void icpp_gadget(void) {}
