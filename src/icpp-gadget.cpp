/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "arch.h"
#include "exec.h"
#include "icpp.h"
#include "loader.h"
#include "object.h"
#include "platform.h"
#include "runcfg.h"
#include "utils.h"
#include <boost/asio.hpp>
#include <cstdarg>
#include <icppdbg.pb.h>
#include <icpppad.pb.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/InitLLVM.h>
#include <mutex>
#include <unicorn/unicorn.h>

namespace cl = llvm::cl;
namespace asio = boost::asio;
namespace ip = asio::ip;
namespace iopad = com::vpand::iopad;

namespace icpp {

cl::OptionCategory ISERVER("ICPP Remote Gadget Server Options");

static cl::opt<int> Port("port", cl::desc("Set the listening port."),
                         cl::init(0), cl::cat(ISERVER));

class gadget {
public:
  gadget();
  ~gadget();

  int startup();

  template <typename... Args>
  int print(std::format_string<Args...> format, Args &&...args);

private:
  int listen();
  void recv(ip::tcp::socket *socket);
  void process(const ProtocolHdr *hdr, const void *body, size_t size);
  void procRun(std::string_view name, const std::string &obuff);

  asio::io_service ios_;
  std::unique_ptr<ip::tcp::acceptor> acceptor_;
  std::unique_ptr<std::thread> listen_;
  std::vector<std::unique_ptr<ip::tcp::socket>> clients_;
  std::vector<std::thread> clirecvs_;
  std::mutex mutex_;
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
  send_buffer(s, iopad::RESPONE, respbuf);
}

static int gadget_printf(const char *format, ...);
static int gadget_puts(const char *text);

template <typename... Args>
int gadget::print(std::format_string<Args...> format, Args &&...args) {
  std::lock_guard lock(mutex_);
  auto msg = std::vformat(format.get(), std::make_format_args(args...));
  for (auto &s : clients_) {
    if (s.get()->is_open())
      send_respose(s.get(), iopad::RESPONE, msg);
  }
  return static_cast<int>(msg.length());
}

static bool is_icpp_server() {
  constexpr const char *server = "icpp-server";
  if (std::getenv(server))
    return true;
#if ON_WINDOWS
  char exe[1024];
  ::GetModuleFileNameA(nullptr, exe, sizeof(exe));
  return std::string_view(exe).find(server) != std::string_view::npos;
#else
  return false;
#endif
}

gadget::gadget() {
  if (!is_icpp_server()) {
    listen_ = std::make_unique<std::thread>(&gadget::listen, this);
  }
  RunConfig::inst("gadget", "")->gadget = true;
  RunConfig::printf = gadget_printf;
  RunConfig::puts = gadget_puts;
  Loader::initialize();
  Loader::cacheSymbol("printf", gadget_printf);
  Loader::cacheSymbol("puts", gadget_puts);
}

gadget::~gadget() {
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
    if (acceptor_)
      acceptor_->close();
    ios_.stop();
  } catch (...) {
  }

  if (listen_)
    listen_->join();
}

int gadget::startup() {
  auto port = Port ? Port : gadget_port;
  log_print(Raw, "Running icpp-server at port {}...", port);
  return listen();
}

int gadget::listen() {
  try {
    auto port = Port ? Port : gadget_port;
    acceptor_ = std::make_unique<ip::tcp::acceptor>(
        ios_, ip::tcp::endpoint(ip::tcp::v4(), port));
    log_print(Develop, "Listening icpp-gadget server at {}...", port);
  } catch (std::exception &error) {
    log_print(Develop, "Create acceptor error: {}.", error.what());
    running_ = false;
    return -1;
  }

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

  return 0;
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
    if (error) {
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
  auto membuf = llvm::MemoryBuffer::getMemBuffer(obuff);
  llvm::file_magic magic = llvm::identify_magic(membuf->getBuffer());
  std::shared_ptr<Object> object;
  using fm = llvm::file_magic;
  switch (magic) {
  case fm::macho_object:
    object = std::make_shared<MachOMemoryObject>(name, std::move(membuf));
    break;
  case fm::elf_relocatable:
    object = std::make_shared<ELFMemoryObject>(name, std::move(membuf));
    break;
  case fm::coff_object:
    object = std::make_shared<COFFMemoryObject>(name, std::move(membuf));
    break;
  default:
    log_print(Runtime, "Unknown object payload, magic: {:16x}.",
              *reinterpret_cast<const uint64_t *>(obuff.data()));
    return;
  }
  exec_object(object);

  // notify clients the execution finished
  for (auto &s : clients_)
    send_respose(s.get(), iopad::RUN, "");
}

int gadget_printf(const char *format, ...) {
  char text[4096];
  va_list ap;
  va_start(ap, format);
  auto textsz = std::vsnprintf(text, sizeof(text) - 1, format, ap);
  text[textsz] = 0;
  va_end(ap);

  return icppsvr.print("{}", std::string(text, textsz));
}

int gadget_puts(const char *text) { return icppsvr.print("{}\n", text); }

static void print_version(llvm::raw_ostream &os) {
  os << "ICPP (https://vpand.com/):\n  Remote icpp-gadget server built with "
        "ICPP "
     << icpp::version_string() << "\n";
}

} // namespace icpp

__ICPP_EXPORT__ extern "C" int icpp_gadget(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);
  cl::HideUnrelatedOptions(icpp::ISERVER);
  cl::AddExtraVersionPrinter(icpp::print_version);
  cl::ParseCommandLineOptions(
      argc, argv,
      std::format(
          "ICPP, Interpreting C++, running C++ in anywhere like a script.\n"
          "  Remote icpp-gadget server built with ICPP {}",
          icpp::version_string()));

  icpp::RunConfig::inst(argv[0], "");

  if (argc == 1 || icpp::Port)
    return icpp::icppsvr.startup();
  return 0;
}
