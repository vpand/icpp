/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "arch.h"
#include "icpp.h"
#include "platform.h"
#include "utils.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/ToolOutputFile.h"
#ifdef ON_WINDOWS
#include <boost/process.hpp>
#else
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <boost/process.hpp>
#pragma clang diagnostic pop
#endif
#include <boost/asio.hpp>
#include <fstream>
#include <icpppad.pb.h>
#include <set>

namespace proc = boost::process;
namespace cl = llvm::cl;
namespace iopad = com::vpand::iopad;
namespace asio = boost::asio;
namespace ip = asio::ip;

cl::OptionCategory IOPad("ICPP Interpretable Object Launch Pad Options");

static cl::opt<std::string>
    IP("ip", cl::desc("Set the remote ip address of icpp-gadget."),
       cl::init("127.0.0.1"), cl::cat(IOPad));
static cl::opt<int> Port("port", cl::desc("Set the connection port."),
                         cl::init(icpp::gadget_port), cl::cat(IOPad));
static cl::opt<std::string>
    Fire("fire",
         cl::desc("Fire the input source file to the connected remote "
                  "icpp-gadget to execute it."),
         cl::cat(IOPad));
static cl::list<std::string> Incdirs(
    "incdir", cl::ZeroOrMore,
    cl::desc("Specify the include directory for compilation, can be multiple."),
    cl::cat(IOPad));
static cl::opt<std::string>
    NDK("ndk",
        cl::desc("Set the Android NDK root path, default to the parent "
                 "directory of the ndk-build in PATH."),
        cl::cat(IOPad));
static cl::opt<bool> Repl(
    "repl",
    cl::desc("Enter into a REPL interactive shell to fire the input snippet "
             "code to the connected remote icpp-gadget to execute it."),
    cl::init(false), cl::cat(IOPad));

static void print_version(llvm::raw_ostream &os) {
  os << "ICPP (https://vpand.com/):\n  IObject Launch Pad Tool built with "
        "ICPP "
     << icpp::version_string() << "\n";
}

struct LaunchPad {
  icpp::CondMutex itc_;
  icpp::ArchType remote_arch_;
  icpp::SystemType remote_system_;
  asio::io_service ios_;
  ip::tcp::socket socket_;
  std::string ndk_;
  bool running_ = false;

  LaunchPad() : socket_(ios_) {}

  void wait() { itc_.wait(); }
  void signal() { itc_.signal(); }

  std::vector<std::string> cflags() {
    std::vector<std::string> args;
    switch (remote_system_) {
    case icpp::Windows:
    case icpp::macOS:
    case icpp::Linux:
      for (auto f : icpp::extra_cflags())
        args.push_back(f.data());
      break;
    case icpp::iOS:
      args.push_back("-arch");
      args.push_back("-arm64");
      args.push_back("-isysroot");
      args.push_back("/Applications/Xcode.app/Contents/Developer/Platforms/"
                     "iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk");
      break;
    default: {
      const char *osname, *osarch;
      switch (icpp::host_system()) {
      case icpp::Windows:
        osname = "windows";
        break;
      case icpp::macOS:
        osname = "darwin";
        break;
      default:
        osname = "linux";
        break;
      }
      switch (icpp::host_arch()) {
      case icpp::X86_64:
        osarch = "x86_64";
        break;
      default:
        if (icpp::host_system() == icpp::Linux)
          osarch = "aarch64";
        else
          osarch = "arm64";
        break;
      }
      args.push_back("-target");
      if (remote_arch_ == icpp::X86_64)
        args.push_back("x86_64-none-linux-android24");
      else
        args.push_back("aarch64-none-linux-android24");
      args.push_back("--sysroot");
      args.push_back(std::format("{}/toolchains/llvm/prebuilt/{}-{}/sysroot",
                                 ndk_.data(), osname, osarch));
      break;
    }
    }
    return args;
  }

  bool connect() {
    try {
      socket_.connect(ip::tcp::endpoint(ip::address::from_string(IP), Port));
      running_ = true;
      icpp::log_print(icpp::Develop, "Connected to remote icpp-gadget.{}:{}.",
                      IP.data(), Port.getValue());
      return true;
    } catch (boost::system::system_error &error) {
      icpp::log_print(icpp::Runtime,
                      "Failed to connect to remote icpp-gadget.{}:{} : {}.",
                      IP.data(), Port.getValue(), error.what());
      return false;
    }
  }

  void disconnect() {
    running_ = false;
    socket_.close();
  }

  void send(iopad::CommandID id, const std::string &cmd) {
    std::string buff;
    buff.resize(sizeof(icpp::ProtocolHdr) + cmd.length());
    auto hdr = reinterpret_cast<icpp::ProtocolHdr *>(buff.data());
    hdr->cmd = id;
    hdr->len = static_cast<uint32_t>(cmd.length());
    std::memcpy(&hdr[1], cmd.data(), cmd.length());

    boost::system::error_code error;
    asio::write(socket_, asio::buffer(buff), error);
    if (error) {
      icpp::log_print(icpp::Runtime, "Failed to send command buffer {}.\n",
                      error.message());
    }
  }

  void recv() {
    while (running_) {
      boost::system::error_code error;
      // protocol header
      asio::streambuf hdrbuffer;
      asio::read(socket_, hdrbuffer,
                 asio::transfer_exactly(sizeof(icpp::ProtocolHdr)), error);
      if (error && error != asio::error::eof) {
        if (running_) {
          disconnect();
          icpp::log_print(
              icpp::Develop,
              "Failed to read header buffer: {}.\nClosed connection.\n",
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
        icpp::log_print(icpp::Develop, "Failed to read body buffer: {}.\n",
                        error.message());
        continue;
      }
      process(hdr, asio::buffer_cast<const void *>(probuffer.data()),
              probuffer.size());
    }
  }

  std::string_view ndk() {
    if (NDK.length())
      return NDK.data();
    icpp::iterate_pathenv([this](std::string_view path) {
      auto ndkbuild = fs::path(path) / icpp::ndk_build;
      if (fs::exists(ndkbuild)) {
        ndk_ = ndkbuild.string();
        return icpp::IterBreak;
      }
      return icpp::IterContinue;
    });
    return ndk_;
  }

  bool checkCompatible() {
    if (!running_)
      return false;

    auto hostsys = icpp::host_system();
    switch (remote_system_) {
    case icpp::Android: {
      // android needs the NDK root path to cross compile the interpretable
      // object
      if (!ndk_.length()) {
        icpp::log_print(icpp::Runtime,
                        "NDK is missing, even tried to parse from PATH, rerun "
                        "with --ndk=</path/to/ndk>.");
        return false;
      }
      return true;
    }
    case icpp::Windows:
      // windows needs Windows system
      return hostsys == icpp::Windows;
    case icpp::Linux:
      // linux needs Linux system
      return hostsys == icpp::Linux;
    default:
      // macOS/iOS needs macOS system
      return hostsys == icpp::macOS;
    }
  }

  void process(const icpp::ProtocolHdr *hdr, const void *body, size_t size) {
    switch (hdr->cmd) {
    case iopad::SYNCENV: {
      iopad::CommandSyncEnv resp;
      if (!resp.ParseFromArray(body, size)) {
        icpp::log_print(icpp::Runtime,
                        "Failed to parse buffer cmd.{} size.{}\n", hdr->cmd,
                        size);
        break;
      }
      remote_arch_ = static_cast<icpp::ArchType>(resp.arch());
      remote_system_ = static_cast<icpp::SystemType>(resp.ostype());
      if (checkCompatible())
        signal();
      else
        disconnect();
      break;
    }
    case iopad::RESPONE: {
      iopad::Respond resp;
      if (!resp.ParseFromArray(body, size)) {
        icpp::log_print(icpp::Runtime,
                        "Failed to parse buffer cmd.{} size.{}\n", hdr->cmd,
                        size);
        break;
      }
      if (resp.result().length())
        std::cout << resp.result();

      switch (resp.cmd()) {
      case iopad::RUN:
        // notify main thread to continue
        itc_.signal();
        break;
      default:
        break;
      }
      break;
    }
    default:
      icpp::log_print(icpp::Develop, "Unknown command {} in protocol header.",
                      hdr->cmd);
      break;
    }
  }
} launchpad;

static void exec_code(std::string_view icpp, std::string_view code) {
  bool snippet;
  std::string srcpath, objpath;
  if (fs::exists(code)) {
    snippet = false;
    srcpath = code.data();
  } else {
    snippet = true;

    // construct a temporary source path
    srcpath =
        (fs::temp_directory_path() / icpp::rand_filename(8, ".cc")).string();
    std::ofstream outf(srcpath);
    if (!outf.is_open()) {
      icpp::log_print(icpp::Runtime,
                      "Failed to create a temporary source file {}.",
                      srcpath.c_str());
      return;
    }
    outf << code.data();
    outf.close();
  }
  objpath = srcpath + ".o";

  std::vector<std::string> ccargs;
  ccargs.push_back("-c");
  ccargs.push_back(srcpath);
  ccargs.push_back("-o");
  ccargs.push_back(objpath);
  for (auto inc : Incdirs)
    ccargs.push_back(std::format("-I{}", inc.data()));
  for (auto spec : launchpad.cflags())
    ccargs.push_back(spec.data());
  ccargs.push_back("-O2");

  proc::child compiler(std::string(icpp.data()), ccargs);
  compiler.wait();
  if (compiler.exit_code())
    return;

  // send to icpp-gadget to execute this object payload
  iopad::CommandRun cmd;
  cmd.set_name(fs::path(srcpath).filename().c_str());
  auto expBuff = llvm::MemoryBuffer::getFile(objpath);
  if (expBuff) {
    auto buff = expBuff.get().get();
    cmd.set_buff(std::string(buff->getBufferStart(), buff->getBufferSize()));
    launchpad.send(iopad::RUN, cmd.SerializeAsString());
    // wait until the remote execution to be finished
    launchpad.wait();
  }

  if (snippet)
    fs::remove(srcpath);
  fs::remove(objpath);
}

static int exec_repl(std::string_view icpp) {
  std::cout << std::format(
      "ICPP {} IOPAD mode. Copyright (c) vpand.com.\nRunning C++ in "
      "anywhere like a script.\n",
      icpp::version_string());
  return icpp::repl_entry(
      [&](std::string_view dyncode) { exec_code(icpp, dyncode); });
}

template <typename T> static void run_launch_pad(bool repl, T task) {
  if (!launchpad.connect())
    return;
  // create a new thread to interact with remote icpp-gadget server
  std::thread threcv(&LaunchPad::recv, &launchpad);
  // wait to synchronize the execution environment
  launchpad.wait();
  if (launchpad.checkCompatible()) {
    // do the real work
    task();
    launchpad.disconnect();
  }
  threcv.join();
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);
  cl::HideUnrelatedOptions(IOPad);
  cl::AddExtraVersionPrinter(print_version);
  cl::ParseCommandLineOptions(
      argc, argv,
      std::format(
          "ICPP, Interpreting C++, running C++ in anywhere like a script.\n"
          "  IObject Launch Pad Tool built with ICPP {}",
          icpp::version_string()));

  auto imodexe = fs::path(argv[0]);
  auto icppexe = (imodexe.parent_path() /
                  (std::string("icpp") + imodexe.extension().string()))
                     .string();
  if (Fire.length()) {
    if (fs::exists(Fire.data())) {
      run_launch_pad(false, [&icppexe]() { exec_code(icppexe.c_str(), Fire); });
    } else {
      icpp::log_print(icpp::Runtime, "Input source {} doesn't exist.",
                      Fire.data());
    }
  }
  if (!Fire.length() || Repl) {
    run_launch_pad(true, [&icppexe]() { exec_repl(icppexe.c_str()); });
  }

  return 0;
}
