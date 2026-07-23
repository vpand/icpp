/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under GPLv2.
   See LICENSE in root directory for more details
*/

#include "arch.h"
#include "log.h"
#include "platform.h"
#include "runcfg.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticFrontend.h"
#include "clang/Basic/Version.h"
#include "clang/Config/config.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Interpreter/CodeCompletion.h"
#include "clang/Interpreter/IncrementalExecutor.h"
#include "clang/Interpreter/Interpreter.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Sema/Sema.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/InitializePasses.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Pass.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/LLVMDriver.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Host.h"
#include "llvm/TargetParser/Triple.h"
#include <optional>

#include <string>
#include <vector>

namespace llvm {
namespace object {
class ObjectFile;
}
} // namespace llvm

using namespace llvm;

// the definition's in llvm-project/clang/tools/driver/driver.cpp
int clang_main(int Argc, char **Argv, const llvm::ToolContext &ToolContext);

namespace icpp {

// used to initialize LLVM targets
const Target *getTarget(const object::ObjectFile *Obj, std::string &TripleName);

struct IncrementalCompilation : public clang::DiagnosticConsumer {
  clang::IncrementalCompilerBuilder CB;
  std::unique_ptr<clang::CompilerInstance> DeviceCI;
  std::unique_ptr<clang::Interpreter> Interp;
  llvm::TargetMachine *TargetMachine = nullptr;
  llvm::Module *Module = nullptr;
  llvm::ExitOnError ExitOnErr;
  std::string_view CppPath;
  std::string_view ObjPath;
  std::string CurMain;
  int SnippetID = 0;

  void HandleDiagnostic(clang::DiagnosticsEngine::Level Level,
                        const clang::Diagnostic &Info) override {
    llvm::SmallString<100> Msg;
    Info.FormatDiagnostic(Msg);

    log_print(Runtime, "{}", Msg.str().data());
  }

  void init(int argc, const char **argv) {
    auto OptLevel = "-O1";
    std::vector<const char *> ClangArgv;
    ClangArgv.reserve(argc);
    for (auto i = 1; i < argc; i++) {
      if (strcmp(argv[i], "-c") == 0)
        CppPath = argv[++i];
      else if (strcmp(argv[i], "-o") == 0)
        ObjPath = argv[++i];
      else
        ClangArgv.push_back(argv[i]);

      if (std::string_view(argv[i]).starts_with("-O"))
        OptLevel = argv[i];
    }
    // we've patched the incremental parser to get this environment value
    set_env("ICPP_SCRIPT", CppPath);
    if (Interp)
      return;
    CB.SetCompilerArgs(ClangArgv);

    // initialize LLVM targets
    std::string targetTriple = llvm::sys::getDefaultTargetTriple();
    getTarget(nullptr, targetTriple);

    CodeGenOptLevel OLvl;
    if (auto Level = CodeGenOpt::parseLevel(OptLevel[2])) {
      OLvl = *Level;
    }

    auto IEB = std::make_unique<clang::IncrementalExecutorBuilder>();
    IEB->IsOutOfProcess = false;

    ExitOnErr.setBanner("icpp: ");
    auto CI = ExitOnErr(CB.CreateCpp());
    if (log_writer) {
      // use dynamic log printer if icpp runtime has one
      CI->getDiagnostics().setClient(this, /*ShouldOwnClient=*/false);
    }
    Interp =
        ExitOnErr(clang::Interpreter::create(std::move(CI), std::move(IEB)));

    std::string error;
    const llvm::Target *target =
        llvm::TargetRegistry::lookupTarget(targetTriple, error);
    std::string cpu = "generic";
#if ARCH_ARM64
    std::string features = "+all";
#else
    std::string features = "";
#endif
    llvm::TargetOptions options;
    auto relocationModel = Reloc::PIC_;
    auto codeModel = CodeModel::Small;
    Triple triple{targetTriple};
    TargetMachine = target->createTargetMachine(
        triple, cpu, features, options, relocationModel, codeModel, OLvl);
  }

  bool parse(std::string_view snippet) {
    auto expModule = Interp->Parse(snippet);
    if (!expModule) {
      log_print(Develop, "{}", llvm::toString(expModule.takeError()));
      return false;
    }
    Module = expModule->TheModule.get();
    return true;
  }

  bool codegen() {
    std::error_code errorCode;
    llvm::raw_fd_ostream dest(ObjPath, errorCode, llvm::sys::fs::OF_None);
    if (errorCode) {
      log_print(Runtime, "{}: {}", ObjPath, errorCode.message());
      return false;
    }

    auto fileType = llvm::CodeGenFileType::ObjectFile;
    llvm::legacy::PassManager PM;
    if (TargetMachine->addPassesToEmitFile(PM, dest, nullptr, fileType)) {
      log_print(Runtime, "{}: TargetMachine can't emit a file of this type",
                ObjPath);
      return false;
    }

    PM.run(*Module);
    dest.flush();
    return true;
  }

public:
  int main(int argc, const char **argv) {
    // argv parsing and lazy initialization
    init(argc, argv);

    ErrorOr<std::unique_ptr<MemoryBuffer>> BufferPtr =
        MemoryBuffer::getFile(CppPath);
    if (std::error_code EC = BufferPtr.getError()) {
      log_print(Runtime, "{}: {}", CppPath, EC.message());
      return -1;
    }
    MemoryBuffer *Buffer = BufferPtr->get();
    auto snippet = strstr(Buffer->getBufferStart(), "int main(");
    if (!SnippetID || !snippet) {
      SnippetID++;
      return parse(Buffer->getBufferStart()) && codegen() ? 0 : -1;
    }

    // the current main name
    CurMain = std::format("_{}_main", SnippetID++);

    std::string directives{Buffer->getBufferStart(), snippet};
    auto snippet_withid = std::format(R"({}
#undef main
#define main {}
extern "C" {})",
                                      directives, CurMain, snippet);
    return parse(snippet_withid) && codegen() ? 0 : -1;
  }
};

// use a raw pointer instance to live as long as icpp's running and explicitly
// ignores its destructor to be called to skip the internal module code emitting
static IncrementalCompilation *compiler = nullptr;

const char *current_main() { return compiler ? compiler->CurMain.c_str() : ""; }

int increment_main(int argc, const char **argv) {
  if (!compiler)
    compiler = new IncrementalCompilation;
  return compiler->main(argc, argv);
}

int clang_main(int argc, const char **argv) {
  return ::clang_main(argc, const_cast<char **>(argv),
                      {argv[0], nullptr, false});
}

} // namespace icpp
